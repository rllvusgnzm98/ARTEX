package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	actool "github.com/Autumn-27/norma/tool"
)

// 撤退现场清单（death manifest）：norma 的 Session.Close 会杀掉本 session 注册
// 的全部后台任务并删除其输出目录——所以 worker 每次 run 结束（不论是取消、
// 超时还是正常收队），它起的监听器/隧道/OOB 回调进程都会死。单次意图的 worker
// 本身会随之消失，但跨意图存活的依托（监听器、共享通道）需要下一棒 worker 重建。
// 本文件实现三件小事：
//  1. deathLedger——给 Bash 套一层记账包装，凡是确认起了后台进程的调用都记下来；
//  2. writeDeathManifest——run 结束时若 ledger 非空，把每个后台输出文件尾段拷进
//     runDir（原路径随 Close 被删，必须先拷），再向 runDir 与 shared/ 各写一份清单；
//  3. deathManifestBlock——worker 进场时读取撤退现场（本 runDir 或 shared/ 里的
//     非陈旧清单），渲染成首条消息的一段，让接班 worker 按需重建。

// deathManifestMaxOutputBytes 是拷贝后台输出尾段的上限：tail 只为接班时评估
// 「进程死前推进到哪」，全量无意义且可能很大。
const deathManifestMaxOutputBytes = 8 * 1024

// deathManifestMaxAge 是清单的保鲜期：跨太久的现场（监听器面向的目标可能已
// 轮换）不再注入，避免给新意图喂过期情报。
const deathManifestMaxAge = 24 * time.Hour

// reBackgroundSpawned 匹配 norma 后台任务的两种出生公告：
//   - "Running in background as <id>. Output file: <path>"（run_in_background=true）
//   - "... moved to background as <id>. Output file: <path>"（前台超时自动转后台）
//   - "Started monitor <id>. Output file: <path>"（Monitor 工具）
var reBackgroundSpawned = regexp.MustCompile(`(?:moved to background as|Running in background as|Started monitor)\s+(\S+?)\.\s*Output file:\s*(\S+)`)

// bgRecord 是一次后台进程诞生的记账。
type bgRecord struct {
	Command    string    `json:"command"`           // 原始 shell 命令
	TaskID     string    `json:"task_id,omitempty"` // norma 任务 id（shell 内 & 起跳无此项）
	OutputPath string    `json:"output_path"`       // 出生公告里的输出文件（Close 后失效，仅作溯源）
	Kind       string    `json:"kind"`              // managed（任务管理器登记）/ shell-bg（命令内 & 后台）
	SpawnedAt  time.Time `json:"spawned_at"`        // 记账时间
}

// deathLedger 是本 run 的后台进程台账，由 Bash 包装器在每次调用后追加。
type deathLedger struct {
	mu      sync.Mutex
	records []bgRecord
}

func (l *deathLedger) add(r bgRecord) {
	l.mu.Lock()
	l.records = append(l.records, r)
	l.mu.Unlock()
}

func (l *deathLedger) snapshot() []bgRecord {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]bgRecord, len(l.records))
	copy(out, l.records)
	return out
}

// deathLedgerTool 包装 Bash（也兼容 Monitor）：调用结束后从结果文本里识别
// 「已进入后台」的出生公告，或入参本身带 run_in_background，把命令与输出路径
// 记进 ledger。包装只读不改写，调用语义与内层完全一致。
type deathLedgerTool struct {
	actool.CoreTool
	ledger *deathLedger
}

func (t *deathLedgerTool) Call(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	res, err := t.CoreTool.Call(ctx, in, tc)
	t.record(in, res)
	return res, err
}

func (t *deathLedgerTool) record(in json.RawMessage, res actool.Result) {
	if t.ledger == nil {
		return
	}
	var input struct {
		Command         string `json:"command"`
		RunInBackground bool   `json:"run_in_background"`
	}
	_ = json.Unmarshal(in, &input) // 解析失败仍尝试用结果文本识别
	cmd := input.Command

	// 结果文本里的出生公告最权威（含 task id 与输出路径）；一次调用最多一条。
	if m := reBackgroundSpawned.FindStringSubmatch(res.Flatten()); m != nil {
		t.ledger.add(bgRecord{
			Command:    cmd,
			TaskID:     m[1],
			OutputPath: m[2],
			Kind:       "managed",
			SpawnedAt:  time.Now(),
		})
		return
	}
	// 显式 run_in_background 但结果里没匹配到公告（任务秒完/输出被截断）：
	// 照样记账，输出路径留空——进程确实可能活过本 run。
	if input.RunInBackground {
		t.ledger.add(bgRecord{Command: cmd, Kind: "managed", SpawnedAt: time.Now()})
		return
	}
	// shell 内 & 起跳：不受任务管理器管辖，Close 杀不掉它但输出无处可读，
	// 记账只为让接班者知道「可能有孤儿进程还在跑，勿重复起」。
	if cmd != "" && shellBackgrounded(cmd) {
		t.ledger.add(bgRecord{Command: cmd, Kind: "shell-bg", SpawnedAt: time.Now()})
	}
}

// shellBackgrounded 判定命令是否以裸 `&` 结尾后台化（保守版：只认命令结尾的
// 单个 &，排除 &&、|&、引号内内容；中间段的 & 不追，避免误判）。
func shellBackgrounded(cmd string) bool {
	cmd = strings.TrimRight(cmd, " \t\r\n")
	if !strings.HasSuffix(cmd, "&") || strings.HasSuffix(cmd, "&&") || strings.HasSuffix(cmd, "|&") {
		return false
	}
	// 引号未成对收尾时放弃判定（引号里的 & 不是 shell 语法）。
	var quote byte
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		if c == '\\' && quote != '\'' {
			i++
			continue
		}
		switch {
		case quote == 0 && (c == '\'' || c == '"'):
			quote = c
		case c == quote:
			quote = 0
		}
	}
	if quote != 0 {
		return false
	}
	// 结尾的 & 必须在引号外：重扫确认最后一个字符不在引号内。
	quote = 0
	for i := 0; i < len(cmd)-1; i++ {
		c := cmd[i]
		if c == '\\' && quote != '\'' {
			i++
			continue
		}
		switch {
		case quote == 0 && (c == '\'' || c == '"'):
			quote = c
		case c == quote:
			quote = 0
		}
	}
	return quote == 0
}

// wrapBashDeathLedger 给工具集里的 Bash/Monitor 套上后台进程记账。
// 包装在内层（concurrency/deadline 包装）之外不影响它们的行为：
// 本包装不改写输入输出、不引入并发（ledger 内部带锁）。
func wrapBashDeathLedger(tools []actool.CoreTool, ledger *deathLedger) []actool.CoreTool {
	if ledger == nil {
		return tools
	}
	out := make([]actool.CoreTool, len(tools))
	for i, t := range tools {
		if t != nil && (t.Name() == "Bash" || t.Name() == "Monitor") {
			out[i] = &deathLedgerTool{CoreTool: t, ledger: ledger}
		} else {
			out[i] = t
		}
	}
	return out
}

// deathManifestEntry 是清单里的一条撤退现场记录。
type deathManifestEntry struct {
	Command    string    `json:"command"`
	Kind       string    `json:"kind"`
	TaskID     string    `json:"task_id,omitempty"`
	SpawnedAt  time.Time `json:"spawned_at"`
	TailFile   string    `json:"tail_file,omitempty"`   // 输出尾段拷贝的绝对路径（shared/ 或 runDir）
	SourcePath string    `json:"source_path,omitempty"` // 原输出路径（溯源用，已失效）
}

type deathManifest struct {
	WrittenAt time.Time            `json:"written_at"`
	IntentID  int64                `json:"intent_id"`
	Note      string               `json:"note"`
	Entries   []deathManifestEntry `json:"entries"`
}

// writeDeathManifest 在 worker run 收尾时落撤退现场清单。ledger 为空直接返回
// （正常收队且无后台残留是常态，不落空清单）。输出尾段拷到 shared/（跨意图
// 唯一可靠位置，清单里记绝对路径）；写清单失败只记日志——保现场是
// best-effort，绝不允许反过来弄砸收尾。
func writeDeathManifest(runDir string, intentID int64, ledger *deathLedger) {
	if ledger == nil {
		return
	}
	records := ledger.snapshot()
	if len(records) == 0 {
		return
	}
	shared := sharedDirForRun(runDir)
	_ = os.MkdirAll(shared, 0o755)
	m := deathManifest{
		WrittenAt: time.Now(),
		IntentID:  intentID,
		Note:      "本 worker 撤退（取消/超时/收队）时这些后台进程随会话被回收。若现场有价值（监听器、隧道、OOB 依托），请按需重建；重建后或确认无价值时删除本清单文件，避免误导后续单兵。shell-bg 条目不受会话管理，可能仍在运行——接手前先核实，勿盲目重启。",
	}
	for i, r := range records {
		e := deathManifestEntry{
			Command:    r.Command,
			Kind:       r.Kind,
			TaskID:     r.TaskID,
			SpawnedAt:  r.SpawnedAt,
			SourcePath: r.OutputPath,
		}
		if r.OutputPath != "" {
			// 尾段落在 shared/ 并以 intent+序号命名，跨清单不撞名；
			// shared 写不进时退回 runDir（同意图续跑仍可见）。
			name := fmt.Sprintf("bg_i%d_%d_%s_tail.txt", intentID, i, sanitizeFilePart(r.TaskID))
			dst := filepath.Join(shared, name)
			if copyFileTail(r.OutputPath, dst, deathManifestMaxOutputBytes) ||
				copyFileTail(r.OutputPath, filepath.Join(runDir, name), deathManifestMaxOutputBytes) {
				// 优先记 shared 绝对路径（写失败时 copyFileTail 返回 false，
				// 落到 runDir 分支则记 runDir 路径）。
				if _, err := os.Stat(dst); err == nil {
					e.TailFile = dst
				} else {
					e.TailFile = filepath.Join(runDir, name)
				}
			}
		}
		m.Entries = append(m.Entries, e)
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return
	}
	// 双份落盘：runDir 供同意图续跑，shared/ 供跨意图接力（文件名带 intent id
	// 互不覆盖；shared 只增不删的约定里，本清单是唯一允许接班者删除的例外）。
	base := fmt.Sprintf("death_manifest_i%d.json", intentID)
	if err := os.WriteFile(filepath.Join(runDir, base), data, 0o644); err != nil {
		log.Printf("[worker] 撤退清单写 runDir 失败: %v", err)
	}
	if err := os.WriteFile(filepath.Join(shared, base), data, 0o644); err != nil {
		log.Printf("[worker] 撤退清单写 shared 失败: %v", err)
	}
}

// copyFileTail 把 src 的最后 max 字节拷到 dst；源不存在/读失败返回 false。
func copyFileTail(src, dst string, max int64) bool {
	f, err := os.Open(src)
	if err != nil {
		return false
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return false
	}
	size := st.Size()
	start := int64(0)
	if size > max {
		start = size - max
	}
	if _, err := f.Seek(start, 0); err != nil {
		return false
	}
	buf := make([]byte, size-start)
	n, _ := f.Read(buf)
	// 截断对齐到 UTF-8 边界，避免接班者读到半个多字节字符。
	data := buf[:n]
	if start > 0 {
		for len(data) > 0 && (data[0]&0xC0) == 0x80 {
			data = data[1:]
		}
	}
	return os.WriteFile(dst, data, 0o644) == nil
}

// sanitizeFilePart 去掉文件名里不适合做路径成分的字符。
func sanitizeFilePart(s string) string {
	if s == "" {
		return "unnamed"
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// deathManifestBlock 渲染进场注入段：优先读本 runDir 的清单（同意图续跑），
// 否则扫 shared/ 里非陈旧的清单（跨意图接力，按修改时间倒序至多 2 份）。
// 没有任何现场时返回空串，首条消息不受影响。
func deathManifestBlock(runDir string, intentID int64) string {
	type hit struct {
		path string
		mod  time.Time
		m    deathManifest
	}
	readOne := func(path string) (hit, bool) {
		st, err := os.Stat(path)
		if err != nil {
			return hit{}, false
		}
		if time.Since(st.ModTime()) > deathManifestMaxAge {
			return hit{}, false // 陈旧现场不注入
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return hit{}, false
		}
		var m deathManifest
		if json.Unmarshal(data, &m) != nil || len(m.Entries) == 0 {
			return hit{}, false
		}
		return hit{path: path, mod: st.ModTime(), m: m}, true
	}

	var hits []hit
	own := filepath.Join(runDir, fmt.Sprintf("death_manifest_i%d.json", intentID))
	if h, ok := readOne(own); ok {
		hits = append(hits, h)
	} else if entries, err := os.ReadDir(sharedDirForRun(runDir)); err == nil {
		var shared []hit
		for _, e := range entries {
			if e.IsDir() || !strings.HasPrefix(e.Name(), "death_manifest_") || !strings.HasSuffix(e.Name(), ".json") {
				continue
			}
			if h, ok := readOne(filepath.Join(sharedDirForRun(runDir), e.Name())); ok {
				shared = append(shared, h)
			}
		}
		sort.Slice(shared, func(i, j int) bool { return shared[i].mod.After(shared[j].mod) })
		if len(shared) > 2 {
			shared = shared[:2] // 注入上限：现场太多时只有最新的值得看
		}
		hits = shared
	}
	if len(hits) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("\n\n【撤退现场清单（前任单兵留下的后台进程依托）】\n")
	sb.WriteString("以下后台进程已随前任单兵撤退被回收。先判断是否与本意图相关：相关则按命令与输出尾段重建（监听器重起、隧道重连）；重建完成或确认无关后，**删除对应清单文件**（这是 shared/ 只增不删约定的唯一例外），避免误导后续单兵。shell-bg 条目不受会话管理、可能仍在运行，重建前先核实（ps/端口检查）勿盲目重启。\n")
	for _, h := range hits {
		fmt.Fprintf(&sb, "\n—— 清单 %s（意图 #%d，写于 %s）：\n", h.path, h.m.IntentID, h.m.WrittenAt.Format("15:04:05"))
		for _, e := range h.m.Entries {
			fmt.Fprintf(&sb, "- [%s] %s\n", e.Kind, e.Command)
			// TailFile 已是绝对路径（写出时决定 shared 或 runDir），直接呈现。
			if e.TailFile != "" {
				fmt.Fprintf(&sb, "  输出尾段：%s（用 Read 查看）\n", e.TailFile)
			}
		}
	}
	return sb.String()
}
