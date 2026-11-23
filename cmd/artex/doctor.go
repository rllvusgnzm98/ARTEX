// doctor.go —— `artex doctor` 部署预检子命令。
// 只读检查：不启动服务、不写 DB；data 目录可写性用临时文件探测（随测随删）。
// 每项打印 OK/WARN/FAIL/SKIP + 一行说明，结尾汇总；有 FAIL 才退出码 1。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/config"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/server"
	"github.com/Autumn-27/artex/session"
	"github.com/Autumn-27/artex/tools"
)

// doctorDefaultAddr 必须与主程序 -addr 默认一致，均为 :8787（全网卡）。
// 不要改成 127.0.0.1:8787。
const doctorDefaultAddr = ":8787"

// isDoctorCommand reports whether process args request the doctor subcommand.
// Checked before the service flag set is parsed and before any subsystem starts.
func isDoctorCommand(args []string) bool {
	return len(args) > 1 && args[1] == "doctor"
}

// doctorStatus 是单项预检结论。SKIP 用于前置条件不满足（如 DB 不可达时查不了
// LLM profile）。
type doctorStatus int

const (
	docOK doctorStatus = iota
	docWarn
	docFail
	docSkip
)

func (s doctorStatus) String() string {
	switch s {
	case docOK:
		return "OK  "
	case docWarn:
		return "WARN"
	case docFail:
		return "FAIL"
	case docSkip:
		return "SKIP"
	}
	return "?"
}

type doctorItem struct {
	status doctorStatus
	name   string
	note   string
}

// runDoctor 跑全部预检并打印报告；返回进程退出码（有 FAIL → 1）。
func runDoctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	addr := fs.String("addr", doctorDefaultAddr, "HTTP listen address（与主程序 -addr 同义，默认 :8787）")
	dataDir := fs.String("data", filepath.Join(config.BaseDir(), "data"), "data directory（与主程序 -data 同义）")
	strictTools := fs.Bool("strict-tools", false, "非 optional 工具缺失或哈希不匹配时记 FAIL（默认只 WARN）")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	// -addr 与主程序同义。:8787（全网卡）本身不是失败条件，只在伪装门控项里如实报告。

	fmt.Printf("ARTEX doctor —— 部署预检（只读，不启动服务、不写 DB）\n\n")
	var items []doctorItem
	check := func(status doctorStatus, name, note string) {
		items = append(items, doctorItem{status, name, note})
		fmt.Printf("[%s] %s: %s\n", status, name, note)
	}

	// 1. PostgreSQL 可连接（复用现有配置解析；轻量 ping，不走 Open 的迁移/seed）
	checkShellAvailability(context.Background(), *dataDir, *strictTools, check)

	dsn, source, dsnErr := db.DSN()
	profiles, dbOK, llmChecked := -1, false, false
	if dsnErr != nil {
		check(docFail, "PostgreSQL", dsnErr.Error())
	} else if n, err := db.Probe(dsn); err != nil {
		var qe *db.ProbeQueryError
		if errors.As(err, &qe) {
			// 已 ping 通，但 count(*) 不是「表不存在」：权限等查询失败。
			check(docFail, "PostgreSQL", fmt.Sprintf("查询/权限失败（来源: %s）: %v", source, err))
			check(docWarn, "LLM profile", "查询/权限失败，无法读取 llm_profiles")
			llmChecked = true
		} else {
			check(docFail, "PostgreSQL", fmt.Sprintf("连接失败（来源: %s）: %v", source, err))
		}
	} else {
		dbOK, profiles = true, n
		check(docOK, "PostgreSQL", fmt.Sprintf("可连接（来源: %s; %s）", source, config.Redact(dsn)))
	}

	// 2. LLM profile 已配置（DB 不可达则 SKIP；查询/权限失败不得说成库未初始化）
	if llmChecked {
		// 已在 Probe 查询失败分支报告
	} else if !dbOK {
		check(docSkip, "LLM profile", "DB 不可达，跳过（请先在 UI / llm_profiles 配置）")
	} else if profiles < 0 {
		check(docWarn, "LLM profile", "库未初始化（llm_profiles 表不存在），启动后请在 UI 配置")
	} else if profiles == 0 {
		check(docWarn, "LLM profile", "未配置任何 LLM profile，探索无法运行；请在 UI「LLM」页添加")
	} else {
		check(docOK, "LLM profile", fmt.Sprintf("已配置 %d 个", profiles))
	}

	// 3. data 目录可写（临时文件探测，随测随删）
	if st, err := os.Stat(*dataDir); err != nil {
		check(docWarn, "data 目录", fmt.Sprintf("%s 不存在（启动时会自动创建）", *dataDir))
	} else if !st.IsDir() {
		check(docFail, "data 目录", fmt.Sprintf("%s 不是目录", *dataDir))
	} else if f, err := os.CreateTemp(*dataDir, ".doctor-*"); err != nil {
		check(docFail, "data 目录", fmt.Sprintf("%s 不可写: %v", *dataDir, err))
	} else {
		name := f.Name()
		_ = f.Close()
		_ = os.Remove(name)
		check(docOK, "data 目录", *dataDir+" 可写")
	}

	// 4/5. 外部工具清单：可选隧道工具逐项 + 军火库存在性汇总
	manifest, mErr := tools.Load(tools.ManifestPath())
	if mErr != nil && !os.IsNotExist(mErr) {
		check(docWarn, "工具清单", "解析失败（跳过工具检查）: "+mErr.Error())
	}
	var results []tools.CheckResult
	if manifest != nil {
		results = tools.Check(manifest, *dataDir)
	} else if os.IsNotExist(mErr) {
		// 清单缺失（开发态/裁剪部署）：隧道工具按运行时同一套解析（env > data/tools）
		// 兜底查存在性。不检查 suo5-payloads。
		for _, name := range []string{"suo5", "chisel"} {
			env := "ARTEX_" + strings.ToUpper(name) + "_PATH"
			results = append(results, tools.CheckEntry(tools.Entry{
				Name: name, Path: "tools/" + name, Env: env, Category: "tunnel",
			}, *dataDir))
		}
		check(docWarn, "工具清单", "packaging/tools-manifest.json 缺失——隧道工具按默认路径检查，军火库无法汇总")
	}

	// 4. 隧道工具（chisel/suo5/ligolo-*）：存在性 + （清单钉了哈希时）sha256。
	// 缺失默认 WARN。-strict-tools 时，非 optional 的缺失/哈希不匹配为 FAIL。
	// 平台不符直接 SKIP，不当成 mismatch。
	{
		var parts []string
		worst := docOK
		saw, applicable := false, 0
		for _, r := range results {
			if r.Entry.Category != "tunnel" {
				continue
			}
			saw = true
			if r.Status == tools.StatusNotApplicable {
				continue
			}
			applicable++
			parts = append(parts, doctorToolNote(r))
			bad := r.Status == tools.StatusMissing || r.Status == tools.StatusMismatch
			if bad && *strictTools && !r.Entry.Optional {
				worst = docFail
			} else if bad && worst != docFail {
				worst = docWarn
			}
		}
		switch {
		case !saw:
			check(docSkip, "隧道工具", "清单中无隧道项")
		case applicable == 0:
			check(docSkip, "隧道工具", "当前平台不适用，已跳过")
		default:
			check(worst, "隧道工具", strings.Join(parts, "; "))
		}
	}

	// 5. 军火库工具存在性汇总（存在 X/Y）。缺失默认 WARN；哈希不匹配也必须 WARN，
	// 不能因为「不是 missing」就算进 present 并在全在时打 OK。
	// -strict-tools 时，非 optional 的缺失/不匹配改为 FAIL。平台不符不计入分母。
	{
		var present, missing, mismatched []string
		saw := false
		skippedPlatform := 0
		strictProblem := false
		for _, r := range results {
			if r.Entry.Category != "arsenal" {
				continue
			}
			saw = true
			if r.Status == tools.StatusNotApplicable {
				skippedPlatform++
				continue
			}
			switch r.Status {
			case tools.StatusMissing:
				missing = append(missing, r.Entry.Name)
				if *strictTools && !r.Entry.Optional {
					strictProblem = true
				}
			case tools.StatusMismatch:
				mismatched = append(mismatched, r.Entry.Name)
				if *strictTools && !r.Entry.Optional {
					strictProblem = true
				}
			default:
				present = append(present, r.Entry.Name)
			}
		}
		total := len(present) + len(missing) + len(mismatched)
		switch {
		case !saw:
			check(docSkip, "军火库工具", "清单缺失，无法汇总")
		case total == 0 && skippedPlatform > 0:
			check(docSkip, "军火库工具", "当前平台不适用，已跳过")
		case len(missing) == 0 && len(mismatched) == 0:
			check(docOK, "军火库工具", fmt.Sprintf("存在 %d/%d", len(present), total))
		default:
			var bits []string
			bits = append(bits, fmt.Sprintf("存在 %d/%d", len(present), total))
			if len(missing) > 0 {
				bits = append(bits, "缺失: "+strings.Join(missing, ", "))
			}
			if len(mismatched) > 0 {
				bits = append(bits, "哈希不匹配: "+strings.Join(mismatched, ", "))
			}
			note := strings.Join(bits, "；")
			if len(missing) > 0 {
				note += "——按需补齐到 " + filepath.Join(*dataDir, "tools")
			}
			st := docWarn
			if strictProblem {
				st = docFail
			}
			check(st, "军火库工具", note)
		}
	}

	// 6. 伪装门控：按与运行时相同的优先级解析 mode/来源，并读 data/gate 的权限和
	// 统计快照。快照不存在就说明服务未运行，不把缺文件写成「命中 0」。
	settingsValue, settingsSet, settingsNote := "", false, ""
	if dsnErr != nil || !dbOK {
		settingsNote = "settings 未读（数据库不可达）"
	} else if v, ok, err := db.LookupSetting(dsn, config.GateModeSettingKey); err != nil {
		settingsNote = "settings 读取失败: " + err.Error()
	} else if ok && strings.TrimSpace(v) != "" {
		settingsValue, settingsSet = v, true
	}
	gateStatus, gateNote := doctorCamouflage(*dataDir, *addr, settingsValue, settingsSet, settingsNote)
	check(gateStatus, "伪装门控", gateNote)

	// 7. ARTEX_CALLBACK_ADDR：隧道回连平台用
	// systemd 部署常用 EnvironmentFile 注入（packaging/artex.service 约定
	// /etc/artex.env），doctor 从 shell 直跑时读不到进程环境，需兜底解析该文件。
	cb := config.CallbackAddr()
	cbSrc := ""
	if cb == "" {
		if v, ok := readEnvFileValue("/etc/artex.env", "ARTEX_CALLBACK_ADDR"); ok {
			cb, cbSrc = v, "（来自 /etc/artex.env）"
		}
	}
	if cb != "" {
		check(docOK, "回连地址", "ARTEX_CALLBACK_ADDR = "+cb+cbSrc)
	} else {
		check(docWarn, "回连地址", "ARTEX_CALLBACK_ADDR 未设置——隧道回连平台不可用；立足点功能不受影响")
	}

	// 7.5 emp3r0r cc sidecar 连通性：enabled=off 直接 SKIP；
	// enabled 但凭据缺失 WARN；齐全时拉起进程内 WG peer 探测 operator API。
	ecfg := config.Emp3r0rConfig()
	if !ecfg.Enabled {
		check(docSkip, "emp3r0r cc", "未启用（config emp3r0r.enabled / ARTEX_EMP3R0R）")
	} else {
		missing := []string{}
		if strings.TrimSpace(ecfg.WGEndpoint) == "" {
			missing = append(missing, "wg_endpoint")
		}
		if strings.TrimSpace(ecfg.WGServerPublicKey) == "" {
			missing = append(missing, "wg_server_public_key")
		}
		if strings.TrimSpace(ecfg.WGServerIP) == "" {
			missing = append(missing, "wg_server_ip")
		}
		if strings.TrimSpace(ecfg.WGOperatorIP) == "" {
			missing = append(missing, "wg_operator_ip")
		}
		if strings.TrimSpace(ecfg.WGOperatorKey) == "" {
			missing = append(missing, "wg_operator_key")
		}
		if len(missing) > 0 {
			check(docWarn, "emp3r0r cc", "已启用但凭据不完整，缺: "+strings.Join(missing, ", "))
		} else {
			cc, cerr := session.NewCCClient(session.Emp3r0rConfig{
				Endpoint:     ecfg.WGEndpoint,
				ServerKey:    ecfg.WGServerPublicKey,
				ServerIP:     ecfg.WGServerIP,
				OperatorIP:   ecfg.WGOperatorIP,
				OperatorKey:  ecfg.WGOperatorKey,
				OperatorPort: ecfg.OperatorPort,
				SessionID:    ecfg.OperatorSession,
			})
			if cerr != nil {
				check(docWarn, "emp3r0r cc", "客户端构造失败: "+cerr.Error())
			} else {
				cctx, ccancel := context.WithTimeout(context.Background(), 8*time.Second)
				perr := cc.Ping(cctx)
				ccancel()
				_ = cc.Close()
				if perr != nil {
					check(docFail, "emp3r0r cc", fmt.Sprintf("连通性失败（%s 经 WG peer → %s）: %v",
						ecfg.WGOperatorIP, ecfg.WGEndpoint, perr))
				} else {
					check(docOK, "emp3r0r cc", fmt.Sprintf("operator API 可达（WG endpoint %s）", ecfg.WGEndpoint))
				}
			}
		}
		if ecfg.Enabled && strings.TrimSpace(ecfg.AgentBinary) == "" {
			check(docWarn, "emp3r0r agent", "emp3r0r.agent_binary 未配置——deploy_emp3r0r 不可用")
		} else if ecfg.Enabled {
			check(docOK, "emp3r0r agent", ecfg.AgentBinary)
		}
	}

	// 8. Hackbots 脚本工具：随包脚本是否落在 skills/ 下、解释器是否可用。
	// doctor 只读，不能走 config.SkillDir()（它会在缺省时创建目录）。
	// 技能目录整体不存在说明本次部署没带技能包：SKIP 而不是 FAIL。
	// 目录在但脚本缺失/解释器不可用：默认 WARN，-strict-tools 升级为 FAIL。
	{
		st, note := doctorHackbots(doctorSkillDir())
		if st == docWarn && *strictTools {
			st = docFail
		}
		check(st, "Hackbots 工具", note)
	}

	// 汇总：有 FAIL 才退出码 1
	var nOK, nWarn, nFail, nSkip int
	for _, it := range items {
		switch it.status {
		case docOK:
			nOK++
		case docWarn:
			nWarn++
		case docFail:
			nFail++
		case docSkip:
			nSkip++
		}
	}
	fmt.Printf("\n汇总：OK %d · WARN %d · FAIL %d · SKIP %d\n", nOK, nWarn, nFail, nSkip)
	if nFail > 0 {
		fmt.Println("存在 FAIL 项，请先修复再启动。")
		return 1
	}
	return 0
}

func checkShellAvailability(ctx context.Context, dataDir string, strict bool, check func(doctorStatus, string, string)) {
	for _, result := range agent.ShellHintAvailability(ctx, dataDir) {
		status, note := docOK, result.Path
		if !result.Available {
			status, note = docWarn, result.Error
			if strict && !result.Optional {
				status = docFail
			}
		}
		if result.Optional {
			note += " (optional)"
		}
		check(status, "CLI "+result.Name, note)
	}
}

// doctorSkillDir 只读地解析技能根目录：与 config.SkillDir() 优先级相同
// （env ARTEX_SKILL_DIR > config.json 的 skill_dir > BaseDir()/skills），但不会
// 创建目录 —— doctor 是只读预检，不能有副作用。
func doctorSkillDir() string {
	if v := strings.TrimSpace(os.Getenv("ARTEX_SKILL_DIR")); v != "" {
		return v
	}
	if v := strings.TrimSpace(config.Load().SkillDir); v != "" {
		return v
	}
	return filepath.Join(config.BaseDir(), "skills")
}

// doctorHackbots 检查随包侦察脚本与解释器。技能目录整体不存在时返回 SKIP
// （本次部署没带技能包，不是故障）；脚本缺失或解释器不可用返回 WARN，由调用方
// 在 -strict-tools 下升级为 FAIL。
func doctorHackbots(skillDir string) (doctorStatus, string) {
	if st, err := os.Stat(skillDir); err != nil || !st.IsDir() {
		return docSkip, "技能目录不存在（" + skillDir + "）——本次部署未带 Hackbots 脚本"
	}
	scripts := server.HackbotsScriptPaths()
	if len(scripts) == 0 {
		return docSkip, "工具清单为空"
	}
	var missing []string
	needPython, needNode := false, false
	for _, rel := range scripts {
		if _, err := os.Stat(filepath.Join(skillDir, filepath.FromSlash(rel))); err != nil {
			missing = append(missing, rel)
			continue
		}
		switch strings.ToLower(filepath.Ext(rel)) {
		case ".py":
			needPython = true
		case ".js", ".mjs":
			needNode = true
		}
	}
	var bits []string
	bits = append(bits, fmt.Sprintf("脚本 %d/%d 存在（%s）", len(scripts)-len(missing), len(scripts), skillDir))
	failed := len(missing) > 0
	if failed {
		bits = append(bits, "缺失: "+strings.Join(missing, ", "))
	}
	if needPython {
		if p := server.DetectPythonInterpreter(); p != "" {
			bits = append(bits, "python="+p)
		} else {
			bits = append(bits, "python 未找到（.py 工具不可用，可在 UI 设置 python_interpreter）")
			failed = true
		}
	}
	if needNode {
		if p := server.DetectNodeInterpreter(); p != "" {
			bits = append(bits, "node="+p)
		} else {
			bits = append(bits, "node 未找到（.js 工具不可用，可在 UI 设置 node_interpreter）")
			failed = true
		}
	}
	if failed {
		return docWarn, strings.Join(bits, "；")
	}
	return docOK, strings.Join(bits, "；")
}

// doctorCamouflage 汇总当前解析结果、监听是否暴露全网卡、data/gate 权限和
// 已落盘的探测计数。计数只来自统计文件；读不到就说明未运行，不编造零值。
func doctorCamouflage(dataDir, addr, settingsValue string, settingsSet bool, settingsNote string) (doctorStatus, string) {
	res := config.ResolveGate(settingsValue, settingsSet)
	var b strings.Builder
	fmt.Fprintf(&b, "mode=%s 来源=%s", res.Mode, res.Source)
	if settingsNote != "" {
		fmt.Fprintf(&b, "；%s", settingsNote)
	}
	fmt.Fprintf(&b, "；%s", doctorListenNote(addr))
	dirNote, dirStatus := doctorGateDir(dataDir)
	fmt.Fprintf(&b, "；%s；%s", dirNote, doctorGateStatsNote(dataDir, res))
	b.WriteString("；off/detect 不改响应；enforce 需显式配置。回环始终放行。旁路：POST /api/gate/bypass（需登录，不写日志）")
	return dirStatus, b.String()
}

// doctorListenNote 描述 -addr 是否绑在全网卡上。只报告事实，不把 :8787 当成失败。
func doctorListenNote(addr string) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		if strings.HasPrefix(strings.TrimSpace(addr), ":") {
			return "监听 " + addr + "，暴露全网卡"
		}
		return "监听地址无法解析: " + addr
	}
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		return "监听 " + addr + "，暴露全网卡"
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsUnspecified() {
			return "监听 " + addr + "，暴露全网卡"
		}
		if ip.IsLoopback() {
			return "监听 " + addr + "，仅本机回环"
		}
	}
	return "监听 " + addr + "，绑定 " + host
}

// doctorGateDir 检查 data/gate。目录不存在表示当前没在用落盘统计，不是故障。
func doctorGateDir(dataDir string) (string, doctorStatus) {
	dir := filepath.Join(dataDir, "gate")
	st, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return "data/gate 不存在（未使用）", docOK
		}
		return "data/gate 无法检查: " + err.Error(), docWarn
	}
	if !st.IsDir() {
		return "data/gate 不是目录", docWarn
	}
	perm := st.Mode().Perm()
	note := fmt.Sprintf("data/gate 权限 %04o", perm)
	// Windows 的权限位不能表示「其他用户可写」，避免把每个目录都打成 WARN。
	if runtime.GOOS != "windows" && perm&0o022 != 0 {
		return note + "（组或其他用户可写）", docWarn
	}
	return note, docOK
}

// doctorGateStatsNote 读取 data/gate/stats.json。文件不存在时明确说服务未运行。
func doctorGateStatsNote(dataDir string, res config.GateResolution) string {
	snap, err := config.ReadGateStats(dataDir)
	if err != nil {
		if os.IsNotExist(err) {
			return "探测计数不可读：服务未运行"
		}
		return "探测计数不可读：" + err.Error()
	}
	when := "更新时间缺失"
	if !snap.UpdatedAt.IsZero() {
		when = "更新于 " + snap.UpdatedAt.UTC().Format(time.RFC3339)
	}
	note := fmt.Sprintf("探测计数 命中 %d · 放行 %d · 旁路 %d · 诱饵 %d（%s）", snap.Hits, snap.Allows, snap.Bypasses, snap.Decoys, when)
	if snap.Mode != "" && (snap.Mode != res.Mode || (snap.Source != "" && snap.Source != res.Source)) {
		note += fmt.Sprintf("；快照 mode=%s 来源=%s", snap.Mode, snap.Source)
	}
	return note
}

// doctorToolNote 渲染单个工具的自检片段（doctor 报告用）。
func doctorToolNote(r tools.CheckResult) string {
	switch r.Status {
	case tools.StatusOK:
		return fmt.Sprintf("%s OK(sha256 一致, %s)", r.Entry.Name, r.Path)
	case tools.StatusUnpinned:
		return fmt.Sprintf("%s 存在（未钉 sha256, %s)", r.Entry.Name, r.Path)
	case tools.StatusMismatch:
		return fmt.Sprintf("%s 哈希不匹配（期望 %s 实际 %s；可能自编译，仅警告）", r.Entry.Name, r.Entry.SHA256, r.Actual)
	case tools.StatusNotApplicable:
		return fmt.Sprintf("%s 当前平台不适用（清单 %s），已跳过", r.Entry.Name, r.Entry.Platform)
	default:
		return fmt.Sprintf("%s 缺失（期望 %s）", r.Entry.Name, r.Path)
	}
}

// readEnvFileValue 解析 systemd EnvironmentFile 风格的 KEY=VALUE 文件，返回指定
// 键的值。文件不存在或键缺失返回 ok=false；# 开头为注释。仅用于 doctor 兜底提示。
func readEnvFileValue(path, key string) (string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(k) != key {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		return v, v != ""
	}
	return "", false
}
