package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent/chainskel"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
)

// 结构化复盘与 TTP 沉淀 (PR2). 任务收官(最后一个 goal 被 prove_goal 标 met)自动触发
// 复盘:汇总探索图血缘 / worker 轨迹 / findings,由 LLM 蒸馏成"场景→判据→转向"条目;
// 外部 writeup 走同一入口解析为同构条目(带来源+置信度)。两类产出都【只入库待审】
// (status=pending),人工审核通过后才并入决策语料(运行时 overlay + 追加落盘 chainskel)。

const retroSystemPrompt = `你是渗透测试复盘专家。下面给出一次【已收官】任务的目标、发现(findings)、关键事实、探索方向与 worker 轨迹。请把其中【可复用的决策经验】蒸馏成若干条"场景→判据→转向"决策骨架,供后续任务的 agent 在相似处境下自问参考。

要求:
- 只提炼【跨目标可复用】的判断/转向经验,不要复述本次具体资产/漏洞细节。
- 每条:scene=进入什么处境;criteria=靠什么判据下结论(可复现的判别信号,而非泛泛而谈);pivot=据此如何转向/下一步。
- category 必须取自:web, ad, app, priv, pwn, recon, rev, pivot, meta, patch, firmware, audit, identity, cloud, protocol, supply, ai, ot, wireless, extension, client, hardware, database, email, report, web3。拿不准用 meta。
- 至多 6 条,宁缺毋滥;没有可提炼的经验就返回空数组 []。
- 【只输出 JSON 数组】,不要任何解释文字。每个元素形如:
{"category":"web","scene":"...","criteria":"...","pivot":"..."}`

const writeupSystemPrompt = `你是渗透测试知识工程师。下面是一篇【外部 writeup / 漏洞报告】原文。请把其中可复用的攻防决策经验解析成若干条"场景→判据→转向"决策骨架。

要求:
- 只提炼【可复用】的判断/转向经验(scene/criteria/pivot 三段),忽略与具体目标强绑定的无复用价值细节。
- category 必须取自:web, ad, app, priv, pwn, recon, rev, pivot, meta, patch, firmware, audit, identity, cloud, protocol, supply, ai, ot, wireless, extension, client, hardware, database, email, report, web3。拿不准用 meta。
- 每条给 confidence(0-1):你对"该经验准确、可复用、非臆测"的置信度;原文含糊/像营销/无法验证就给低分。
- 至多 8 条;没有可提炼内容返回 []。
- 【只输出 JSON 数组】,元素形如:
{"category":"web","scene":"...","criteria":"...","pivot":"...","confidence":0.7}`

// parsedTTP mirrors one LLM-distilled entry.
type parsedTTP struct {
	Category   string  `json:"category"`
	Scene      string  `json:"scene"`
	Criteria   string  `json:"criteria"`
	Pivot      string  `json:"pivot"`
	Confidence float64 `json:"confidence"`
}

// parseTTPJSON extracts the JSON array the model was asked to emit (tolerant of
// stray prose/code fences around it).
func parseTTPJSON(text string) []parsedTTP {
	i := strings.IndexByte(text, '[')
	j := strings.LastIndexByte(text, ']')
	if i < 0 || j < 0 || j <= i {
		return nil
	}
	var out []parsedTTP
	if err := json.Unmarshal([]byte(text[i:j+1]), &out); err != nil {
		return nil
	}
	return out
}

// collectText runs one bounded non-streaming completion and returns the text.
// Unlike server.streamCollectText (1024-token cap, meant for short verdicts), the
// TTP distillation can emit several entries, so it needs real headroom — a cap that
// is too low truncates the JSON array and parseTTPJSON silently drops everything.
func collectText(ctx context.Context, prov llm.Provider, system, user string, maxTokens int) (string, error) {
	temp := 0.0
	req := llm.CompletionRequest{
		System:      []string{system},
		Messages:    []llm.Message{llm.UserText(user)},
		MaxTokens:   maxTokens,
		Temperature: &temp,
		Thinking:    "disabled",
	}
	var sb strings.Builder
	for ev, err := range prov.Stream(ctx, req) {
		if err != nil {
			return "", err
		}
		if ev.Type == llm.SETextDelta {
			sb.WriteString(ev.Text)
		}
	}
	return sb.String(), nil
}

// retroProvider resolves the LLM provider for a task's retro (task-pinned profile,
// else global active), nil when none is configured.
func (s *Server) retroProvider(t *Task) llm.Provider {
	if t != nil && t.LLMProfileID != nil {
		if p, _, ok := s.providerForProfile(*t.LLMProfileID); ok {
			return p
		}
	}
	return s.defaultProvider()
}

func (s *Server) defaultProvider() llm.Provider {
	if s.m.pg != nil {
		if ap, err := s.m.pg.ActiveProfile(); err == nil && ap != nil {
			if p, _, ok := s.providerForProfile(ap.ID); ok {
				return p
			}
		}
	}
	return s.llmProv
}

// wireRetro installs the runtime chainskel overlay (approved TTP entries become
// live decision skeletons without a rebuild) and the task-completion retro hook.
func (s *Server) wireRetro() {
	chainskel.SetOverlay(func(category string) []string {
		if s.m.pg == nil {
			return nil
		}
		lines, err := s.m.pg.ApprovedTTPLines(category)
		if err != nil {
			return nil
		}
		return lines
	})
	s.engine.retroHook = func(taskID string) { go s.runRetro(taskID) }
}

// runRetro distills reusable decision experience from a just-completed task into
// pending (unreviewed) TTP entries. Best-effort: never blocks or crashes the engine.
func (s *Server) runRetro(taskID string) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[retro] task %s panic: %v", taskID, r)
		}
	}()
	if s.m.pg == nil {
		return
	}
	t, ok := s.m.Task(taskID)
	if !ok || t.Store == nil {
		return
	}
	prov := s.retroProvider(t)
	if prov == nil {
		log.Printf("[retro] task %s: 无可用模型,跳过复盘", taskID)
		return
	}
	input := s.gatherRetroInput(t)
	if strings.TrimSpace(input) == "" {
		return
	}
	ctx, cancel := context.WithTimeout(s.ctx, 2*time.Minute)
	defer cancel()
	text, err := collectText(ctx, prov, retroSystemPrompt, input, 4096)
	if err != nil {
		log.Printf("[retro] task %s 蒸馏失败: %v", taskID, err)
		return
	}
	tid, _ := strconv.ParseInt(taskID, 10, 64)
	n := 0
	for _, p := range parseTTPJSON(text) {
		if strings.TrimSpace(p.Scene) == "" || strings.TrimSpace(p.Criteria) == "" || strings.TrimSpace(p.Pivot) == "" {
			continue
		}
		e := db.TTPEntry{Source: "retro", Status: "pending", Category: normCategory(p.Category),
			Scene: p.Scene, Criteria: p.Criteria, Pivot: p.Pivot}
		if tid > 0 {
			e.TaskID = &tid
		}
		if _, err := s.m.pg.AddTTPEntry(e); err == nil {
			n++
		}
	}
	log.Printf("[retro] task %s 复盘蒸馏出 %d 条待审 TTP", taskID, n)
}

func normCategory(c string) string {
	c = strings.ToLower(strings.TrimSpace(c))
	if chainskel.Valid(c) {
		return c
	}
	return "meta"
}

// gatherRetroInput assembles findings, key facts, intents and the worker trace of a
// task into a compact distillation prompt (bounded).
func (s *Server) gatherRetroInput(t *Task) string {
	st := t.Store
	var b strings.Builder
	fmt.Fprintf(&b, "任务目标: %s\n任务描述: %s\n", t.Goal, t.Description)
	if fs, _ := st.ListByKind(db.KindFinding, 200); len(fs) > 0 {
		b.WriteString("\n## 发现(findings)\n")
		for _, n := range fs {
			b.WriteString("- " + nodeBrief(n) + "\n")
		}
	}
	if facts, _ := st.ListByKind(db.KindFact, 200); len(facts) > 0 {
		b.WriteString("\n## 关键事实(facts)\n")
		for _, n := range facts {
			b.WriteString("- " + nodeBrief(n) + "\n")
		}
	}
	if ints, _ := st.ListByKind(db.KindIntent, 200); len(ints) > 0 {
		b.WriteString("\n## 探索方向(intents)\n")
		for _, n := range ints {
			b.WriteString("- [" + n.State + "] " + nodeBrief(n) + "\n")
		}
	}
	if acts, _, err := st.ActivityList(nil, 0, 150); err == nil && len(acts) > 0 {
		b.WriteString("\n## worker 轨迹(trace,节选)\n")
		for _, a := range acts {
			if strings.TrimSpace(a.Summary) == "" {
				continue
			}
			tool := a.Tool
			if tool == "" {
				tool = a.Kind
			}
			b.WriteString("- " + tool + ": " + a.Summary + "\n")
		}
	}
	out := b.String()
	const cap = 24000
	if len(out) > cap {
		out = out[:cap] + "\n…(截断)"
	}
	return out
}

func nodeBrief(n *db.Node) string {
	var p map[string]any
	_ = json.Unmarshal(n.Payload, &p)
	pick := func(k string) string {
		if v, ok := p[k].(string); ok {
			return strings.TrimSpace(v)
		}
		return ""
	}
	var head string
	for _, k := range []string{"name", "summary", "text"} {
		if v := pick(k); v != "" {
			head = v
			break
		}
	}
	extra := []string{}
	if v := pick("vulnclass"); v != "" {
		extra = append(extra, v)
	}
	if v := pick("severity"); v != "" {
		extra = append(extra, v)
	}
	if head == "" {
		head = fmt.Sprintf("#%d", n.ID)
	}
	if len(extra) > 0 {
		head += " (" + strings.Join(extra, "/") + ")"
	}
	return head
}

// --- HTTP: TTP review pipeline ---

// listTTPEntries lists review-queue entries. GET /api/ttp/entries?status=pending.
func (s *Server) listTTPEntries(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	entries, err := pg.ListTTPEntries(strings.TrimSpace(r.URL.Query().Get("status")))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"entries": entries})
}

func (s *Server) reviewTTPEntry(w http.ResponseWriter, r *http.Request, status string) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "invalid id")
		return
	}
	// 原子状态转移:只在 status 仍为 pending 时更新,changed=false 表示被并发的另一次
	// 审核(approve/reject 二选一)抢先定夺 → 返回 409,且不并入决策语料,避免重复/错误落盘。
	updated, changed, err := pg.SetTTPStatus(id, status, "human")
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if updated == nil {
		writeErr(w, 404, "条目不存在")
		return
	}
	if !changed {
		writeErr(w, 409, "该条目已审核")
		return
	}
	// 审核通过:并入决策语料。运行时已由 overlay(读 approved)即时生效;再 best-effort
	// 追加落盘到 agent/chainskel/<category>.md,把语料持久化成仓库格式(供下次构建 embed)。
	if status == "approved" {
		appendChainskelLine(updated.Category, db.TTPLine(*updated))
	}
	writeJSON(w, 200, map[string]any{"ok": true, "entry": updated})
}

func (s *Server) approveTTPEntry(w http.ResponseWriter, r *http.Request) {
	s.reviewTTPEntry(w, r, "approved")
}

func (s *Server) rejectTTPEntry(w http.ResponseWriter, r *http.Request) {
	s.reviewTTPEntry(w, r, "rejected")
}

// importWriteup parses a pasted/uploaded external writeup into pending TTP entries
// (source=writeup, carrying confidence) via the same review pipeline.
// POST /api/ttp/writeups {text, origin_ref}.
func (s *Server) importWriteup(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var body struct {
		Text      string `json:"text"`
		OriginRef string `json:"origin_ref"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, "invalid JSON")
		return
	}
	if strings.TrimSpace(body.Text) == "" {
		writeErr(w, 400, "writeup 内容不能为空")
		return
	}
	prov := s.defaultProvider()
	if prov == nil {
		writeErr(w, 503, "无可用模型,无法解析 writeup")
		return
	}
	ctx, cancel := context.WithTimeout(s.ctx, 2*time.Minute)
	defer cancel()
	text, err := collectText(ctx, prov, writeupSystemPrompt, body.Text, 4096)
	if err != nil {
		writeErr(w, 502, "解析失败: "+err.Error())
		return
	}
	origin := strings.TrimSpace(body.OriginRef)
	n := 0
	for _, p := range parseTTPJSON(text) {
		if strings.TrimSpace(p.Scene) == "" || strings.TrimSpace(p.Criteria) == "" || strings.TrimSpace(p.Pivot) == "" {
			continue
		}
		conf := p.Confidence
		if conf < 0 {
			conf = 0
		} else if conf > 1 {
			conf = 1
		}
		e := db.TTPEntry{Source: "writeup", Status: "pending", Category: normCategory(p.Category),
			Scene: p.Scene, Criteria: p.Criteria, Pivot: p.Pivot, Confidence: conf, OriginRef: origin}
		if _, err := pg.AddTTPEntry(e); err != nil {
			writeErr(w, 500, fmt.Sprintf("已保存 %d 条,但入库失败: %v", n, err))
			return
		}
		n++
	}
	writeJSON(w, 200, map[string]any{"ok": true, "queued": n})
}

// appendChainskelLine best-effort appends an approved entry to its on-disk category
// skeleton. Failure is ignored: the overlay already makes approved entries live; the
// file write only persists them in repo format. Dir overridable for non-repo deploys.
func appendChainskelLine(category, line string) {
	dir := os.Getenv("ARTEX_CHAINSKEL_DIR")
	if dir == "" {
		dir = filepath.Join("agent", "chainskel")
	}
	f, err := os.OpenFile(filepath.Join(dir, category+".md"), os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.WriteString("\n- " + line)
}
