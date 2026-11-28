package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

// 规划者成本态势注入（planner.SetSituationalExtra 接线，见 task_llm.go）。
// 数据源是常驻计量账本 llm_usage（每次调用都写，不受 llm_record 录制开关门控），
// 所以录制关闭/无数据时不是报错而是静默不注入——planner 永不因成本查询被阻断。

// compactTokens 把 token 量压成紧凑单位串（1.2K/41.2M），供单行态势展示。
func compactTokens(n int) string {
	switch {
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1_000_000)
	case n >= 1000:
		return fmt.Sprintf("%.1fK", float64(n)/1000)
	default:
		return strconv.Itoa(n)
	}
}

// terminalIntent 判定意图是否已到终态（planner 关心已完成意图的成本复盘）。
func terminalIntent(state string) bool {
	switch state {
	case "done", "blocked", "exhausted":
		return true
	}
	return false
}

// costSituational 组装一行紧凑的【成本态势】，拼进 planner 每轮 user input。
// 返回 "" 表示无注入（无数据/查询失败/任务缺失）——绝不让成本查询阻断规划。
func (s *Server) costSituational(taskID int64) string {
	m := s.m
	if m == nil || m.pg == nil {
		return ""
	}
	task, ok := m.Task(strconv.FormatInt(taskID, 10))
	if !ok || task == nil || task.Store == nil {
		return ""
	}
	idStr := strconv.FormatInt(taskID, 10)
	lanes, err := m.pg.CostByLane(idStr)
	if err != nil || len(lanes) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString("【成本态势（token 用量，input+output+cache）】：")

	// 每 lane 总成本（work#N/planner/mainagent/…），截前 6 个避免长行。
	// lane 名归一化：worker lane 由 attribution 写 work#N；planner lane 有显式归因；
	// mainagent/goals 无显式归因，lane 回落为 session 解析出的角色（'main'/'goals'）。
	laneName := func(lane string) string {
		if lane == "main" {
			return "mainagent"
		}
		return lane
	}
	const laneCap = 6
	parts := make([]string, 0, laneCap)
	for i, lc := range lanes {
		if i >= laneCap {
			parts = append(parts, fmt.Sprintf("…共%d路", len(lanes)))
			break
		}
		parts = append(parts, fmt.Sprintf("%s %s", laneName(lc.Lane), compactTokens(lc.TotalTokens())))
	}
	b.WriteString(strings.Join(parts, "/"))

	// 已完成意图的成本复盘：按最近调用排序，取已终态的前 10 条，算均值与低产项。
	intentCosts, err := m.pg.CostByIntent(idStr)
	if err != nil || len(intentCosts) == 0 {
		return b.String()
	}
	nodes, err := task.Store.ListByKind(db.KindIntent, 300)
	if err != nil {
		return b.String()
	}
	byID := make(map[int64]*db.Node, len(nodes))
	for _, n := range nodes {
		byID[n.ID] = n
	}
	type doneCost struct {
		id      int64
		summary string
		yields  int
		cost    int
	}
	done := make([]doneCost, 0, 10)
	for _, ic := range intentCosts {
		if len(done) >= 10 {
			break
		}
		n := byID[ic.IntentID]
		if n == nil || !terminalIntent(n.State) {
			continue // open/running 意图还在花钱，不算「已完成」
		}
		summary := ""
		var inputAssets []int64
		var p struct {
			Summary  string  `json:"summary"`
			AssetIDs []int64 `json:"asset_ids"`
		}
		if json.Unmarshal(n.Payload, &p) == nil {
			summary = p.Summary
			inputAssets = p.AssetIDs
		}
		yields := 0
		if cnt, yerr := task.Store.IntentYieldCount(ic.IntentID, inputAssets); yerr == nil {
			yields = cnt
		} else if ids, ferr := task.Store.FactsYielded(ic.IntentID); ferr == nil {
			yields = len(ids)
		}
		done = append(done, doneCost{id: ic.IntentID, summary: summary, yields: yields, cost: ic.TotalTokens()})
	}
	if len(done) == 0 {
		return b.String()
	}
	total := 0
	for _, d := range done {
		total += d.cost
	}
	mean := total / len(done)
	b.WriteString(fmt.Sprintf("，近%d个已完成意图均值 %s", len(done), compactTokens(mean)))
	// 两类零产出异常（已计入事实、发现与新发现资产）：
	//  - 低产(早退零产)：成本 < 均值/2 且零产出（投入不足即收手，方向可能未挖动）
	//  - 高耗零产：成本 >= 均值*2 且零产出（烧预算空转，续派前应反思换路）
	var low, highBurn []string
	formatItem := func(d doneCost) string {
		if label := truncateRunes(d.summary, 12); label != "" {
			return fmt.Sprintf("#%d %s %s", d.id, label, compactTokens(d.cost))
		}
		return fmt.Sprintf("#%d %s", d.id, compactTokens(d.cost))
	}
	for _, d := range done {
		if d.yields > 0 || d.cost <= 0 {
			continue
		}
		switch {
		case d.cost < mean/2:
			low = append(low, formatItem(d))
		case mean > 0 && d.cost >= mean*2:
			highBurn = append(highBurn, formatItem(d))
		}
	}
	if len(low) > 0 {
		if len(low) > 4 {
			low = low[:4]
		}
		b.WriteString("；低产(早退零产)：")
		b.WriteString(strings.Join(low, "、"))
	}
	if len(highBurn) > 0 {
		if len(highBurn) > 4 {
			highBurn = highBurn[:4]
		}
		b.WriteString("；高耗零产：")
		b.WriteString(strings.Join(highBurn, "、"))
	}
	return b.String()
}

// truncateRunes 截断到 n 个 rune，超出加省略号。
func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

const (
	defaultLLMRecordsMaxRows = 10000
	defaultLLMRecordsTTLDays = 14
)

func envIntOrDefault(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 0 {
		return fallback
	}
	return v
}

// runLLMRecordsRetention periodically trims llm_records when default-on recording
// is active, bounding PostgreSQL storage by row count and age (0 disables either).
func (s *Server) runLLMRecordsRetention(ctx context.Context) {
	if s == nil || s.m == nil || s.m.pg == nil {
		return
	}
	maxRows := envIntOrDefault("ARTEX_LLM_RECORDS_MAX_ROWS", defaultLLMRecordsMaxRows)
	ttlDays := envIntOrDefault("ARTEX_LLM_RECORDS_TTL_DAYS", defaultLLMRecordsTTLDays)
	if maxRows <= 0 && ttlDays <= 0 {
		return
	}
	maxAge := time.Duration(ttlDays) * 24 * time.Hour
	pruneOnce := func() {
		pctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		n, err := s.m.pg.PruneLLMRecords(pctx, maxRows, maxAge)
		if err != nil {
			if ctx.Err() == nil {
				log.Printf("[llmrec] retention prune: %v", err)
			}
			return
		}
		if n > 0 {
			log.Printf("[llmrec] retention pruned %d old rows (max_rows=%d ttl_days=%d)", n, maxRows, ttlDays)
		}
	}

	initTimer := time.NewTimer(30 * time.Second)
	defer initTimer.Stop()
	select {
	case <-ctx.Done():
		return
	case <-initTimer.C:
		pruneOnce()
	}

	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pruneOnce()
		}
	}
}
