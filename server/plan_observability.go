package server

import (
	"context"
	"log"
	"time"

	"github.com/Autumn-27/artex/db"
)

func (e *Engine) restorePlanRoundCounter(ctx context.Context, t *Task) {
	if e.m.pg == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	round, err := e.m.pg.LatestPlanRound(ctx, t.ID)
	if err != nil {
		log.Printf("[planner] task %s 读取观测轮数失败: %v", t.ID, err)
		return
	}
	current, _ := e.plannerRound.LoadOrStore(t.ID, 0)
	if round > int64(current.(int)) {
		e.plannerRound.Store(t.ID, int(round))
	}
}

func planIntentCounts(ctx context.Context, t *Task) map[string]int {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer cancel()
	counts, err := t.Store.IntentCountsByState(ctx)
	if err != nil {
		log.Printf("[planner] task %s 观测意图计数失败: %v", t.ID, err)
		return nil
	}
	return counts
}

func planIntentDelta(before, after map[string]int) (added, cancelled int) {
	if before == nil || after == nil {
		return 0, 0
	}
	total := func(counts map[string]int) int {
		n := 0
		for _, count := range counts {
			n += count
		}
		return n
	}
	return max(0, total(after)-total(before)), max(0, after["stopped"]-before["stopped"])
}

func (e *Engine) recordPlanRound(ctx context.Context, t *Task, r db.PlanRound, before map[string]int) {
	r.IntentsAdded, r.IntentsCancelled = planIntentDelta(before, planIntentCounts(ctx, t))
	log.Printf("[planner] task %s 第%d轮 耗时=%s 调用=%d 新增意图=%d 撤销=%d",
		t.ID, r.Round, time.Duration(r.DurationMS)*time.Millisecond, r.LLMCalls, r.IntentsAdded, r.IntentsCancelled)
	if e.m.pg == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer cancel()
	if err := e.m.pg.InsertPlanRound(ctx, r); err != nil {
		log.Printf("[planner] task %s 第%d轮 观测记录失败: %v", t.ID, r.Round, err)
	}
}
