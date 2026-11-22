package server

import (
	"context"
	"log"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/llmrec"
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

func (e *Engine) recordPlanRound(ctx context.Context, t *Task, r db.PlanRound) {
	first := true
	llmrec.ObserveIntentCounts(ctx, func(added, cancelled int64) {
		r.IntentsAdded, r.IntentsCancelled = int(added), int(cancelled)
		if !first {
			if e.m.pg != nil {
				writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
				defer cancel()
				if _, err := e.m.pg.ExecContext(writeCtx, `UPDATE plan_rounds SET intents_added=$3,intents_cancelled=$4 WHERE task_id=$1 AND round=$2`, t.ID, r.Round, added, cancelled); err != nil {
					log.Printf("[planner] task %s 第%d轮 更新意图观测失败: %v", t.ID, r.Round, err)
				}
			}
			return
		}
		first = false
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
	})
}
