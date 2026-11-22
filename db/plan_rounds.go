package db

import (
	"context"
	"time"
)

type PlanRound struct {
	TaskID           string
	Round            int64
	StartedAt        time.Time
	DurationMS       int64
	TriggerSrc       string
	TriggerCount     int
	LLMCalls         int64
	IntentsAdded     int
	IntentsCancelled int
	Outcome          string
}

func (d *DB) InsertPlanRound(ctx context.Context, r PlanRound) error {
	_, err := d.ExecContext(ctx, `INSERT INTO plan_rounds
(task_id, round, started_at, duration_ms, trigger_src, trigger_count, llm_calls, intents_added, intents_cancelled, outcome)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, r.TaskID, r.Round, r.StartedAt, r.DurationMS,
		r.TriggerSrc, r.TriggerCount, r.LLMCalls, r.IntentsAdded, r.IntentsCancelled, r.Outcome)
	return err
}

func (d *DB) LatestPlanRound(ctx context.Context, taskID string) (int64, error) {
	var round int64
	err := d.QueryRowContext(ctx, `SELECT GREATEST(
(SELECT COALESCE(max(round),0) FROM plan_rounds WHERE task_id=$1),
(SELECT COALESCE(max(plan_round),0) FROM llm_usage WHERE task_id=$1))`, taskID).Scan(&round)
	return round, err
}

func (s *ExplorationStore) IntentCountsByState(ctx context.Context) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT state, count(*) FROM exploration_nodes
WHERE exploration_id=$1 AND kind='intent' GROUP BY state`, s.expID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	counts := make(map[string]int)
	for rows.Next() {
		var state string
		var count int
		if err := rows.Scan(&state, &count); err != nil {
			return nil, err
		}
		counts[state] = count
	}
	return counts, rows.Err()
}
