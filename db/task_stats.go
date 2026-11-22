package db

import "context"

type PlanRoundsSummary struct {
	Count         int64            `json:"count"`
	DurationMSSum int64            `json:"duration_ms_sum"`
	DurationMSAvg float64          `json:"duration_ms_avg"`
	LLMCalls      int64            `json:"llm_calls"`
	Outcomes      map[string]int64 `json:"outcomes"`
}

type WorkerLLMStats struct {
	Worker           string  `json:"worker"`
	Calls            int64   `json:"calls"`
	Errors           int64   `json:"errors"`
	InputTokens      int64   `json:"input_tokens"`
	OutputTokens     int64   `json:"output_tokens"`
	CacheReadTokens  int64   `json:"cache_read_tokens"`
	CacheWriteTokens int64   `json:"cache_write_tokens"`
	LatencyP50MS     float64 `json:"latency_p50_ms"`
	LatencyP95MS     float64 `json:"latency_p95_ms"`
}

type TaskLLMStats struct {
	ByWorker                   []WorkerLLMStats `json:"by_worker"`
	WorkerCallsWithIntentID    int64            `json:"worker_calls_with_intent_id"`
	WorkerCallsWithoutIntentID int64            `json:"worker_calls_without_intent_id"`
}

func (d *DB) TaskPlanRoundsSummary(ctx context.Context, taskID string) (PlanRoundsSummary, error) {
	summary := PlanRoundsSummary{Outcomes: map[string]int64{"ok": 0, "error": 0, "met": 0}}
	var ok, failed, met int64
	err := d.QueryRowContext(ctx, `SELECT count(*), COALESCE(sum(duration_ms),0), COALESCE(avg(duration_ms),0),
COALESCE(sum(llm_calls),0), count(*) FILTER (WHERE outcome='ok'), count(*) FILTER (WHERE outcome='error'),
count(*) FILTER (WHERE outcome='met') FROM plan_rounds WHERE task_id=$1`, taskID).
		Scan(&summary.Count, &summary.DurationMSSum, &summary.DurationMSAvg, &summary.LLMCalls, &ok, &failed, &met)
	summary.Outcomes["ok"], summary.Outcomes["error"], summary.Outcomes["met"] = ok, failed, met
	return summary, err
}

func (d *DB) TaskLLMStats(ctx context.Context, taskID string) (TaskLLMStats, error) {
	stats := TaskLLMStats{ByWorker: []WorkerLLMStats{}}
	rows, err := d.QueryContext(ctx, `SELECT COALESCE(worker,''), count(*), count(*) FILTER (WHERE status='error'),
COALESCE(sum(input_tokens),0), COALESCE(sum(output_tokens),0), COALESCE(sum(cache_read),0), COALESCE(sum(cache_write),0),
COALESCE(percentile_cont(0.5) WITHIN GROUP (ORDER BY latency_ms),0),
COALESCE(percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms),0),
count(*) FILTER (WHERE intent_id IS NOT NULL), count(*) FILTER (WHERE intent_id IS NULL)
FROM llm_usage WHERE task_id=$1 GROUP BY COALESCE(worker,'') ORDER BY COALESCE(worker,'')`, taskID)
	if err != nil {
		return stats, err
	}
	defer rows.Close()
	for rows.Next() {
		var lane WorkerLLMStats
		var attributed, unattributed int64
		if err := rows.Scan(&lane.Worker, &lane.Calls, &lane.Errors, &lane.InputTokens, &lane.OutputTokens,
			&lane.CacheReadTokens, &lane.CacheWriteTokens, &lane.LatencyP50MS, &lane.LatencyP95MS,
			&attributed, &unattributed); err != nil {
			return stats, err
		}
		stats.ByWorker = append(stats.ByWorker, lane)
		if lane.Worker == "worker" {
			stats.WorkerCallsWithIntentID, stats.WorkerCallsWithoutIntentID = attributed, unattributed
		}
	}
	return stats, rows.Err()
}
