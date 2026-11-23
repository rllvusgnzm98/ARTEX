package db

import "encoding/json"

// SummarizeToolActivityOutcomes groups exported tool results without guessing
// whether a legacy IsError flag came from execution or a policy rejection.
func SummarizeToolActivityOutcomes(activities []Activity) map[string]int {
	counts := map[string]int{}
	for _, activity := range activities {
		if activity.Kind != "tool_result" {
			continue
		}
		var metadata struct {
			Class string `json:"outcome_class"`
		}
		if json.Unmarshal(activity.Metadata, &metadata) != nil || metadata.Class == "" {
			metadata.Class = "unknown"
		}
		counts[metadata.Class]++
	}
	return counts
}
