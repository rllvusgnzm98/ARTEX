package server

import (
	"net/http"

	"github.com/Autumn-27/artex/db"
)

type taskStatsResponse struct {
	IntentCounts map[string]int       `json:"intent_counts"`
	PlanRounds   db.PlanRoundsSummary `json:"plan_rounds"`
	LLMUsage     db.TaskLLMStats      `json:"llm_usage"`
}

func (s *Server) taskStats(w http.ResponseWriter, r *http.Request) {
	task, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	counts, err := task.Store.IntentCountsByState(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	rounds, err := pg.TaskPlanRoundsSummary(r.Context(), task.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	usage, err := pg.TaskLLMStats(r.Context(), task.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, taskStatsResponse{IntentCounts: counts, PlanRounds: rounds, LLMUsage: usage})
}
