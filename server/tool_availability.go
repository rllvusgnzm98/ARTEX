package server

import (
	"net/http"

	"github.com/Autumn-27/artex/agent"
)

func (s *Server) toolAvailability(w http.ResponseWriter, r *http.Request) {
	dataDir := ""
	if s.m != nil {
		dataDir = s.m.dir
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, agent.ShellHintAvailability(r.Context(), dataDir))
}
