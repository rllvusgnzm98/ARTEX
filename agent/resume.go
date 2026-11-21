package agent

import (
	"fmt"
	"log"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/agentcore"
)

func resumeHistory(s *agentcore.Session, sessionID, worker string, emit func(db.Activity)) string {
	if err := s.Resume(sessionID); err != nil {
		warning := fmt.Sprintf("history restoration failed: %v; previous context lost, re-read graph/transcript", err)
		log.Printf("[resume] session=%s worker=%s: %s", sessionID, worker, warning)
		if emit != nil {
			emit(db.Activity{Worker: worker, Kind: "error", IsError: true, Summary: firstLine(warning, 200), Detail: warning})
		}
		return warning + "\n\n"
	}
	return ""
}
