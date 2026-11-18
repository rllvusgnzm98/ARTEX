package db

import (
	"database/sql"
	"strings"
)

// GraphIncompleteReason is the first-class fail-soft signal written when graph
// compression exhausts empty-response retries. An empty string means the graph
// is not marked incomplete. This is not a node or goal state.
func (s *ExplorationStore) GraphIncompleteReason() (string, error) {
	if s == nil || s.db == nil {
		return "", nil
	}
	var reason string
	err := s.db.QueryRow(`SELECT graph_incomplete_reason FROM explorations WHERE id=$1`, s.expID).Scan(&reason)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(reason), nil
}

// SetGraphIncomplete records the fail-soft incomplete-graph signal. It updates
// only the exploration's signal column and never writes nodes or goal state.
func (s *ExplorationStore) SetGraphIncomplete(reason string) error {
	if s == nil || s.db == nil {
		return nil
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "graph_compress"
	}
	_, err := s.db.Exec(`UPDATE explorations SET graph_incomplete_reason=$2 WHERE id=$1`, s.expID, reason)
	return err
}

// ClearGraphIncomplete drops a previously recorded incomplete-graph signal,
// for example after a later compression attempt succeeds.
func (s *ExplorationStore) ClearGraphIncomplete() error {
	if s == nil || s.db == nil {
		return nil
	}
	_, err := s.db.Exec(`UPDATE explorations SET graph_incomplete_reason='' WHERE id=$1`, s.expID)
	return err
}
