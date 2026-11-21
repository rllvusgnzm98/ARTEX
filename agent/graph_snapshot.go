package agent

import "github.com/Autumn-27/artex/db"

// graphSnapshot memoizes exploration-graph reads for one prompt build. The full
// graph (nodes + edges) is loaded once and per-kind lists, capped edge lists and
// the cold-graph view are derived from it, so the overview and the worker entry
// seed no longer each re-query facts/findings/goals/edges and reload the whole
// graph. If the full load fails, reads fall back to the store's direct queries.
// Not safe for concurrent use; build one per prompt and discard it.
type graphSnapshot struct {
	ts     *db.ExplorationStore
	loaded bool
	nodes  []*db.Node // id ASC
	edges  []db.Edge
	cg     *coldGraph
	err    error
}

func newGraphSnapshot(ts *db.ExplorationStore) *graphSnapshot { return &graphSnapshot{ts: ts} }

func (s *graphSnapshot) load() error {
	if !s.loaded {
		s.loaded = true
		s.nodes, s.edges, s.err = loadGraphRows(s.ts)
		if s.err == nil {
			s.cg, _ = buildColdGraph(s.nodes, s.edges)
		}
	}
	return s.err
}

func (s *graphSnapshot) coldGraph() (*coldGraph, error) {
	if err := s.load(); err != nil {
		return nil, err
	}
	return s.cg, nil
}

// listByKind matches ExplorationStore.ListByKind: newest first, same default cap.
func (s *graphSnapshot) listByKind(kind string, limit int) ([]*db.Node, error) {
	if s.load() != nil {
		return s.ts.ListByKind(kind, limit)
	}
	if limit <= 0 {
		limit = 500
	}
	var out []*db.Node
	for i := len(s.nodes) - 1; i >= 0 && len(out) < limit; i-- {
		if s.nodes[i].Kind == kind {
			out = append(out, s.nodes[i])
		}
	}
	return out, nil
}

// edges matches ExplorationStore.Edges: at most limit edges, same default cap.
func (s *graphSnapshot) edgeList(limit int) ([]db.Edge, error) {
	if s.load() != nil {
		return s.ts.Edges(limit)
	}
	if limit <= 0 {
		limit = 5000
	}
	if len(s.edges) <= limit {
		return s.edges, nil
	}
	return s.edges[:limit], nil
}
