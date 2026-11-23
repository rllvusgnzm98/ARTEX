package db

import (
	"encoding/json"
	"strings"
)

// SetCrownJewel marks/unmarks a global asset as a crown jewel (目标导向分析) and
// records its business value note. Unmarking leaves the note cleared.
func (s *AssetStore) SetCrownJewel(id int64, on bool, note string) error {
	note = strings.TrimSpace(note)
	if !on {
		note = ""
	}
	_, err := s.db.Exec(
		`UPDATE assets SET crown_jewel=$2, crown_jewel_note=NULLIF($3,''), updated_at=now() WHERE id=$1`,
		id, on, note)
	return err
}

// CrownJewels lists every asset currently flagged as a crown jewel (newest first).
func (s *AssetStore) CrownJewels() ([]*Asset, error) {
	rows, err := s.db.Query(assetSelectCols + " WHERE crown_jewel ORDER BY id DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAssets(rows)
}

// CrownJewelPathNode is one reasoning node on the lineage chain that reached a
// crown jewel target.
type CrownJewelPathNode struct {
	ID      int64  `json:"id"`
	Kind    string `json:"kind"`
	State   string `json:"state"`
	Summary string `json:"summary"`
}

// CrownJewelStatus is this exploration's situational standing toward one crown
// jewel target asset: whether a finding/fact already touched it, the exploration
// nodes anchored to it, the lineage chain (root→…→reaching node), and the graph
// distance from the current open frontier to the target.
type CrownJewelStatus struct {
	AssetID          int64                `json:"asset_id"`
	ReachedByFinding bool                 `json:"reached_by_finding"`
	ReachedByFact    bool                 `json:"reached_by_fact"`
	AnchoredNodes    []AssetRef           `json:"anchored_nodes"`
	FrontierDistance *int                 `json:"frontier_distance,omitempty"`
	Path             []CrownJewelPathNode `json:"path,omitempty"`
}

// CrownJewelStatusFor computes this exploration's standing toward the given crown
// jewel target asset by retracing the exploration graph lineage
// (derived_from/yields/spawns upstream) and measuring frontier→target distance.
func (s *ExplorationStore) CrownJewelStatusFor(assetID int64) (CrownJewelStatus, error) {
	st := CrownJewelStatus{AssetID: assetID, AnchoredNodes: []AssetRef{}}
	allRefs, err := s.AssetRefs(assetID)
	if err != nil {
		return st, err
	}
	// Exclude the task's origin/seed fact: its anchor to the configured target is
	// provenance ("this is the objective"), not an observation that reached it —
	// otherwise a seeded target would read as reached before any work runs.
	refs := make([]AssetRef, 0, len(allRefs))
	for _, r := range allRefs {
		if r.Kind == KindFact && r.State == StateOrigin {
			continue
		}
		refs = append(refs, r)
	}
	st.AnchoredNodes = refs
	anchored := map[int64]bool{}
	for _, r := range refs {
		anchored[r.ID] = true
		switch r.Kind {
		case KindFinding:
			st.ReachedByFinding = true
		case KindFact:
			st.ReachedByFact = true
		}
	}

	edges, err := s.Edges(5000)
	if err != nil {
		return st, err
	}
	// parentsOf: child node -> its upstream parents, retraced along lineage edges.
	parentsOf := map[int64][]int64{}
	adj := map[int64][]int64{} // undirected, for frontier distance
	for _, e := range edges {
		adj[e.From] = append(adj[e.From], e.To)
		adj[e.To] = append(adj[e.To], e.From)
		switch e.Rel {
		case RelDerivedFrom, RelSpawns, RelYields:
			// Lineage edges are stored src=parent→dst=child (see FindingLineage's
			// ancestor walk): derived_from (source fact/finding→derived intent),
			// spawns (root→goal), yields (intent→fact/finding). proves (evidence→
			// goal) is a downstream assertion, not lineage, so it is excluded.
			parentsOf[e.To] = append(parentsOf[e.To], e.From)
		}
	}

	// Attack path: pick a representative reaching node (prefer finding, else fact,
	// else intent — refs are newest-first) and walk upstream to the task root.
	var start int64
	pick := func(kind string) int64 {
		for _, r := range refs {
			if r.Kind == kind {
				return r.ID
			}
		}
		return 0
	}
	for _, k := range []string{KindFinding, KindFact, KindIntent} {
		if start = pick(k); start != 0 {
			break
		}
	}
	if start != 0 {
		chain := []int64{}
		seen := map[int64]bool{}
		cur := start
		for cur != 0 && !seen[cur] {
			seen[cur] = true
			chain = append(chain, cur)
			ps := parentsOf[cur]
			var next int64
			for _, p := range ps { // prefer the lowest id (closest to root)
				if !seen[p] && (next == 0 || p < next) {
					next = p
				}
			}
			cur = next
		}
		// chain is reaching-node→…→root; reverse to root→…→reaching-node.
		for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
			chain[i], chain[j] = chain[j], chain[i]
		}
		st.Path = s.pathNodes(chain)
	}

	// Frontier distance: undirected BFS from every open intent to the nearest
	// anchored node. 0 = frontier itself already anchored to the target; nil =
	// no node touches the target yet (unreached, distance unknown).
	if len(anchored) > 0 {
		frontier, _ := s.openIntentIDs()
		if len(frontier) > 0 {
			dist := map[int64]int{}
			queue := []int64{}
			for _, f := range frontier {
				dist[f] = 0
				queue = append(queue, f)
			}
			best := -1
			for len(queue) > 0 {
				n := queue[0]
				queue = queue[1:]
				if anchored[n] {
					best = dist[n]
					break
				}
				for _, nb := range adj[n] {
					if _, ok := dist[nb]; !ok {
						dist[nb] = dist[n] + 1
						queue = append(queue, nb)
					}
				}
			}
			if best >= 0 {
				st.FrontierDistance = &best
			}
		}
	}
	return st, nil
}

// pathNodes hydrates node ids into compact path entries (kind/state/summary).
func (s *ExplorationStore) pathNodes(ids []int64) []CrownJewelPathNode {
	out := []CrownJewelPathNode{}
	for _, id := range ids {
		n, err := s.GetNode(id)
		if err != nil || n == nil {
			continue
		}
		out = append(out, CrownJewelPathNode{
			ID:      n.ID,
			Kind:    n.Kind,
			State:   n.State,
			Summary: nodeSummary(n),
		})
	}
	return out
}

// openIntentIDs returns the ids of this exploration's open intents (the frontier).
func (s *ExplorationStore) openIntentIDs() ([]int64, error) {
	rows, err := s.db.Query(
		`SELECT id FROM exploration_nodes WHERE exploration_id=$1 AND kind='intent' AND state='open'`,
		s.expID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// nodeSummary extracts a short human label from a node payload (summary, else text).
func nodeSummary(n *Node) string {
	var p map[string]any
	_ = json.Unmarshal(n.Payload, &p)
	for _, k := range []string{"summary", "text", "name"} {
		if v, ok := p[k].(string); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// Unanchor removes a node→asset anchor (used to un-anchor a goal from a crown jewel).
func (s *ExplorationStore) Unanchor(nodeID, assetID int64) error {
	_, err := s.db.Exec(
		`DELETE FROM exploration_anchors WHERE node_id=$1 AND asset_id=$2`, nodeID, assetID)
	return err
}

// AnchoredGoalIDs returns the goal node ids in THIS exploration anchored to the
// given asset — i.e. which objectives target this (crown jewel) asset.
func (s *ExplorationStore) AnchoredGoalIDs(assetID int64) ([]int64, error) {
	rows, err := s.db.Query(`
SELECT en.id
FROM exploration_anchors ea
JOIN exploration_nodes en ON en.id = ea.node_id
WHERE ea.asset_id = $1 AND en.exploration_id = $2 AND en.kind = 'goal'
ORDER BY en.id`, assetID, s.expID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []int64{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
