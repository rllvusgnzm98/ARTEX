package agent

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestEntrySeedOldKeyFactsBeyondPrefetch(t *testing.T) {
	for _, tc := range []struct {
		relevantGeneral int
		lastCategory    string
	}{{100, "scope_limit"}, {1495, ""}} {
		relevantGeneral := tc.relevantGeneral
		t.Run(fmt.Sprintf("relevant_general=%d", relevantGeneral), func(t *testing.T) {
			d, es := retentionStore(t)
			tools := NewToolSet(es, "worker")
			var keyIDs []int64
			for i, category := range []string{"negative_result", "scope_limit", "cleanup_status", "evidence", tc.lastCategory} {
				var refs []string
				if i >= 3 {
					refs = []string{fmt.Sprintf("evidence:%d", i)}
				}
				id, err := tools.recordOneFact(factItem{
					Summary: fmt.Sprintf("old-key-%d", i), Category: category,
					Confidence: "inferred", EvidenceIDs: refs,
				}, 0)
				if err != nil {
					t.Fatal(err)
				}
				keyIDs = append(keyIDs, id)
			}
			intentID, err := es.AddIntent(map[string]any{"summary": "continue with retained context"}, 0, nil, "planner")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := d.Exec(`INSERT INTO exploration_nodes (exploration_id,kind,payload,priority,state,origin)
SELECT $1,'fact',jsonb_build_object('summary','general-'||lpad(g::text,4,'0'),'sequence',g,'confidence','observed'),5,'confirmed','entry-priority-general'
FROM generate_series(1,1495) AS g`, es.ID()); err != nil {
				t.Fatal(err)
			}
			if _, err := d.Exec(`INSERT INTO exploration_edges (exploration_id,src_id,rel,dst_id)
SELECT $1,id,'derived_from',$2 FROM exploration_nodes
WHERE exploration_id=$1 AND origin='entry-priority-general' AND (payload->>'sequence')::int <= $3`, es.ID(), intentID, relevantGeneral); err != nil {
				t.Fatal(err)
			}
			keys, err := es.EntrySeedFacts(true)
			if err != nil || len(keys) != 5 {
				t.Fatalf("independent key query=%v err=%v", keys, err)
			}
			for i, key := range keys {
				if key.ID != keyIDs[i] {
					t.Errorf("key order=%d want %d", key.ID, keyIDs[i])
				}
			}
			intent, err := es.GetNode(intentID)
			if err != nil {
				t.Fatal(err)
			}
			seed := LoadWorkerEntrySeed(es, nil, intent)
			if seed.GraphIncomplete || len(seed.ConfirmedFacts) != relevantGeneral+5 {
				t.Fatalf("entry fact count=%d want %d incomplete=%v", len(seed.ConfirmedFacts), relevantGeneral+5, seed.GraphIncomplete)
			}
			prompt := RenderWorkerEntrySeed(seed)
			for i, id := range keyIDs {
				if !strings.Contains(prompt, fmt.Sprintf("fact #%d ", id)) || i >= 3 && !strings.Contains(prompt, fmt.Sprintf(`evidence_ids=["evidence:%d"]`, i)) {
					t.Errorf("key #%d or its evidence reference missing:\n%s", id, prompt)
				}
			}
			for _, category := range []string{"negative_result", "scope_limit", "cleanup_status", "evidence"} {
				if !strings.Contains(prompt, "[category="+category+"]") {
					t.Errorf("category %s missing from seed", category)
				}
			}
			omitted := relevantGeneral - (entrySeedFactCap - 5)
			wantNote := fmt.Sprintf("另有 %d 条事实未列出：关键事实 0 条，相关普通事实 %d 条", omitted, omitted)
			if !strings.Contains(prompt, wantNote) || !strings.Contains(prompt, "list_facts / node_detail") {
				t.Errorf("wrong omission note, want %q:\n%s", wantNote, prompt)
			}
			if got := strings.Count(prompt, "- fact #"); got != entrySeedFactCap {
				t.Errorf("rendered facts=%d want %d", got, entrySeedFactCap)
			}
			if !strings.Contains(prompt, fmt.Sprintf("general-%04d", relevantGeneral)) || strings.Contains(prompt, fmt.Sprintf("general-%04d", relevantGeneral-55)) {
				t.Error("ordinary slots must contain only the newest relevant facts")
			}
		})
	}
}

func TestRenderEntrySeedKeyCapAndOmissions(t *testing.T) {
	seed := WorkerEntrySeed{Prefetched: true}
	for i := 44; i >= 0; i-- {
		seed.ConfirmedFacts = append(seed.ConfirmedFacts, EntryFact{ID: int64(i + 1), Summary: fmt.Sprintf("key-%d", i), Category: "scope_limit"})
	}
	for i := 99; i >= 0; i-- {
		seed.ConfirmedFacts = append(seed.ConfirmedFacts, EntryFact{ID: int64(i + 100), Summary: fmt.Sprintf("ordinary-%d", i)})
	}
	prompt := RenderWorkerEntrySeed(seed)
	if strings.Count(prompt, "- fact #") != 60 || strings.Count(prompt, "[category=scope_limit]") != 40 {
		t.Fatalf("wrong class caps:\n%s", prompt)
	}
	if !strings.Contains(prompt, "fact #1 ") || !strings.Contains(prompt, "fact #40 ") || strings.Contains(prompt, "fact #41 ") || strings.Contains(prompt, "fact #179 ") || !strings.Contains(prompt, "fact #180 ") || !strings.Contains(prompt, "fact #199 ") {
		t.Errorf("must retain oldest 40 keys, newest 20 ordinary facts:\n%s", prompt)
	}
	if strings.Index(prompt, "fact #40 ") > strings.Index(prompt, "fact #180 ") {
		t.Error("keys must render before ordinary facts")
	}
	if !strings.Contains(prompt, "另有 85 条事实未列出：关键事实 5 条，相关普通事实 80 条") || !strings.Contains(prompt, "list_facts / node_detail") {
		t.Errorf("incorrect class omission counts:\n%s", prompt)
	}
}

func TestEntrySeedKeyFactsDoNotImplyReachability(t *testing.T) {
	intent := node(1, db.KindIntent, "open", nil)
	key := node(2, db.KindFact, "confirmed", map[string]any{"summary": "scope excludes this host", "category": "scope_limit", "confidence": "inferred", "evidence_ids": []string{"scope:1"}})
	dismissed := node(3, db.KindFact, "dismissed", map[string]any{"summary": "obsolete restriction", "category": "scope_limit"})
	seed := BuildWorkerEntrySeed(EntryGraph{Intent: intent, Facts: []*db.Node{key, dismissed}, Anchors: map[int64][]int64{2: {22}}})
	if len(seed.ConfirmedFacts) != 1 || seed.ConfirmedFacts[0].ID != key.ID || len(seed.NextHops) != 0 || RepeatScanRisk(seed, []int64{22}) != 1 {
		t.Fatalf("key constraints must survive without implying a confirmed reachable next hop: %+v", seed)
	}
	prompt := RenderWorkerEntrySeed(seed)
	if !strings.Contains(prompt, "(inferred)") || !strings.Contains(prompt, "[category=scope_limit]") || !strings.Contains(prompt, `evidence_ids=["scope:1"]`) {
		t.Errorf("key attributes lost:\n%s", prompt)
	}
}

func TestEntrySeedPriorityEmptyAndQueryError(t *testing.T) {
	_, es := retentionStore(t)
	intentID, err := es.AddIntent(map[string]any{"summary": "no facts"}, 0, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	intent, err := es.GetNode(intentID)
	if err != nil {
		t.Fatal(err)
	}
	seed := LoadWorkerEntrySeed(es, nil, intent)
	if len(seed.ConfirmedFacts) != 0 || seed.GraphIncomplete || strings.Contains(RenderWorkerEntrySeed(seed), "未列出") {
		t.Fatalf("unexpected empty seed: %+v", seed)
	}
	failedDB := testDB(t)
	failedStore := failedDB.Exploration(es.ID())
	if err := failedDB.Close(); err != nil {
		t.Fatal(err)
	}
	for _, key := range []bool{true, false} {
		if _, err := failedStore.EntrySeedFacts(key); err == nil {
			t.Errorf("key=%v: closed database must return an error", key)
		}
	}
	if seed := LoadWorkerEntrySeed(failedStore, nil, intent); !seed.GraphIncomplete || seed.Prefetched || len(seed.Writes) != 0 {
		t.Fatalf("query errors must remain read-only and fail soft: %+v", seed)
	}
}
