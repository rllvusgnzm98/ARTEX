package agent

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
)

type scriptedComplete struct {
	text string
	err  error
}

type scriptedCompactorProvider struct {
	mu    sync.Mutex
	calls int
	steps []scriptedComplete
}

func (p *scriptedCompactorProvider) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(func(llm.StreamEvent, error) bool) {}
}

func (p *scriptedCompactorProvider) Complete(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	i := p.calls
	p.calls++
	if len(p.steps) == 0 {
		return llm.Message{}, "", llm.Usage{}, errors.New("no scripted responses")
	}
	if i >= len(p.steps) {
		i = len(p.steps) - 1
	}
	s := p.steps[i]
	if s.err != nil {
		return llm.Message{}, "", llm.Usage{}, s.err
	}
	return assistantText(s.text), "end_turn", llm.Usage{}, nil
}

func (p *scriptedCompactorProvider) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

func assistantText(s string) llm.Message {
	if s == "" {
		return llm.Message{Role: llm.RoleAssistant}
	}
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock(s)}}
}

type memGraphIncomplete struct {
	reason string
	sets   int
	clears int
}

func (m *memGraphIncomplete) SetGraphIncomplete(reason string) error {
	m.reason = reason
	m.sets++
	return nil
}

func (m *memGraphIncomplete) ClearGraphIncomplete() error {
	m.reason = ""
	m.clears++
	return nil
}

func (m *memGraphIncomplete) GraphIncompleteReason() (string, error) {
	return m.reason, nil
}

func testCompress(t *testing.T, prov llm.Provider) (string, error) {
	t.Helper()
	c := NewCompactor(prov, "test-model")
	return c.compress(context.Background(), newColdGraph(nil, nil), block{Members: []int64{1, 2}}, map[int64]*db.Node{})
}

func seedFromCompressSignal(reason string) WorkerEntrySeed {
	g, _ := multiStageGraph()
	if reason != "" {
		g.CompressErr = fmt.Errorf("%s", reason)
	}
	return BuildWorkerEntrySeed(g)
}

func TestCompressEmptyThenRetrySucceeds(t *testing.T) {
	prov := &scriptedCompactorProvider{steps: []scriptedComplete{
		{text: ""},
		{text: "综合：两台主机的已确认观察已折叠（#1,#2）"},
	}}
	sig := &memGraphIncomplete{}
	body, err := testCompress(t, prov)
	if err != nil {
		t.Fatalf("retry should succeed, err=%v", err)
	}
	if !strings.Contains(body, "已确认观察已折叠") {
		t.Fatalf("unexpected body %q", body)
	}
	if got := prov.callCount(); got != 2 {
		t.Fatalf("calls=%d, want 2 (empty then success)", got)
	}
	if err := syncGraphIncompleteSignal(sig, false, true); err != nil {
		t.Fatal(err)
	}
	if sig.reason != "" || sig.sets != 0 || sig.clears != 1 {
		t.Fatalf("successful retry must clear, not set, the signal: %+v", sig)
	}
	seed := seedFromCompressSignal(sig.reason)
	if seed.GraphIncomplete {
		t.Fatalf("successful compression must not be marked incomplete: %+v", seed)
	}
	prompt := RenderWorkerEntrySeed(seed)
	if strings.Contains(prompt, GraphIncompleteMarker) {
		t.Fatalf("successful retry must not inject %s:\n%s", GraphIncompleteMarker, prompt)
	}
}

func TestCompressEmptyRetriesExhaustedMarksIncomplete(t *testing.T) {
	// Mix the three empty-class shapes: empty body, empty response, no choices.
	prov := &scriptedCompactorProvider{steps: []scriptedComplete{
		{text: ""},
		{err: errors.New("openai: empty response (body: {})")},
		{err: errors.New("openai: empty response (no choices; body: {})")},
	}}
	body, err := testCompress(t, prov)
	if body != "" {
		t.Fatalf("exhausted retries must not return a body, got %q", body)
	}
	if !isEmptyCompressionErr(err) {
		t.Fatalf("want empty-class error, got %v", err)
	}
	if got := prov.callCount(); got != 1+compressEmptyRetries {
		t.Fatalf("calls=%d, want cap 1+compressEmptyRetries=%d", got, 1+compressEmptyRetries)
	}

	sig := &memGraphIncomplete{}
	if err := syncGraphIncompleteSignal(sig, true, false); err != nil {
		t.Fatal(err)
	}
	if sig.reason != "graph_compress" || sig.sets != 1 || sig.clears != 0 {
		t.Fatalf("exhaustion must set the first-class signal: %+v", sig)
	}

	g, _ := multiStageGraph()
	goalStates := map[int64]string{}
	for _, goal := range g.Goals {
		if goal != nil {
			goalStates[goal.ID] = goal.State
		}
	}
	nodeIDs := map[int64]bool{}
	for _, n := range append(append(g.Facts, g.Findings...), g.Goals...) {
		if n != nil {
			nodeIDs[n.ID] = true
		}
	}
	// Same hook LoadWorkerEntrySeed uses after reading the store signal.
	attachStoredGraphIncomplete(&g, sig)
	seed := BuildWorkerEntrySeed(g)
	if !seed.GraphIncomplete {
		t.Fatal("expected 图谱不完整 signal")
	}
	if len(seed.Writes) != 0 {
		t.Fatalf("fail-soft must not write nodes/goals, writes=%v", seed.Writes)
	}
	for _, goal := range g.Goals {
		if goal != nil && goalStates[goal.ID] != goal.State {
			t.Fatalf("goal state mutated: id=%d %s -> %s", goal.ID, goalStates[goal.ID], goal.State)
		}
	}
	for _, n := range append(append(g.Facts, g.Findings...), g.Goals...) {
		if n != nil && !nodeIDs[n.ID] {
			t.Fatalf("unexpected node write id=%d", n.ID)
		}
	}
	prompt := RenderWorkerEntrySeed(seed)
	if !strings.Contains(prompt, "【"+GraphIncompleteMarker+"】") {
		t.Fatalf("LoadWorkerEntrySeed hook must inject existing marker, prompt:\n%s", prompt)
	}
	if !strings.Contains(prompt, "进场不被阻断") {
		t.Fatalf("entry must not be blocked:\n%s", prompt)
	}
	if !strings.Contains(prompt, "不要把这次失败记录为目标失败") {
		t.Fatalf("must not record a target failure:\n%s", prompt)
	}
	// Entry is usable: incomplete seed still renders and does not count as a hard error.
	if prompt == "" {
		t.Fatal("fail-soft entry prompt must be non-empty")
	}
}

func TestSuccessfulCompressionNotMarkedIncomplete(t *testing.T) {
	prov := &scriptedCompactorProvider{steps: []scriptedComplete{
		{text: "已有压缩结论：相关已确认事实保持区分度（#1,#2）"},
	}}
	body, err := testCompress(t, prov)
	if err != nil {
		t.Fatalf("successful compression err=%v", err)
	}
	if body == "" {
		t.Fatal("successful compression returned empty body")
	}
	if got := prov.callCount(); got != 1 {
		t.Fatalf("calls=%d, want 1 (no empty retry)", got)
	}
	sig := &memGraphIncomplete{reason: "stale"}
	if err := syncGraphIncompleteSignal(sig, false, true); err != nil {
		t.Fatal(err)
	}
	if sig.reason != "" {
		t.Fatalf("already-successful compression must not stay marked incomplete: %+v", sig)
	}
	g, _ := multiStageGraph()
	attachStoredGraphIncomplete(&g, sig)
	seed := BuildWorkerEntrySeed(g)
	if seed.GraphIncomplete {
		t.Fatalf("already-successful compression mis-marked incomplete: %+v", seed)
	}
	prompt := RenderWorkerEntrySeed(seed)
	if strings.Contains(prompt, GraphIncompleteMarker) {
		t.Fatalf("must not inject %s after a successful compression:\n%s", GraphIncompleteMarker, prompt)
	}
}

func TestNonEmptyProviderErrorIsNotRetried(t *testing.T) {
	want := errors.New("provider 503")
	prov := &scriptedCompactorProvider{steps: []scriptedComplete{{err: want}}}
	_, err := testCompress(t, prov)
	if !errors.Is(err, want) {
		t.Fatalf("err=%v, want %v", err, want)
	}
	if got := prov.callCount(); got != 1 {
		t.Fatalf("non-empty errors must not retry, calls=%d", got)
	}
}

func TestLoadWorkerEntrySeedReadsIncompleteSignal(t *testing.T) {
	d, ts, intent, cleanup := openEntryExploration(t)
	defer cleanup()

	beforeNodes, beforeGoals := countNodesAndGoals(t, ts)

	if err := ts.SetGraphIncomplete("graph_compress"); err != nil {
		t.Fatal(err)
	}
	seed := LoadWorkerEntrySeed(ts, nil, intent)
	if !seed.GraphIncomplete {
		t.Fatal("LoadWorkerEntrySeed must surface the stored 图谱不完整 signal")
	}
	if len(seed.Writes) != 0 {
		t.Fatalf("LoadWorkerEntrySeed must not write, writes=%v", seed.Writes)
	}
	prompt := RenderWorkerEntrySeed(seed)
	if !strings.Contains(prompt, "【"+GraphIncompleteMarker+"】") {
		t.Fatalf("LoadWorkerEntrySeed must inject existing marker:\n%s", prompt)
	}
	if !strings.Contains(prompt, "进场不被阻断") {
		t.Fatalf("entry must not be blocked:\n%s", prompt)
	}

	afterNodes, afterGoals := countNodesAndGoals(t, ts)
	if afterNodes != beforeNodes || afterGoals != beforeGoals {
		t.Fatalf("signal path wrote nodes/goals: nodes %d→%d goals %d→%d",
			beforeNodes, afterNodes, beforeGoals, afterGoals)
	}

	// Exhausted empty compression must set the same signal and not write a digest.
	c := NewCompactor(&scriptedCompactorProvider{steps: []scriptedComplete{
		{text: ""},
		{text: ""},
		{err: errors.New("openai: empty response (no choices; body: {})")},
	}}, "test-model")
	got := c.foldBlock(context.Background(), ts, newColdGraph(nil, nil), block{Members: []int64{1, 2}}, map[int64]*db.Node{}, map[int64]int{}, 1)
	if got != foldEmptyExhausted {
		t.Fatalf("foldBlock=%v, want foldEmptyExhausted", got)
	}
	if err := syncGraphIncompleteSignal(ts, true, false); err != nil {
		t.Fatal(err)
	}
	reason, err := ts.GraphIncompleteReason()
	if err != nil {
		t.Fatal(err)
	}
	if reason != "graph_compress" {
		t.Fatalf("stored reason=%q, want graph_compress", reason)
	}
	afterFoldNodes, afterFoldGoals := countNodesAndGoals(t, ts)
	if afterFoldNodes != beforeNodes || afterFoldGoals != beforeGoals {
		t.Fatalf("exhausted fold wrote nodes/goals: nodes %d→%d goals %d→%d",
			beforeNodes, afterFoldNodes, beforeGoals, afterFoldGoals)
	}
	_ = d
}

func TestLoadWorkerEntrySeedSuccessfulCompressionNotIncomplete(t *testing.T) {
	_, ts, intent, cleanup := openEntryExploration(t)
	defer cleanup()

	if err := ts.SetGraphIncomplete("graph_compress"); err != nil {
		t.Fatal(err)
	}
	if err := syncGraphIncompleteSignal(ts, false, true); err != nil {
		t.Fatal(err)
	}
	reason, err := ts.GraphIncompleteReason()
	if err != nil {
		t.Fatal(err)
	}
	if reason != "" {
		t.Fatalf("successful compression left stale signal %q", reason)
	}
	seed := LoadWorkerEntrySeed(ts, nil, intent)
	if seed.GraphIncomplete {
		t.Fatalf("already-successful compression mis-marked incomplete: %+v", seed)
	}
	prompt := RenderWorkerEntrySeed(seed)
	if strings.Contains(prompt, GraphIncompleteMarker) {
		t.Fatalf("must not inject %s:\n%s", GraphIncompleteMarker, prompt)
	}
}

func openEntryExploration(t *testing.T) (*db.DB, *db.ExplorationStore, *db.Node, func()) {
	t.Helper()
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	expID, err := d.CreateExploration("多主机授权场景进场预取", "继续核验已确认可达但尚未兑现的后续目标")
	if err != nil {
		d.Close()
		t.Fatal(err)
	}
	ts := d.Exploration(expID)
	intentID, err := ts.AddIntent(map[string]any{
		"summary": "在已确认可达的应用主机上继续核验，不要把该主机当新目标重开",
	}, 0, nil, "test")
	if err != nil {
		_, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
		d.Close()
		t.Fatal(err)
	}
	intent, err := ts.GetNode(intentID)
	if err != nil {
		_, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
		d.Close()
		t.Fatal(err)
	}
	cleanup := func() {
		_, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
		_ = d.Close()
	}
	return d, ts, intent, cleanup
}

func countNodesAndGoals(t *testing.T, ts *db.ExplorationStore) (nodes, goals int) {
	t.Helper()
	all, err := ts.Nodes(1000)
	if err != nil {
		t.Fatal(err)
	}
	goalNodes, err := ts.ListByKind(db.KindGoal, 200)
	if err != nil {
		t.Fatal(err)
	}
	return len(all), len(goalNodes)
}

func TestCompactorMajorPreservesMaxGenerationAndSkipsIndependentChurn(t *testing.T) {
	_, ts := retentionStore(t)
	// Create 9 independent cold branches (exceeding default c.m=8).
	var firstIntent, firstFact int64
	for i := 0; i < 9; i++ {
		iid, err := ts.AddNode(db.KindIntent, map[string]any{"summary": fmt.Sprintf("branch-%d", i)}, 0, "done", "test", nil)
		if err != nil {
			t.Fatal(err)
		}
		fid, err := ts.AddNode(db.KindFact, map[string]any{"summary": fmt.Sprintf("fact-%d", i)}, 0, "confirmed", "test", nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := ts.Link(iid, db.RelYields, fid); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			firstIntent, firstFact = iid, fid
		}
	}
	prov := &scriptedCompactorProvider{steps: []scriptedComplete{{text: "独立分支摘要"}}}
	c := NewCompactor(prov, "test-model")
	c.params.R = 0
	c.cooldown = 0
	if _, _, _, err := c.maintain(ts); err != nil {
		t.Fatal(err)
	}
	c.minor(t.Context(), ts)
	callsAfterMinor := prov.callCount()
	if callsAfterMinor != 9 {
		t.Fatalf("expected 9 initial minor compressions, got %d", callsAfterMinor)
	}
	// Next maintainState: activeDigests=9 >= c.m(8), but all 9 are independent → needMajor must be false!
	st, err := c.maintainState(ts)
	if err != nil {
		t.Fatal(err)
	}
	if st.activeDigests != 9 || st.needMajor {
		t.Fatalf("independent 9 digests should not trigger major: %+v", st)
	}

	// Verify generation cap in major(): seed a gen=maxDigestGeneration digest covering branch 0,
	// attach a new cold fact so branch 0's signature changes, and confirm major() preserves it
	// without refolding into gen4+.
	active, err := ts.ActiveDigests()
	if err != nil {
		t.Fatal(err)
	}
	var branch0Digest int64
	for _, d := range active {
		for _, m := range digestMemberIDs(d) {
			if m == firstIntent {
				branch0Digest = d.ID
			}
		}
	}
	if branch0Digest == 0 {
		t.Fatal("branch 0 digest not found")
	}
	if err := ts.SupersedeDigests([]int64{branch0Digest}); err != nil {
		t.Fatal(err)
	}
	genCapDigest, err := ts.AddDigest(map[string]any{
		"body":       "frozen gen3 body",
		"member_ids": map[string]any{"facts": []int64{firstFact}, "intents": []int64{firstIntent}},
		"generation": maxDigestGeneration,
		"signature":  "old-gen3-sig",
	}, []int64{firstIntent, firstFact})
	if err != nil {
		t.Fatal(err)
	}
	extraFact, err := ts.AddNode(db.KindFact, map[string]any{"summary": "late fact on branch 0"}, 0, "confirmed", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ts.Link(firstIntent, db.RelYields, extraFact); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := c.maintain(ts); err != nil {
		t.Fatal(err)
	}
	callsBeforeMajor := prov.callCount()
	c.major(t.Context(), ts)
	if prov.callCount() != callsBeforeMajor {
		t.Fatalf("major refolded gen=%d digest (extra calls=%d)", maxDigestGeneration, prov.callCount()-callsBeforeMajor)
	}
	activeAfter, err := ts.ActiveDigests()
	if err != nil {
		t.Fatal(err)
	}
	foundFrozen := false
	for _, d := range activeAfter {
		if d.ID == genCapDigest {
			foundFrozen = true
		}
		if _, gen := digestSigGen(d); gen > maxDigestGeneration {
			t.Fatalf("digest #%d exceeded max generation %d: gen=%d", d.ID, maxDigestGeneration, gen)
		}
	}
	if !foundFrozen {
		t.Fatalf("gen=%d digest #%d was superseded instead of preserved", maxDigestGeneration, genCapDigest)
	}
}

func TestGraphOverviewColdDigestsCompactAndOverflowIDs(t *testing.T) {
	_, ts := retentionStore(t)
	longBody := strings.Repeat("冷区历史折叠正文", 40) // 320 runes (>120)
	var digestIDs []int64
	for i := 0; i < 10; i++ {
		fid, err := ts.AddNode(db.KindFact, map[string]any{"summary": fmt.Sprintf("cold-%d", i)}, 0, "confirmed", "test", nil)
		if err != nil {
			t.Fatal(err)
		}
		did, err := ts.AddDigest(map[string]any{
			"body":       longBody,
			"member_ids": map[string]any{"facts": []int64{fid}},
			"generation": 1,
			"signature":  fmt.Sprintf("sig-%d", i),
		}, []int64{fid})
		if err != nil {
			t.Fatal(err)
		}
		digestIDs = append(digestIDs, did)
	}
	ov := NewToolSet(ts, "planner").graphOverviewData()
	cds, ok := ov["cold_digests"].([]map[string]any)
	if !ok || len(cds) != plannerColdDigestsCap {
		t.Fatalf("cold_digests len=%d want %d (ok=%v)", len(cds), plannerColdDigestsCap, ok)
	}
	for _, entry := range cds {
		body, _ := entry["body"].(string)
		if utf8.RuneCountInString(body) > plannerColdDigestBodyMax+1 {
			t.Fatalf("cold digest body not clipped to <=%d runes: got %d (%q)", plannerColdDigestBodyMax, utf8.RuneCountInString(body), body)
		}
	}
	more, ok := ov["cold_digests_more"].([]int64)
	if !ok || len(more) != len(digestIDs)-plannerColdDigestsCap {
		t.Fatalf("cold_digests_more=%v want %d overflow IDs", more, len(digestIDs)-plannerColdDigestsCap)
	}
}
