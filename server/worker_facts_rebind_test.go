package server

import (
	"testing"

	"github.com/Autumn-27/artex/db"
)

type fakeBindingStore struct {
	settings map[string]string
	tools    map[string]*db.Tool
	binds    [][]string
}

func newFakeBindingStore() *fakeBindingStore {
	return &fakeBindingStore{
		settings: map[string]string{},
		tools: map[string]*db.Tool{
			"list_facts":         {Key: "list_facts", Agents: []string{"planner", "mainagent"}},
			"list_companies":     {Key: "list_companies", Agents: []string{"planner", "mainagent", "auto"}},
			"list_worker_traces": {Key: "list_worker_traces", Agents: []string{"planner"}},
			"get_worker_trace":   {Key: "get_worker_trace", Agents: []string{"worker"}},
			"node_detail":        {Key: "node_detail", Agents: []string{"worker"}},
		},
	}
}

func (f *fakeBindingStore) GetSetting(key string) (string, bool, error) {
	v, ok := f.settings[key]
	return v, ok, nil
}

func (f *fakeBindingStore) SetSetting(key, value string) error {
	f.settings[key] = value
	return nil
}

func (f *fakeBindingStore) GetTool(key string) (*db.Tool, error) {
	t := f.tools[key]
	if t == nil {
		return nil, nil
	}
	cp := *t
	cp.Agents = append([]string(nil), t.Agents...)
	return &cp, nil
}

func (f *fakeBindingStore) AddAgentToToolBinding(agentKey string, keys []string) error {
	f.binds = append(f.binds, append([]string{agentKey}, keys...))
	for _, k := range keys {
		t := f.tools[k]
		if t == nil {
			continue
		}
		if !toolHasAgent(t, agentKey) {
			t.Agents = append(t.Agents, agentKey)
		}
	}
	return nil
}

func tracesAgents(f *fakeBindingStore) []string {
	return append([]string(nil), f.tools["list_worker_traces"].Agents...)
}

func TestFactsRebindRestoresV1UnbindOnLegacyDB(t *testing.T) {
	f := newFakeBindingStore()
	f.settings[workerReadToolsUnbindV1] = "true"

	if err := applyWorkerFactsRebind(f); err != nil {
		t.Fatal(err)
	}
	if f.settings[workerFactsRebindV3] != "true" {
		t.Fatal("v3 flag not set")
	}
	for _, key := range []string{"list_facts", "list_companies"} {
		if !toolHasAgent(f.tools[key], "worker") {
			t.Errorf("%s should be rebound onto worker after v1, agents=%v", key, f.tools[key].Agents)
		}
	}
	if toolHasAgent(f.tools["list_worker_traces"], "worker") {
		t.Fatal("list_worker_traces must not be touched by v3")
	}
}

func TestFactsRebindFreshDBAfterV1Pipeline(t *testing.T) {
	// Fresh startup: SeedTool would bind worker via WorkerTools(), then v1 strips
	// list_facts/list_companies and sets its flag, then v3 puts them back.
	f := newFakeBindingStore()
	f.tools["list_facts"].Agents = []string{"planner", "mainagent", "worker"}
	f.tools["list_companies"].Agents = []string{"planner", "auto", "worker"}
	// v1 unbind
	for _, key := range []string{"list_facts", "list_companies", "list_worker_traces"} {
		agents := f.tools[key].Agents
		kept := agents[:0]
		for _, a := range agents {
			if a != "worker" {
				kept = append(kept, a)
			}
		}
		f.tools[key].Agents = append([]string(nil), kept...)
	}
	f.settings[workerReadToolsUnbindV1] = "true"
	beforeTraces := tracesAgents(f)

	if err := applyWorkerFactsRebind(f); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"list_facts", "list_companies"} {
		if !toolHasAgent(f.tools[key], "worker") {
			t.Errorf("fresh DB after v1+v3 should bind worker to %s, agents=%v", key, f.tools[key].Agents)
		}
	}
	after := tracesAgents(f)
	if len(after) != len(beforeTraces) {
		t.Fatalf("list_worker_traces agents changed: before=%v after=%v", beforeTraces, after)
	}
	for i := range after {
		if after[i] != beforeTraces[i] {
			t.Fatalf("list_worker_traces agents changed: before=%v after=%v", beforeTraces, after)
		}
	}
}

func TestFactsRebindSkipsUserManualUnbindWithoutV1(t *testing.T) {
	f := newFakeBindingStore() // list_facts/list_companies unbound, v1 flag absent
	beforeFacts := append([]string(nil), f.tools["list_facts"].Agents...)
	beforeCo := append([]string(nil), f.tools["list_companies"].Agents...)

	if err := applyWorkerFactsRebind(f); err != nil {
		t.Fatal(err)
	}
	if f.settings[workerFactsRebindV3] != "true" {
		t.Fatal("v3 flag should still be set after a no-op")
	}
	if toolHasAgent(f.tools["list_facts"], "worker") || toolHasAgent(f.tools["list_companies"], "worker") {
		t.Fatal("user-manual unbind (v1 never ran) must not be forcibly rebound")
	}
	if len(f.binds) != 0 {
		t.Fatalf("expected no bind writes, got %v", f.binds)
	}
	assertSame := func(name string, got, want []string) {
		t.Helper()
		if len(got) != len(want) {
			t.Fatalf("%s agents changed: got=%v want=%v", name, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%s agents changed: got=%v want=%v", name, got, want)
			}
		}
	}
	assertSame("list_facts", f.tools["list_facts"].Agents, beforeFacts)
	assertSame("list_companies", f.tools["list_companies"].Agents, beforeCo)
}

func TestFactsRebindDoesNotOverrideLaterManualUnbind(t *testing.T) {
	f := newFakeBindingStore()
	f.settings[workerReadToolsUnbindV1] = "true"
	if err := applyWorkerFactsRebind(f); err != nil {
		t.Fatal(err)
	}
	if !toolHasAgent(f.tools["list_facts"], "worker") {
		t.Fatal("setup: v3 should have rebound list_facts")
	}
	// User later unbinds list_facts only.
	kept := []string{}
	for _, a := range f.tools["list_facts"].Agents {
		if a != "worker" {
			kept = append(kept, a)
		}
	}
	f.tools["list_facts"].Agents = kept
	f.binds = nil

	if err := applyWorkerFactsRebind(f); err != nil {
		t.Fatal(err)
	}
	if toolHasAgent(f.tools["list_facts"], "worker") {
		t.Fatal("later user-manual unbind of list_facts must survive a second v3 run")
	}
	if !toolHasAgent(f.tools["list_companies"], "worker") {
		t.Fatal("unrelated list_companies binding should stay")
	}
	if len(f.binds) != 0 {
		t.Fatalf("second run must be a no-op, binds=%v", f.binds)
	}
}

func TestFactsRebindIdempotentWhenAlreadyBound(t *testing.T) {
	f := newFakeBindingStore()
	f.settings[workerReadToolsUnbindV1] = "true"
	f.tools["list_facts"].Agents = append(f.tools["list_facts"].Agents, "worker")
	f.tools["list_companies"].Agents = append(f.tools["list_companies"].Agents, "worker")
	if err := applyWorkerFactsRebind(f); err != nil {
		t.Fatal(err)
	}
	if len(f.binds) != 0 {
		t.Fatalf("already-bound tools should not be rewritten, binds=%v", f.binds)
	}
	if f.settings[workerFactsRebindV3] != "true" {
		t.Fatal("flag should still be set")
	}
}
