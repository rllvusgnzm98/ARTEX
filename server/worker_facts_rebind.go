package server

import (
	"log"

	"github.com/Autumn-27/artex/db"
)

const (
	workerReadToolsUnbindV1 = "worker_readtools_unbind_v1"
	workerFactsRebindV3     = "worker_facts_rebind_v3"
)

// workerFactsRebindKeys are the tools v1 stripped from worker that this
// migration puts back. list_worker_traces is intentionally absent: v2 already
// restored the worker look-back tools and must not be re-touched here.
var workerFactsRebindKeys = []string{"list_facts", "list_companies"}

// toolBindingStore is the settings + catalog surface seedWorkerFactsRebind needs.
// The real *db.DB implements it; tests use a fake.
type toolBindingStore interface {
	GetSetting(key string) (value string, ok bool, err error)
	SetSetting(key, value string) error
	GetTool(key string) (*db.Tool, error)
	AddAgentToToolBinding(agentKey string, keys []string) error
}

// seedWorkerFactsRebind re-binds list_facts and list_companies onto worker ONCE.
//
// Distinction:
//   - v1 unbind: settings flag worker_readtools_unbind_v1 is true and the tool
//     currently lacks the worker binding → attribute the gap to v1 and rebind.
//   - user-manual unbind: the tool is unbound but v1 never ran, or this v3
//     migration already completed (flag worker_facts_rebind_v3) → leave it.
//
// A later user unbind after v3 has run is protected by the one-shot flag, same
// as seedWorkerReadbackRebind. list_worker_traces is never written.
func (s *Server) seedWorkerFactsRebind() {
	if s == nil || s.m == nil || s.m.pg == nil {
		return
	}
	if err := applyWorkerFactsRebind(s.m.pg); err != nil {
		log.Printf("[worker] list_facts/list_companies 补绑失败: %v", err)
	}
}

func applyWorkerFactsRebind(store toolBindingStore) error {
	if v, _, err := store.GetSetting(workerFactsRebindV3); err != nil {
		return err
	} else if v == "true" {
		return nil
	}
	v1, _, err := store.GetSetting(workerReadToolsUnbindV1)
	if err != nil {
		return err
	}

	var keys []string
	for _, k := range workerFactsRebindKeys {
		t, err := store.GetTool(k)
		if err != nil {
			return err
		}
		if toolHasAgent(t, "worker") {
			continue // already bound; leave as-is
		}
		if v1 != "true" {
			// Unbound, and v1 never ran: treat as a user-manual unbind.
			continue
		}
		keys = append(keys, k)
	}
	if len(keys) > 0 {
		if err := store.AddAgentToToolBinding("worker", keys); err != nil {
			return err // 出错不落 flag，下次启动重试
		}
	}
	return store.SetSetting(workerFactsRebindV3, "true")
}

func toolHasAgent(t *db.Tool, agent string) bool {
	if t == nil {
		return false
	}
	for _, a := range t.Agents {
		if a == agent {
			return true
		}
	}
	return false
}
