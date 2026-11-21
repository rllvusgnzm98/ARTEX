package agent

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestRecordFactStructuredPriority(t *testing.T) {
	_, es := retentionStore(t)
	tool := NewToolSet(es, "worker").recordFact()
	for _, category := range []string{"", "negative_result", "scope_limit", "cleanup_status", "evidence"} {
		t.Run("category="+category, func(t *testing.T) {
			input := map[string]any{"summary": "structured observation", "category": category, "evidence_ids": []string{"traffic:73", "artifact:cleanup.json"}}
			raw, _ := json.Marshal(input)
			result, err := tool.Call(t.Context(), raw, nil)
			if err != nil || result.IsError {
				t.Fatalf("record_fact failed: %s %v", result.Flatten(), err)
			}
			var id int64
			if _, err := fmt.Sscanf(result.Flatten(), "fact recorded: %d", &id); err != nil {
				t.Fatal(err)
			}
			n, err := es.GetNode(id)
			if err != nil {
				t.Fatal(err)
			}
			var got factItem
			if err := json.Unmarshal(n.Payload, &got); err != nil {
				t.Fatal(err)
			}
			if n.Kind != db.KindFact || got.Category != category || !reflect.DeepEqual(got.EvidenceIDs, input["evidence_ids"]) {
				t.Fatalf("structured payload lost or converted to finding: %s", n.Payload)
			}
		})
	}
	result, err := tool.Call(t.Context(), json.RawMessage(`{"summary":"plain observation"}`), nil)
	if err != nil || result.IsError {
		t.Fatalf("omitted optional fields: %s %v", result.Flatten(), err)
	}
	var id int64
	if _, err := fmt.Sscanf(result.Flatten(), "fact recorded: %d", &id); err != nil {
		t.Fatal(err)
	}
	n, err := es.GetNode(id)
	if err != nil {
		t.Fatal(err)
	}
	var plain map[string]any
	if err := json.Unmarshal(n.Payload, &plain); err != nil {
		t.Fatal(err)
	}
	if _, exists := plain["category"]; exists {
		t.Error("omitted category must remain general without changing legacy payloads")
	}
	if _, exists := plain["evidence_ids"]; exists {
		t.Error("omitted evidence_ids should not be written")
	}
	for _, input := range []string{
		`{"summary":"invalid","category":"finding"}`,
		`{"summary":"invalid","category":"general"}`,
		`{"summary":"invalid","evidence_ids":[3]}`,
		`{"summary":"invalid","evidence_ids":"not-a-list"}`,
		`{`,
	} {
		before, err := es.CountByKind(db.KindFact)
		if err != nil {
			t.Fatal(err)
		}
		result, err := tool.Call(t.Context(), json.RawMessage(input), nil)
		if err != nil || !result.IsError {
			t.Errorf("invalid input accepted: %s => %s, %v", input, result.Flatten(), err)
		}
		after, err := es.CountByKind(db.KindFact)
		if err != nil || before != after {
			t.Fatalf("invalid input wrote a fact: before=%d after=%d err=%v", before, after, err)
		}
	}
}

func TestRecordFactBatchPrioritySchema(t *testing.T) {
	_, es := retentionStore(t)
	tool := NewToolSet(es, "worker").recordFact()
	props := tool.InputSchema()["properties"].(map[string]any)
	itemProps := props["facts"].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)
	for _, p := range []map[string]any{props, itemProps} {
		category := p["category"].(map[string]any)
		if !reflect.DeepEqual(category["enum"], []string{"negative_result", "scope_limit", "cleanup_status", "evidence"}) {
			t.Errorf("missing category enum: %v", category)
		}
		ids := p["evidence_ids"].(map[string]any)
		if ids["type"] != "array" || ids["items"].(map[string]any)["type"] != "string" {
			t.Errorf("invalid evidence_ids schema: %v", ids)
		}
	}
	result, err := tool.Call(t.Context(), json.RawMessage(`{"facts":[{"summary":"one","category":"scope_limit","evidence_ids":["scope:1"]},{"summary":"bad","category":"finding"},{"summary":"plain","evidence_ids":[]}]}`), nil)
	if err != nil || result.IsError {
		t.Fatalf("batch failed: %s %v", result.Flatten(), err)
	}
	var got struct {
		IDs    []int64           `json:"ids"`
		Errors map[string]string `json:"errors"`
	}
	if err := json.Unmarshal([]byte(result.Flatten()), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.IDs) != 3 || got.IDs[0] == 0 || got.IDs[1] != 0 || got.IDs[2] == 0 || got.Errors["1"] == "" {
		t.Fatalf("invalid batch result: %+v", got)
	}
	n, err := es.GetNode(got.IDs[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(n.Payload), `"scope:1"`) || !strings.Contains(string(n.Payload), `"scope_limit"`) {
		t.Fatalf("batch fields lost: %s", n.Payload)
	}
}
