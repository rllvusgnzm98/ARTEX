package agent

import (
	"reflect"
	"slices"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestCompactionDecisionGenerationFor(t *testing.T) {
	c := NewCompactor(nil, "")
	b := block{Members: []int64{11, 12}}
	sig := blockSignature(b, nil)
	matching := &db.Node{Payload: []byte(`{"signature":"` + sig + `","generation":3,"member_ids":{"facts":[11],"intents":[12]}}`)}
	changed := &db.Node{Payload: []byte(`{"signature":"old","generation":7,"member_ids":{"intents":[12,13]}}`)}
	disjoint := &db.Node{Payload: []byte(`{"signature":"unrelated","generation":20,"member_ids":{"facts":[99]}}`)}
	missingMembers := &db.Node{Payload: []byte(`{"signature":"current","generation":10}`)}
	badGeneration := &db.Node{Payload: []byte(`{"generation":"bad","member_ids":{"facts":[11]}}`)}

	for _, tt := range []struct {
		name   string
		active []*db.Node
		want   int
	}{
		{name: "no active digest", want: 1},
		{name: "matching digest", active: []*db.Node{matching}, want: 4},
		{name: "different signature and disjoint members", active: []*db.Node{disjoint}, want: 1},
		{name: "highest overlapping generation even with changed signature", active: []*db.Node{disjoint, changed, matching}, want: 8},
		{name: "missing member metadata", active: []*db.Node{missingMembers}, want: 1},
		{name: "invalid generation", active: []*db.Node{badGeneration}, want: 1},
		{name: "empty and malformed payloads", active: []*db.Node{{}, {Payload: []byte(`{`)}}, want: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := c.generationFor(b, tt.active); got != tt.want {
				t.Errorf("generationFor() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestCompactionDecisionDigestPayload(t *testing.T) {
	nodes := map[int64]*db.Node{
		11: {Kind: db.KindFact},
		12: {Kind: db.KindIntent},
		13: nil,
		14: {Kind: db.KindIntent},
	}
	for _, tt := range []struct {
		name                    string
		members, facts, intents []int64
	}{
		{
			name:    "partitions by kind and defaults missing nodes to facts",
			members: []int64{12, 11, 14, 13, 15},
			facts:   []int64{11, 13, 15}, intents: []int64{12, 14},
		},
		{
			name:    "preserves order within each kind and preserves duplicates",
			members: []int64{15, 14, 13, 12, 11, 14, 15},
			facts:   []int64{15, 13, 11, 15}, intents: []int64{14, 12, 14},
		},
		{name: "no members"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b := block{Members: tt.members, Anchors: []int64{22, 21}}
			got := digestPayload("压缩正文", b, nodes, 4, "sig-4")
			want := map[string]any{
				"body":       "压缩正文",
				"member_ids": map[string]any{"facts": tt.facts, "intents": tt.intents},
				"anchor_ids": []int64{22, 21},
				"generation": 4,
				"signature":  "sig-4",
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("digestPayload() = %#v, want %#v", got, want)
			}
		})
	}
}

func TestCompactionDecisionDigestMetadata(t *testing.T) {
	for _, tt := range []struct {
		name, payload, signature string
		generation               int
		members                  []int64
	}{
		{
			name:       "valid metadata",
			payload:    `{"signature":"sig","generation":4,"member_ids":{"intents":[7,5],"facts":[9,3,9]}}`,
			signature:  "sig",
			generation: 4,
			members:    []int64{9, 3, 9, 7, 5},
		},
		{name: "empty payload"},
		{name: "malformed JSON", payload: `{"signature":"sig","generation":4`},
		{name: "wrong field types", payload: `{"signature":42,"generation":"4","member_ids":[]}`},
		{
			name:       "valid fields survive unrelated type errors",
			payload:    `{"signature":42,"generation":4,"member_ids":{"facts":"bad","intents":[7]}}`,
			generation: 4,
			members:    []int64{7},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			n := &db.Node{Payload: []byte(tt.payload)}
			signature, generation := digestSigGen(n)
			if signature != tt.signature || generation != tt.generation {
				t.Errorf("digestSigGen() = (%q, %d), want (%q, %d)", signature, generation, tt.signature, tt.generation)
			}
			if got := digestMemberIDs(n); !slices.Equal(got, tt.members) {
				t.Errorf("digestMemberIDs() = %v, want %v", got, tt.members)
			}
		})
	}
}

func TestCompactionDecisionStampOps(t *testing.T) {
	ops := []stampOp{
		{ID: 1, Set: true, Round: 17},
		{ID: 2, Round: 18},
		{ID: 3, Set: true, Round: 0},
		{ID: 4},
	}
	wantOps := []db.StampOp{
		{ID: 1, Set: true, Round: 17},
		{ID: 2, Round: 18},
		{ID: 3, Set: true, Round: 0},
		{ID: 4},
	}
	if got := toDBStampOps(ops); !slices.Equal(got, wantOps) {
		t.Errorf("toDBStampOps() = %+v, want %+v", got, wantOps)
	}

	stamps := map[int64]*int64{1: nil, 2: ptr(8), 5: ptr(9)}
	applyStampsInPlace(stamps, ops)
	wantStamps := map[int64]*int64{1: ptr(17), 2: nil, 3: ptr(0), 4: nil, 5: ptr(9)}
	if !reflect.DeepEqual(stamps, wantStamps) {
		t.Errorf("applyStampsInPlace() stamps = %#v, want %#v", stamps, wantStamps)
	}

	for _, empty := range [][]stampOp{nil, {}} {
		if got := toDBStampOps(empty); len(got) != 0 {
			t.Errorf("toDBStampOps(%#v) = %+v, want no operations", empty, got)
		}
		applyStampsInPlace(nil, empty)
		applyStampsInPlace(stamps, empty)
		if !reflect.DeepEqual(stamps, wantStamps) {
			t.Errorf("empty operations changed stamp map: %#v", stamps)
		}
	}
}

func TestCompactionDecisionTryStartAndFinish(t *testing.T) {
	c := NewCompactor(nil, "")
	c.cooldown = 0
	const first, second = 101, 202
	const contenders = 16
	start := make(chan struct{})
	results := make(chan bool, contenders)
	for range contenders {
		go func() {
			<-start
			results <- c.tryStart(first)
		}()
	}
	close(start)
	started := 0
	for range contenders {
		if <-results {
			started++
		}
	}
	if started != 1 {
		t.Fatalf("%d attempts started for experiment %d, want 1", started, first)
	}
	if !c.tryStart(second) {
		t.Fatalf("experiment %d could not start while %d was running", second, first)
	}
	t.Cleanup(func() { c.finish(second) })
	c.finish(first)
	if c.tryStart(second) {
		t.Errorf("finishing experiment %d released the lock for %d", first, second)
	}
	if !c.tryStart(first) {
		t.Fatalf("experiment %d could not restart after finish", first)
	}
	c.finish(first)
}
