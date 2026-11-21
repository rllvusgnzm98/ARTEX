package dualverify

import (
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func testSpec() Spec {
	return Spec{
		Target:  Request{Method: "GET", URL: "https://example.test/private/{{RESOURCE_ID}}", Headers: map[string]string{"Authorization": "Bearer {{AUTH}}", "Accept": "application/json"}},
		Plant:   Request{Method: "PATCH", URL: "https://example.test/private/{{RESOURCE_ID}}", Headers: map[string]string{"Authorization": "Bearer {{AUTH}}"}, Body: `{"note":"{{MARKER}}"}`},
		Cleanup: Request{Method: "PATCH", URL: "https://example.test/private/{{RESOURCE_ID}}", Headers: map[string]string{"Authorization": "Bearer {{AUTH}}"}, Body: `{"note":""}`},
		Marker:  "artex-mark-private", ResourceID: "resource-a", Read: true,
	}
}

func testPlan(t *testing.T, s Spec) Plan {
	t.Helper()
	p, err := BuildPlan(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func baseline(p Plan) []Observation {
	o := make([]Observation, 0, len(p.Steps))
	for _, s := range p.Steps {
		status, marker := 403, false
		if s.Actor == "A" {
			status = 200
			marker = s.Action == "read"
		}
		o = append(o, Observation{StepID: s.ID, Status: status, MarkerSeen: marker, Scope: ScopeIn})
	}
	return o
}

func change(o []Observation, id string, f func(*Observation)) {
	for i := range o {
		if o[i].StepID == id {
			f(&o[i])
			return
		}
	}
}

func TestNewMarker(t *testing.T) {
	a, err := NewMarker()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewMarker()
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^artex-mark-[0-9a-f]{32}$`).MatchString(a) || a == b {
		t.Fatalf("invalid/randomness collision: %q %q", a, b)
	}
}

func TestPlanMatrix(t *testing.T) {
	s := testSpec()
	s.Write = true
	s.SessionToken = true
	s.TenantRole = true
	p := testPlan(t, s)
	wantIDs := []string{"plant", "public", "owner", "probe", "B_expired", "B_revoked", "B_wrong_issuer", "tenant", "cleanup"}
	var ids []string
	for _, step := range p.Steps {
		ids = append(ids, step.ID)
		if strings.Contains(step.Request.URL, "{{RESOURCE_ID}}") || !strings.Contains(step.Request.URL, "resource-a") {
			t.Fatal(step)
		}
		if step.Actor == "public" {
			if _, ok := step.Request.Headers["Authorization"]; ok {
				t.Fatal("public has auth")
			}
		} else if step.Request.Headers["Authorization"] != "Bearer "+actorTokens[step.Actor] {
			t.Fatal(step)
		}
		if step.ID == "plant" && !strings.Contains(step.Request.Body, s.Marker) {
			t.Fatal(step)
		}
		if step.ID == "owner" && (!step.RequireMarker || step.Expect != Allow) {
			t.Fatal(step)
		}
		if strings.HasPrefix(step.Actor, "B_") && step.Expect != Deny {
			t.Fatal(step)
		}
	}
	if !reflect.DeepEqual(ids, wantIDs) {
		t.Fatalf("%v", ids)
	}
	if p.WriteNotAttempted {
		t.Fatal("write suppressed")
	}
	// The plan owns its maps, independent of the caller and of other steps.
	s.Target.Headers["Accept"] = "changed"
	p.Steps[1].Request.Headers["Accept"] = "public-only"
	if p.Steps[2].Request.Headers["Accept"] != "application/json" {
		t.Fatal("aliased maps")
	}
}

func TestFootprint(t *testing.T) {
	for _, tc := range []struct {
		name                           string
		write, min, dirty, allow, want bool
	}{
		{"disabled", false, false, false, false, false},
		{"enabled", true, false, false, false, true},
		{"min", true, true, false, false, false},
		{"dirty", true, false, true, false, false},
		{"both", true, true, true, false, false},
		{"min authorized", true, true, false, true, true},
		{"dirty authorized", true, false, true, true, true},
		{"both authorized", true, true, true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testSpec()
			s.Write = tc.write
			s.Footprint = Footprint{tc.min, tc.dirty}
			s.AllowWrite = tc.allow
			p := testPlan(t, s)
			count := 0
			for _, step := range p.Steps {
				if step.Action == "write" {
					count++
				}
			}
			want := 0
			if tc.want {
				want = 2
			}
			if count != want || p.WriteNotAttempted == tc.want {
				t.Fatal(p)
			}
			if !tc.want && !strings.Contains(Report(Result{}, p), "write not attempted") {
				t.Fatal("missing note")
			}
		})
	}
}

func TestBuildErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*Spec)
	}{
		{"no families", func(s *Spec) { s.Read = false }},
		{"empty marker", func(s *Spec) { s.Marker = "" }},
		{"empty resource", func(s *Spec) { s.ResourceID = "" }},
		{"empty request", func(s *Spec) { s.Target = Request{} }},
		{"unsafe read", func(s *Spec) { s.Target.Method = "POST" }},
		{"literal auth", func(s *Spec) { s.Target.Headers["Authorization"] = "Bearer real-secret" }},
		{"literal cookie", func(s *Spec) { s.Target.Headers["Cookie"] = "session=real-secret" }},
		{"literal api key", func(s *Spec) { s.Target.Headers["X-API-Key"] = "real-secret" }},
		{"missing plant", func(s *Spec) { s.Write = true; s.Plant = Request{} }},
		{"missing cleanup", func(s *Spec) { s.Write = true; s.Cleanup = Request{} }},
		{"unsafe plant", func(s *Spec) { s.Write = true; s.Plant.Method = "GET" }},
		{"no planted marker", func(s *Spec) { s.Write = true; s.Plant.Body = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testSpec()
			tc.edit(&s)
			if _, err := BuildPlan(s); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	for _, family := range []string{"write", "session", "tenant"} {
		t.Run(family+" implicit controls", func(t *testing.T) {
			s := testSpec()
			s.Read = false
			switch family {
			case "write":
				s.Write = true
			case "session":
				s.SessionToken = true
			case "tenant":
				s.TenantRole = true
			}
			p := testPlan(t, s)
			if len(p.Steps) < 3 {
				t.Fatal(p)
			}
		})
	}
}

func TestDecisionTable(t *testing.T) {
	for _, tc := range []struct {
		name    string
		edit    func(*Observation)
		id      string
		verdict Verdict
	}{
		{"normal", func(o *Observation) {}, "probe", ControlsHold},
		{"B reads marker", func(o *Observation) { o.Status = 200; o.MarkerSeen = true }, "probe", Verified},
		{"B allowed without marker", func(o *Observation) { o.Status = 200 }, "probe", ControlsHold},
		{"public data", func(o *Observation) { o.Status = 200; o.MarkerSeen = true }, "public", FalsePositive},
		{"A absent marker", func(o *Observation) { o.MarkerSeen = false }, "owner", Inconclusive},
		{"A denied", func(o *Observation) { o.Status = 403 }, "owner", Inconclusive},
		{"B out flag", func(o *Observation) { o.OutOfScope = true }, "probe", Inconclusive},
		{"B out scope", func(o *Observation) { o.Scope = ScopeOut }, "probe", Inconclusive},
		{"B empty scope", func(o *Observation) { o.Scope = ScopeEmpty }, "probe", Inconclusive},
		{"B unset scope", func(o *Observation) { o.Scope = "" }, "probe", Inconclusive},
		{"B bypass", func(o *Observation) { o.ProxyBypass = true }, "probe", Inconclusive},
		{"B skipped", func(o *Observation) { o.NotExecuted = true }, "probe", Inconclusive},
		{"B ambiguous", func(o *Observation) { o.Status = 302 }, "probe", Inconclusive},
		{"B contradictory", func(o *Observation) { o.MarkerSeen = true }, "probe", Inconclusive},
		{"public bypass", func(o *Observation) { o.ProxyBypass = true }, "public", Inconclusive},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := testPlan(t, testSpec())
			o := baseline(p)
			change(o, tc.id, tc.edit)
			r, err := Evaluate(p, o)
			if err != nil || r.Verdict != tc.verdict || r.Reason == "" {
				t.Fatalf("%+v %v", r, err)
			}
		})
	}
}

func TestMissingAndUntrustworthyControls(t *testing.T) {
	p := testPlan(t, testSpec())
	for _, id := range []string{"public", "owner", "probe"} {
		t.Run(id, func(t *testing.T) {
			o := baseline(p)
			change(o, "probe", func(o *Observation) { o.Status = 200; o.MarkerSeen = true })
			var filtered []Observation
			for _, v := range o {
				if v.StepID != id {
					filtered = append(filtered, v)
				}
			}
			r, err := Evaluate(p, filtered)
			if err != nil || r.Verdict != Inconclusive {
				t.Fatalf("%+v %v", r, err)
			}
		})
	}
	r, err := Evaluate(p, nil)
	if err != nil || r.Verdict != Inconclusive {
		t.Fatalf("%+v %v", r, err)
	}
	for _, id := range []string{"owner", "probe"} {
		for _, flag := range []string{"scope", "bypass", "skip"} {
			t.Run(id+flag, func(t *testing.T) {
				o := baseline(p)
				change(o, "probe", func(o *Observation) { o.Status = 200; o.MarkerSeen = true })
				change(o, id, func(o *Observation) {
					switch flag {
					case "scope":
						o.Scope = ScopeOut
					case "bypass":
						o.ProxyBypass = true
					case "skip":
						o.NotExecuted = true
					}
				})
				r, err := Evaluate(p, o)
				if err != nil || r.Verdict != Inconclusive {
					t.Fatalf("%+v %v", r, err)
				}
			})
		}
	}
}

func TestTokensAndPublicPrecedence(t *testing.T) {
	s := testSpec()
	s.SessionToken = true
	p := testPlan(t, s)
	for _, actor := range []string{"none", "B_expired", "B_revoked", "B_wrong_issuer"} {
		t.Run(actor, func(t *testing.T) {
			o := baseline(p)
			change(o, actor, func(o *Observation) { o.Status = 200 })
			r, err := Evaluate(p, o)
			if err != nil || r.Verdict != ControlsHold {
				t.Fatalf("%+v %v", r, err)
			}
			want := 1
			if actor == "none" {
				want = 0
			}
			if len(r.TokenDefects) != want {
				t.Fatal(r)
			}
			if want == 1 && (r.TokenDefects[0].Actor != actor || r.TokenDefects[0].Verdict != Verified) {
				t.Fatal(r)
			}
		})
	}
	o := baseline(p)
	for i := range o {
		o[i].Status = 200
		o[i].MarkerSeen = true
	}
	r, err := Evaluate(p, o)
	if err != nil || r.Verdict != FalsePositive || len(r.TokenDefects) != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	for _, flag := range []string{"scope", "bypass", "skip", "ambiguous"} {
		t.Run(flag, func(t *testing.T) {
			o := baseline(p)
			change(o, "B_expired", func(o *Observation) {
				o.Status = 200
				switch flag {
				case "scope":
					o.Scope = ScopeEmpty
				case "bypass":
					o.ProxyBypass = true
				case "skip":
					o.NotExecuted = true
				case "ambiguous":
					o.Status = 500
				}
			})
			r, err := Evaluate(p, o)
			if err != nil || len(r.TokenDefects) != 0 {
				t.Fatalf("%+v %v", r, err)
			}
		})
	}
}

func TestEvaluationErrors(t *testing.T) {
	p := testPlan(t, testSpec())
	for _, o := range [][]Observation{{{StepID: "unknown"}}, {{StepID: "probe"}, {StepID: "probe"}}} {
		if _, err := Evaluate(p, o); err == nil {
			t.Fatal("expected error")
		}
	}
	for _, bad := range []Plan{{}, {Steps: []Step{{ID: ""}}}, {Steps: []Step{{ID: "public"}, {ID: "public"}}}} {
		if _, err := Evaluate(bad, nil); err == nil {
			t.Fatal("expected error")
		}
	}
}

func TestReport(t *testing.T) {
	s := testSpec()
	s.Write = true
	s.SessionToken = true
	p := testPlan(t, s)
	o := baseline(p)
	change(o, "cleanup", func(o *Observation) { o.NotExecuted = true })
	change(o, "B_expired", func(o *Observation) { o.Status = 200 })
	change(o, "B_revoked", func(o *Observation) { o.ProxyBypass = true })
	change(o, "B_wrong_issuer", func(o *Observation) { o.Scope = ScopeEmpty })
	r, err := Evaluate(p, o)
	if err != nil {
		t.Fatal(err)
	}
	report := Report(r, p)
	for _, want := range []string{string(r.Verdict), p.Marker, "控制对照矩阵", "{{A_AUTH}}", "{{B_AUTH}}", "{{B_EXPIRED}}", "{{B_REVOKED}}", "{{B_WRONG_ISSUER}}", "cleanup：成功响应=false", "plant：成功响应=true", "未执行", "empty-scope", "范围：in", "proxy-bypass=true", "明确未验证", "持久化/清理结果未独立验证"} {
		if !strings.Contains(report, want) {
			t.Errorf("missing %q", want)
		}
	}
	secret := "real-credential-never-passed-to-package"
	if strings.Contains(report, secret) || strings.Contains(report, "{{AUTH}}") || strings.Contains(report, "{{MARKER}}") {
		t.Fatal("unsafe/unresolved report")
	}
	if Report(r, p) != report {
		t.Fatal("nondeterministic report")
	}
	change(o, "cleanup", func(o *Observation) { o.NotExecuted = false })
	r, err = Evaluate(p, o)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(Report(r, p), "cleanup：成功响应=true") {
		t.Fatal("cleanup status absent")
	}
}
