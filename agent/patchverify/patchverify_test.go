package patchverify

import (
	"strings"
	"testing"
)

func TestPatchVerifyVerdicts(t *testing.T) {
	const before = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const after = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	pair := func(id, v, f string) Pair {
		return Pair{Observation{id, before, "record-before", v, after}, Observation{id, before, "record-after", f, after}}
	}
	s := Spec{
		Tag:             "patch",
		Vulnerable:      Pins{"vendor", "product", "1", "snapshot-a", "amd64", before, "unknown"},
		Fixed:           Pins{"vendor", "product", "2", "snapshot-b", "amd64", after, "upstream-fixed"},
		Preflight:       Preflight{"sample reader", "2.0", []string{"none"}, "linux/amd64", before, "preflight log", true},
		RootCause:       RootCause{FixCommit: "commit", File: "fixture.go", Function: "main"},
		Reachability:    Reachability{Check{"input log", true}, Check{"call log", true}, Check{"config log", true}},
		SafeToReproduce: true,
		SafeReason:      "operator-provided harmless evidence",
	}
	r := Regression{pair("diff", "effect", "no_effect"), pair("normal", "normal", "normal"), pair("deny", "denied", "denied"), "same environment", "isolation log"}

	for _, test := range []struct {
		name string
		edit func(*Spec, *Regression)
		want Verdict
	}{
		{"complete", func(*Spec, *Regression) {}, Verified},
		{"missing preflight", func(s *Spec, _ *Regression) { s.Preflight = Preflight{} }, Blocked},
		{"failed preflight", func(s *Spec, _ *Regression) { s.Preflight.Passed = false }, Blocked},
		{"other sample", func(s *Spec, _ *Regression) { s.Preflight.SampleSHA256 = after }, Blocked},
		{"no call evidence", func(s *Spec, _ *Regression) { s.Reachability.Call.EvidenceRef = "" }, Candidate},
		{"not configured", func(s *Spec, _ *Regression) { s.Reachability.Config.Reached = false }, Candidate},
		{"unsafe", func(s *Spec, _ *Regression) { s.SafeToReproduce = false }, Unverified},
		{"different differential input", func(_ *Spec, r *Regression) { r.Differential.Fixed.InputSHA256 = after }, Unverified},
		{"normal inequality", func(_ *Spec, r *Regression) { r.Normal.Fixed.ResultSHA256 = before }, Unverified},
		{"denied absent", func(_ *Spec, r *Regression) { r.Denied = Pair{} }, Unverified},
		{"environment absent", func(_ *Spec, r *Regression) { r.EnvironmentDiff = "" }, Unverified},
		{"missing fix build", func(s *Spec, _ *Regression) { s.Fixed.Build = "" }, Unverified},
		{"unknown backport label", func(s *Spec, _ *Regression) { s.Fixed.BackportState = "other" }, Unverified},
		{"no root cause", func(s *Spec, _ *Regression) { s.RootCause = RootCause{} }, Unverified},
	} {
		t.Run(test.name, func(t *testing.T) {
			spec, regression := s, r
			test.edit(&spec, &regression)
			plan, err := BuildPlan(spec)
			if err != nil {
				t.Fatal(err)
			}
			result := Evaluate(plan, regression)
			if result.Verdict != test.want {
				t.Fatalf("got %+v, want %s", result, test.want)
			}
			if !spec.SafeToReproduce && !strings.Contains(Report(result, plan, regression), unsafeReason) {
				t.Fatal("unsafe result must explicitly say no PoC was provided")
			}
		})
	}
	for _, tag := range []string{"patch", "audit", "rev", "firmware", "supply"} {
		if _, err := BuildPlan(Spec{Tag: tag}); err != nil {
			t.Errorf("%s: %v", tag, err)
		}
	}
	for _, tag := range []string{"", "web", "needs patch diff"} {
		if _, err := BuildPlan(Spec{Tag: tag}); err == nil {
			t.Errorf("accepted non-route %q", tag)
		}
	}
}
