// Package patchverify assesses supplied patch regression evidence without
// executing samples or inputs.
package patchverify

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

type Verdict string

const (
	Verified   Verdict = "verified"
	Candidate  Verdict = "candidate"
	Blocked    Verdict = "blocked"
	Unverified Verdict = "unverified"
)

func AllowedTag(tag string) bool {
	switch tag {
	case "patch", "audit", "rev", "firmware", "supply":
		return true
	}
	return false
}

type Pins struct {
	Vendor        string `json:"vendor"`
	Product       string `json:"product"`
	Version       string `json:"version"`
	Build         string `json:"build"`
	Architecture  string `json:"architecture"`
	SampleSHA256  string `json:"sample_sha256"`
	BackportState string `json:"backport_state"`
}

type Preflight struct {
	Tool         string   `json:"tool"`
	Version      string   `json:"version"`
	Dependencies []string `json:"dependencies"`
	Platform     string   `json:"platform"`
	SampleSHA256 string   `json:"sample_sha256"`
	EvidenceRef  string   `json:"evidence_ref"`
	Passed       bool     `json:"passed"`
}

type RootCause struct {
	Advisory  string `json:"advisory"`
	FixCommit string `json:"fix_commit"`
	Function  string `json:"function"`
	File      string `json:"file"`
}

type Check struct {
	EvidenceRef string `json:"evidence_ref"`
	Reached     bool   `json:"reached"`
}

type Reachability struct {
	Input  Check `json:"input"`
	Call   Check `json:"call"`
	Config Check `json:"config"`
}

type Observation struct {
	InputID      string `json:"input_id"`
	InputSHA256  string `json:"input_sha256"`
	EvidenceRef  string `json:"evidence_ref"`
	Outcome      string `json:"outcome"`
	ResultSHA256 string `json:"result_sha256,omitempty"`
}

type Pair struct {
	Vulnerable Observation `json:"vulnerable"`
	Fixed      Observation `json:"fixed"`
}

type Regression struct {
	Differential    Pair   `json:"differential"`
	Normal          Pair   `json:"normal"`
	Denied          Pair   `json:"denied"`
	EnvironmentDiff string `json:"environment_diff"`
	IsolationRef    string `json:"isolation_ref"`
}

type Spec struct {
	Tag             string       `json:"-"`
	Vulnerable      Pins         `json:"vulnerable"`
	Fixed           Pins         `json:"fixed"`
	Preflight       Preflight    `json:"preflight"`
	RootCause       RootCause    `json:"root_cause"`
	Reachability    Reachability `json:"reachability"`
	SafeToReproduce bool         `json:"safe_to_reproduce"`
	SafeReason      string       `json:"safe_reason"`
}

type Plan struct{ spec Spec }

type Result struct {
	Verdict Verdict `json:"verdict"`
	Reason  string  `json:"reason"`
}

const unsafeReason = "cannot be safely reproduced, not verified, no PoC provided"

func BuildPlan(spec Spec) (Plan, error) {
	spec.Tag = strings.ToLower(strings.TrimSpace(spec.Tag))
	if !AllowedTag(spec.Tag) {
		return Plan{}, errors.New("patch verification requires an explicit patch/audit/rev/firmware/supply tag")
	}
	return Plan{spec: spec}, nil
}

func present(values ...string) bool {
	for _, v := range values {
		if strings.TrimSpace(v) == "" {
			return false
		}
	}
	return true
}

func validHash(v string) bool {
	_, err := hex.DecodeString(v)
	return len(v) == 64 && err == nil
}

func (p Pins) complete() bool {
	switch p.BackportState {
	case "upstream-fixed", "backported", "unknown":
		return validHash(p.SampleSHA256) && present(p.Vendor, p.Product, p.Version, p.Build, p.Architecture)
	}
	return false
}

func (f Preflight) proves(sample string) bool {
	return f.Passed && len(f.Dependencies) > 0 && present(f.Dependencies...) &&
		present(f.Tool, f.Version, f.Platform, f.EvidenceRef) &&
		validHash(sample) && strings.EqualFold(f.SampleSHA256, sample)
}

func (r Reachability) proven() bool {
	for _, c := range []Check{r.Input, r.Call, r.Config} {
		if !c.Reached || !present(c.EvidenceRef) {
			return false
		}
	}
	return true
}

func (p Pair) shows(before, after string) bool {
	v, f := p.Vulnerable, p.Fixed
	return present(v.InputID, v.EvidenceRef, f.EvidenceRef) && v.InputID == f.InputID &&
		validHash(v.InputSHA256) && strings.EqualFold(v.InputSHA256, f.InputSHA256) &&
		v.Outcome == before && f.Outcome == after
}

func Evaluate(p Plan, r Regression) Result {
	s := p.spec
	switch {
	case !AllowedTag(s.Tag):
		return Result{Blocked, "explicit patch verification tag missing"}
	case !s.Preflight.proves(s.Vulnerable.SampleSHA256):
		return Result{Blocked, "toolchain unproven on the declared sample"}
	case !s.SafeToReproduce:
		return Result{Unverified, unsafeReason}
	case !s.Reachability.proven():
		return Result{Candidate, "input/call/config reachability unproven; retain as a candidate"}
	case !s.Vulnerable.complete() || !s.Fixed.complete() || strings.EqualFold(s.Vulnerable.SampleSHA256, s.Fixed.SampleSHA256):
		return Result{Unverified, "distinct and complete vulnerable/fixed build pins required"}
	case s.Vulnerable.Vendor != s.Fixed.Vendor || s.Vulnerable.Product != s.Fixed.Product || s.Vulnerable.Architecture != s.Fixed.Architecture:
		return Result{Unverified, "builds must identify the same vendor, product and architecture"}
	case !present(s.RootCause.Function, s.RootCause.File) || !present(s.RootCause.Advisory) && !present(s.RootCause.FixCommit):
		return Result{Unverified, "root cause metadata incomplete"}
	case !present(s.SafeReason, r.EnvironmentDiff, r.IsolationRef):
		return Result{Unverified, "safe reproduction reason, isolation reference and environment diff required"}
	case !r.Differential.shows("effect", "no_effect") || !r.Normal.shows("normal", "normal") || !r.Denied.shows("denied", "denied"):
		return Result{Unverified, "same-input differential, normal and denied controls required"}
	case !validHash(r.Normal.Vulnerable.ResultSHA256) || !strings.EqualFold(r.Normal.Vulnerable.ResultSHA256, r.Normal.Fixed.ResultSHA256):
		return Result{Unverified, "normal control result hashes must match"}
	default:
		return Result{Verified, "supplied evidence satisfies the reachability and regression checks"}
	}
}

// Report is a reference-only record; it does not contain or replay input payloads.
func Report(result Result, p Plan, regression Regression) string {
	s := p.spec
	var b strings.Builder
	fmt.Fprintf(&b, "# Patch reachability and regression evidence\n\nVerdict: %s — %s\n\nExplicit tag: %q\n", result.Verdict, result.Reason, s.Tag)
	for _, build := range []struct {
		label string
		pins  Pins
	}{{"Vulnerable", s.Vulnerable}, {"Fixed", s.Fixed}} {
		v := build.pins
		fmt.Fprintf(&b, "- %s: vendor=%q product=%q version=%q build=%q architecture=%q sample SHA-256=%q backport=%q\n", build.label, v.Vendor, v.Product, v.Version, v.Build, v.Architecture, v.SampleSHA256, v.BackportState)
	}
	f := s.Preflight
	fmt.Fprintf(&b, "- Toolchain: tool=%q version=%q dependencies=%q platform=%q sample SHA-256=%q evidence=%q passed=%t\n", f.Tool, f.Version, f.Dependencies, f.Platform, f.SampleSHA256, f.EvidenceRef, f.Passed)
	fmt.Fprintf(&b, "- Root cause: advisory=%q fix=%q file=%q function=%q\n", s.RootCause.Advisory, s.RootCause.FixCommit, s.RootCause.File, s.RootCause.Function)
	for _, item := range []struct {
		label string
		check Check
	}{{"Input", s.Reachability.Input}, {"Call", s.Reachability.Call}, {"Config", s.Reachability.Config}} {
		fmt.Fprintf(&b, "- %s reached=%t evidence=%q\n", item.label, item.check.Reached, item.check.EvidenceRef)
	}
	for _, item := range []struct {
		label string
		pair  Pair
	}{{"Differential", regression.Differential}, {"Normal", regression.Normal}, {"Denied", regression.Denied}} {
		v, f := item.pair.Vulnerable, item.pair.Fixed
		fmt.Fprintf(&b, "- %s: vulnerable input=%q SHA-256=%q outcome=%q result SHA-256=%q evidence=%q; fixed input=%q SHA-256=%q outcome=%q result SHA-256=%q evidence=%q\n", item.label, v.InputID, v.InputSHA256, v.Outcome, v.ResultSHA256, v.EvidenceRef, f.InputID, f.InputSHA256, f.Outcome, f.ResultSHA256, f.EvidenceRef)
	}
	fmt.Fprintf(&b, "- Environment diff: %q\n- Isolation evidence: %q\n- Safe to reproduce: %t; reason=%q\n", regression.EnvironmentDiff, regression.IsolationRef, s.SafeToReproduce, s.SafeReason)
	if !s.SafeToReproduce && result.Reason != unsafeReason {
		fmt.Fprintf(&b, "- %s\n", unsafeReason)
	}
	b.WriteString("\nAssessment of supplied metadata only; no sample or input was executed by this tool.\n")
	return b.String()
}
