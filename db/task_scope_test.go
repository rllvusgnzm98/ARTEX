package db

import "testing"

// TestStripHostPort covers the ip:port / [ipv6]:port stripping used by the
// ip/cidr scope path so a target like "10.0.188.136:3000" no longer 404s.
func TestStripHostPort(t *testing.T) {
	cases := []struct{ in, want string }{
		{"10.0.188.136:3000", "10.0.188.136"},       // the reported IP case
		{"10.0.188.136", "10.0.188.136"},            // bare IPv4 unchanged
		{"[2001:db8::1]:8080", "2001:db8::1"},       // bracketed IPv6 + port
		{"2001:db8::1", "2001:db8::1"},              // bare IPv6 unchanged (has colons)
		{" 1.2.3.4:80 ", "1.2.3.4"},                 // trims surrounding space
		{"example.com:443", "example.com"},          // domain + port → bare host
		{"api.example.com:8080", "api.example.com"}, // subdomain + port
		{"example.com", "example.com"},              // bare domain unchanged
	}
	for _, c := range cases {
		if got := stripHostPort(c.in); got != c.want {
			t.Errorf("stripHostPort(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCovTargetCTEExcludesExcludedScopes(t *testing.T) {
	dsn, _, err := DSN()
	if err != nil {
		t.Skipf("no database config (%v)", err)
	}
	d, err := Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()

	task, err := d.CreateTask("cov exclude fixture", "scope exclusion sql test", nil, 0, 0)
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	defer func() { _ = d.DeleteTask(task.ID) }()
	as := d.Assets()

	_, _ = d.Exec(`DELETE FROM assets WHERE domain IN ('api.cov-ex.test','blog.cov-ex.test','cdn.sub.cov-ex.test','sub.cov-ex.test','cov-ex.test')`)
	defer func() {
		_, _ = d.Exec(`DELETE FROM assets WHERE domain IN ('api.cov-ex.test','blog.cov-ex.test','cdn.sub.cov-ex.test','sub.cov-ex.test','cov-ex.test')`)
	}()

	if _, err := as.UpsertSubdomain(UpsertSubdomainReq{Domain: "api.cov-ex.test", TaskID: task.ID}); err != nil {
		t.Fatalf("UpsertSubdomain api: %v", err)
	}
	if _, err := as.UpsertSubdomain(UpsertSubdomainReq{Domain: "blog.cov-ex.test", TaskID: task.ID}); err != nil {
		t.Fatalf("UpsertSubdomain blog: %v", err)
	}
	if _, err := as.UpsertSubdomain(UpsertSubdomainReq{Domain: "cdn.sub.cov-ex.test", TaskID: task.ID}); err != nil {
		t.Fatalf("UpsertSubdomain cdn.sub: %v", err)
	}
	if _, err := as.AddAgentScope(task.ID, "root_domain", "cov-ex.test", "in-scope root", "manual"); err != nil {
		t.Fatalf("AddAgentScope root_domain: %v", err)
	}
	if _, err := as.AddAgentScope(task.ID, "exclude_subdomain", "blog.cov-ex.test", "out-of-scope exact", "manual"); err != nil {
		t.Fatalf("AddAgentScope exclude_subdomain: %v", err)
	}
	if _, err := as.AddAgentScope(task.ID, "exclude_root_domain", "sub.cov-ex.test", "out-of-scope subtree", "manual"); err != nil {
		t.Fatalf("AddAgentScope exclude_root_domain: %v", err)
	}

	cov, err := as.TaskCoverage(task.ID, task.ExplorationID)
	if err != nil {
		t.Fatalf("TaskCoverage: %v", err)
	}
	// Should include root_domain cov-ex.test + subdomain api.cov-ex.test (blog + cdn.sub excluded = 2 assets total, 0 tested).
	untested, total, err := as.ListUntestedAssets(task.ID, task.ExplorationID, "", 50, 0)
	if err != nil {
		t.Fatalf("ListUntestedAssets: %v", err)
	}
	if total != cov.Denominator {
		t.Fatalf("denominator=%d untested total=%d", cov.Denominator, total)
	}
	labels := map[string]bool{}
	for _, u := range untested {
		labels[u.Label] = true
	}
	if !labels["api.cov-ex.test"] {
		t.Errorf("expected api.cov-ex.test in coverage target, got %+v", untested)
	}
	if labels["blog.cov-ex.test"] || labels["cdn.sub.cov-ex.test"] {
		t.Errorf("excluded assets leaked into coverage denominator: %+v", untested)
	}

	graph, err := as.BuildCoverageGraph(task.ID, task.ExplorationID)
	if err != nil {
		t.Fatalf("BuildCoverageGraph: %v", err)
	}
	graphLabels := map[string]bool{}
	for _, n := range graph.Nodes {
		if n.InScope {
			graphLabels[n.Label] = true
		}
	}
	if !graphLabels["api.cov-ex.test"] {
		t.Errorf("expected api.cov-ex.test in BuildCoverageGraph InScope nodes, got %+v", graph.Nodes)
	}
	if graphLabels["blog.cov-ex.test"] || graphLabels["cdn.sub.cov-ex.test"] {
		t.Errorf("excluded assets leaked into BuildCoverageGraph InScope nodes: %+v", graph.Nodes)
	}
}

func TestEvaluateAutoScopeContainment(t *testing.T) {
	// 1. Zero existing scope rules → backwards-compatible autoScopeAllow.
	dec, _, _ := evaluateAutoScope(nil, autoScopeCandidate(1, "ip", "", "", "192.168.52.30"))
	if dec != autoScopeAllow {
		t.Fatalf("empty existing scope should allow auto-scope, got %v", dec)
	}

	// 2. Only untrusted auto/agent rules → backwards-compatible autoScopeAllow.
	untrustedOnly := []TaskScope{{Kind: "ip", Net: "10.0.0.1/32", Source: "auto"}}
	dec, _, _ = evaluateAutoScope(untrustedOnly, autoScopeCandidate(1, "ip", "", "", "10.0.0.2"))
	if dec != autoScopeAllow {
		t.Fatalf("untrusted-only scope should allow auto-scope, got %v", dec)
	}

	// 3. Trusted manual/seed scope present: in-scope allowed, out-of-scope routed to pending_scope.
	trusted := []TaskScope{
		{Kind: "root_domain", Domain: "acme.test", Source: "manual"},
		{Kind: "subdomain", Domain: "only.partner.test", Source: "seed"},
		{Kind: "ip", Net: "192.168.111.20/32", Source: "seed"},
		{Kind: "exclude_subdomain", Domain: "blog.acme.test", Source: "manual"},
		{Kind: "exclude_cidr", Net: "10.99.0.0/16", Source: "manual"},
	}

	cases := []struct {
		name      string
		cand      TaskScope
		wantDec   autoScopeDecision
		wantKind  string
		wantValue string
	}{
		{"in-scope subdomain under root", autoScopeCandidate(1, "subdomain", "api.acme.test", "", ""), autoScopeAllow, "", ""},
		{"in-scope exact subdomain", autoScopeCandidate(1, "subdomain", "only.partner.test", "", ""), autoScopeAllow, "", ""},
		{"in-scope ip", autoScopeCandidate(1, "ip", "", "", "192.168.111.20"), autoScopeAllow, "", ""},
		{"in-scope IP-literal HTTP service", autoScopeCandidate(1, "service", "", "http://192.168.111.20:8080/login", ""), autoScopeAllow, "", ""},
		{"out-of-scope subdomain routed to pending", autoScopeCandidate(1, "subdomain", "evil.other.test", "", ""), autoScopePending, "subdomain", "evil.other.test"},
		{"broader root_domain must not match exact subdomain", autoScopeCandidate(1, "root_domain", "partner.test", "", ""), autoScopePending, "root_domain", "partner.test"},
		{"out-of-scope IP routed to pending", autoScopeCandidate(1, "ip", "", "", "192.168.52.30"), autoScopePending, "ip", "192.168.52.30"},
		{"out-of-scope IP-literal service routed to pending", autoScopeCandidate(1, "service", "", "http://192.168.52.30:8080/", ""), autoScopePending, "ip", "192.168.52.30"},
		{"explicitly excluded subdomain skipped", autoScopeCandidate(1, "subdomain", "blog.acme.test", "", ""), autoScopeSkip, "", ""},
		{"explicitly excluded CIDR IP skipped", autoScopeCandidate(1, "ip", "", "", "10.99.1.5"), autoScopeSkip, "", ""},
		{"loopback IP skipped when trusted scope exists", autoScopeCandidate(1, "ip", "", "", "127.0.0.1"), autoScopeSkip, "", ""},
	}
	for _, tc := range cases {
		gotDec, gotKind, gotVal := evaluateAutoScope(trusted, tc.cand)
		if gotDec != tc.wantDec || gotKind != tc.wantKind || gotVal != tc.wantValue {
			t.Errorf("%s: got (%v, %q, %q), want (%v, %q, %q)",
				tc.name, gotDec, gotKind, gotVal, tc.wantDec, tc.wantKind, tc.wantValue)
		}
	}
}

func TestTaskScopeSeedSourceAndAutoScopeContainmentDB(t *testing.T) {
	dsn, _, err := DSN()
	if err != nil {
		t.Skipf("no database config (%v)", err)
	}
	d, err := Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()

	task, err := d.CreateTask("seed and auto containment", "scope db test", nil, 0, 0)
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	defer func() {
		_, _ = d.Exec(`DELETE FROM pending_scope WHERE task_id=$1`, task.ID)
		_ = d.DeleteTask(task.ID)
	}()
	as := d.Assets()

	// Seed source is accepted by task_scope source check constraint.
	if _, err := as.AddAgentScope(task.ID, "ip", "192.168.111.20", "round-0 seed target", "seed"); err != nil {
		t.Fatalf("AddAgentScope(seed): %v", err)
	}

	// Out-of-scope AddAutoScope must NOT expand task_scope and MUST write pending_scope.
	if err := as.AddAutoScope(task.ID, "ip", "", "", "192.168.52.30"); err != nil {
		t.Fatalf("AddAutoScope(out-of-scope ip): %v", err)
	}
	if err := as.AddAutoScope(task.ID, "subdomain", "lateral.other.test", "", ""); err != nil {
		t.Fatalf("AddAutoScope(out-of-scope subdomain): %v", err)
	}

	scopes, err := as.ListTaskScope(task.ID)
	if err != nil {
		t.Fatalf("ListTaskScope: %v", err)
	}
	if len(scopes) != 1 || scopes[0].Source != "seed" || scopes[0].Net != "192.168.111.20/32" {
		t.Fatalf("task_scope must keep only the seed row, got %+v", scopes)
	}

	pending, err := as.ListPendingScope(task.ID, false)
	if err != nil {
		t.Fatalf("ListPendingScope: %v", err)
	}
	gotPending := map[string]bool{}
	for _, p := range pending {
		gotPending[p.Kind+":"+p.Value] = true
	}
	for _, want := range []string{"ip:192.168.52.30", "subdomain:lateral.other.test"} {
		if !gotPending[want] {
			t.Errorf("pending_scope missing %s; got %+v", want, pending)
		}
	}
}
