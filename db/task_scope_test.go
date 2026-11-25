package db

import "testing"

// TestStripHostPort covers the ip:port / [ipv6]:port stripping used by the
// ip/cidr scope path so a target like "10.0.188.136:3000" no longer 404s.
func TestStripHostPort(t *testing.T) {
	cases := []struct{ in, want string }{
		{"10.0.188.136:3000", "10.0.188.136"},          // the reported IP case
		{"10.0.188.136", "10.0.188.136"},               // bare IPv4 unchanged
		{"[2001:db8::1]:8080", "2001:db8::1"},          // bracketed IPv6 + port
		{"2001:db8::1", "2001:db8::1"},                 // bare IPv6 unchanged (has colons)
		{" 1.2.3.4:80 ", "1.2.3.4"},                    // trims surrounding space
		{"example.com:443", "example.com"},             // domain + port → bare host
		{"api.example.com:8080", "api.example.com"},    // subdomain + port
		{"example.com", "example.com"},                 // bare domain unchanged
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
