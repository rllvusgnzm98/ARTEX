package db

import "testing"

func TestBareIPNeverBecomesRootDomainAssetOrScope(t *testing.T) {
	candRoot := autoScopeCandidate(1, "root_domain", "192.168.2.22", "", "")
	if candRoot.Kind != "ip" || candRoot.Net != "192.168.2.22/32" || candRoot.Domain != "" {
		t.Fatalf("bare IP root_domain candidate must normalize to ip/32, got %+v", candRoot)
	}
	candSub := autoScopeCandidate(1, "subdomain", "192.168.2.33", "", "")
	if candSub.Kind != "ip" || candSub.Net != "192.168.2.33/32" || candSub.Domain != "" {
		t.Fatalf("bare IP subdomain candidate must normalize to ip/32, got %+v", candSub)
	}

	dsn, _, err := DSN()
	if err != nil {
		t.Skipf("no database config (%v)", err)
	}
	d, err := Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()

	task, err := d.CreateTask("bare ip scope fixture", "ensure bare IP never becomes root_domain", nil, 0, 0)
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	defer func() { _ = d.DeleteTask(task.ID) }()
	as := d.Assets()

	const ip = "198.51.100.77"
	defer func() {
		_, _ = d.Exec(`DELETE FROM assets WHERE domain=$1 OR ip=$1 OR url LIKE $2`, ip, "http://"+ip+"%")
	}()

	if _, err := as.UpsertHTTPService(UpsertHTTPServiceReq{URL: "http://" + ip + ":8080/execute.php", IP: ip, TaskID: task.ID}); err != nil {
		t.Fatalf("UpsertHTTPService: %v", err)
	}
	var fakeRoots int
	if err := d.QueryRow(`SELECT COUNT(*) FROM assets WHERE type='root_domain' AND domain=$1`, ip).Scan(&fakeRoots); err != nil {
		t.Fatal(err)
	}
	if fakeRoots != 0 {
		t.Fatalf("UpsertService for IP URL created %d fake root_domain asset(s)", fakeRoots)
	}

	ts, err := as.AddAgentScope(task.ID, "root_domain", ip, "misclassified IP", "agent")
	if err != nil {
		t.Fatalf("AddAgentScope(root_domain, ip): %v", err)
	}
	if ts.Kind != "ip" || ts.Net != ip+"/32" || ts.Domain != "" {
		t.Fatalf("AddAgentScope(root_domain, ip) must normalize to ip/32, got %+v", ts)
	}
	tsEx, err := as.AddAgentScope(task.ID, "exclude_root_domain", ip, "exclude IP", "manual")
	if err != nil {
		t.Fatalf("AddAgentScope(exclude_root_domain, ip): %v", err)
	}
	if tsEx.Kind != "exclude_ip" || tsEx.Net != ip+"/32" || tsEx.Domain != "" {
		t.Fatalf("AddAgentScope(exclude_root_domain, ip) must normalize to exclude_ip/32, got %+v", tsEx)
	}
}
