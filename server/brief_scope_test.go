package server

import (
	"context"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/oob"
)

func TestSeedBriefScopeExcludesGatewayOOBAndNegatedURLs(t *testing.T) {
	pg := openTestPG(t)
	row, err := pg.CreateTask("seed brief scope fixture", "test brief guard", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.DeleteTask(row.ID) })

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	oobMgr, err := oob.New(ctx, filepath.Join(t.TempDir(), "oob"))
	if err != nil {
		t.Fatal(err)
	}
	defer oobMgr.Close()
	oobMgr.SetBaseURL("http://10.88.0.2:8787")

	taskID := strconv.FormatInt(row.ID, 10)
	task := &Task{ID: taskID, ExpID: row.ExplorationID, Store: pg.Exploration(row.ExplorationID)}
	s := &Server{
		m:      &Manager{pg: pg, assets: pg.Assets(), tasks: map[string]*Task{taskID: task}},
		ctx:    ctx,
		oob:    oobMgr,
		llmCfg: agent.Config{BaseURL: "https://llm-gw.internal.test/v1"},
	}

	brief := "先访问 https://target.lab.test/login ；" +
		"严禁访问 https://prod.forbidden.test/ ；" +
		"模型接口 https://llm-gw.internal.test/v1 ；" +
		"平台回调 http://10.88.0.2:8787/o/demo"
	s.seedBriefScope(task, brief)

	rows, err := pg.Assets().ListTaskScope(row.ID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, r := range rows {
		if r.Domain != "" {
			got[r.Domain] = true
		}
		if r.Net != "" {
			got[r.Net] = true
		}
		if r.Value != "" {
			got[r.Value] = true
		}
	}
	if !got["target.lab.test"] {
		t.Fatalf("expected target.lab.test in seed scope, got %+v", rows)
	}
	for _, forbidden := range []string{"prod.forbidden.test", "llm-gw.internal.test", "10.88.0.2/32", "10.88.0.2"} {
		if got[forbidden] {
			t.Fatalf("forbidden/infra host %q must not be added to seed scope: %+v", forbidden, rows)
		}
	}
}

func TestRecordRoEWarnDeduplicatesPerTaskHost(t *testing.T) {
	pg := openTestPG(t)
	row, err := pg.CreateTask("roe warn dedup fixture", "test", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.DeleteTask(row.ID) })

	taskID := strconv.FormatInt(row.ID, 10)
	s := &Server{
		m: &Manager{
			pg:    pg,
			tasks: map[string]*Task{taskID: {ID: taskID, ExpID: row.ExplorationID, Store: pg.Exploration(row.ExplorationID)}},
		},
	}
	s.recordRoEWarn(row.ID, "10.255.0.9", "⚠ out of scope 1")
	s.recordRoEWarn(row.ID, "10.255.0.9", "⚠ out of scope 2")
	s.recordRoEWarn(row.ID, "10.255.0.10", "⚠ out of scope other")

	var cnt int
	if err := pg.QueryRow(`SELECT COUNT(*) FROM activity WHERE exploration_id=$1 AND tool='roe'`, row.ExplorationID).Scan(&cnt); err != nil {
		t.Fatal(err)
	}
	if cnt != 2 {
		t.Fatalf("expected 2 deduplicated roe activity rows (2 distinct hosts), got %d", cnt)
	}
}
