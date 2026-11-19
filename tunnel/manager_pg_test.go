package tunnel

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func openTunnelTestDB(t *testing.T) *db.DB {
	t.Helper()
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

// TestManagerDeployPostgresFixture 走真实 tunnels 表：stub 成功 → alive，teardown 杀进程。
func TestManagerDeployPostgresFixture(t *testing.T) {
	d := openTunnelTestDB(t)
	ctx := context.Background()
	store := db.NewTunnelStore(d)
	m, err := NewManager(Options{Store: store, DataDir: t.TempDir(), ChiselPath: buildStub(t)})
	if err != nil {
		t.Fatal(err)
	}
	rec, err := m.Deploy(ctx, socksPlan(91001, freeListenPort(t), freeListenPort(t)))
	if err != nil {
		t.Fatalf("Deploy: %v rec=%+v", err, rec)
	}
	t.Cleanup(func() {
		_ = m.Teardown(context.Background(), rec.ID)
		_ = store.Delete(context.Background(), rec.ID)
	})
	if rec.State != db.TunnelAlive {
		t.Fatalf("want alive, got %+v", rec)
	}
	var p Plan
	_ = json.Unmarshal(rec.DeployParams, &p)
	if p.ServerPID <= 0 || !processAlive(p.ServerPID) {
		t.Fatalf("应回写存活 pid: %+v", p)
	}
	if err := m.Teardown(ctx, rec.ID); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	got, err := store.Get(ctx, rec.ID)
	if err != nil || got == nil || got.State != db.TunnelStopped {
		t.Fatalf("PG 台账应为 stopped: %+v %v", got, err)
	}
}
