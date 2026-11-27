package db

import "testing"

func TestSetStatusAndTerminalGuardedSyncExplorationStatus(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { _ = d.Close() })

	tk, err := d.CreateTask("exp status sync", "verify atomic sync", nil, 0, 0)
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(tk.ID) })

	readExpStatus := func() string {
		t.Helper()
		var st string
		if err := d.QueryRow(`SELECT status FROM explorations WHERE id=$1`, tk.ExplorationID).Scan(&st); err != nil {
			t.Fatalf("query explorations.status: %v", err)
		}
		return st
	}

	for _, tc := range []struct {
		taskStatus string
		wantExp    string
	}{
		{"running", "open"},
		{"done", "achieved"},
		{"running", "open"},
		{"failed", "failed"},
		{"created", "open"},
		{"timeout", "failed"},
	} {
		if err := d.SetStatus(tk.ID, tc.taskStatus); err != nil {
			t.Fatalf("SetStatus(%s): %v", tc.taskStatus, err)
		}
		if got := readExpStatus(); got != tc.wantExp {
			t.Fatalf("after SetStatus(%s): explorations.status=%q, want %q", tc.taskStatus, got, tc.wantExp)
		}
	}

	// Reset to running and verify SetTerminalStatusGuarded first-writer-wins + atomic sync.
	if err := d.SetStatus(tk.ID, "running"); err != nil {
		t.Fatalf("SetStatus(running): %v", err)
	}
	won, err := d.SetTerminalStatusGuarded(tk.ID, "done")
	if err != nil || !won {
		t.Fatalf("SetTerminalStatusGuarded(done): won=%v err=%v", won, err)
	}
	if got := readExpStatus(); got != "achieved" {
		t.Fatalf("after guarded done: explorations.status=%q, want achieved", got)
	}
	won2, err := d.SetTerminalStatusGuarded(tk.ID, "timeout")
	if err != nil || won2 {
		t.Fatalf("second SetTerminalStatusGuarded(timeout) must lose: won=%v err=%v", won2, err)
	}
	if got := readExpStatus(); got != "achieved" {
		t.Fatalf("loser must not overwrite explorations.status: got %q, want achieved", got)
	}
}
