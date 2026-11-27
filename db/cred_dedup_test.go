package db

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestAddCredentialDedup(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { _ = d.Close() })

	ctx := context.Background()
	cs := NewCredentialStore(d, []byte("cred-dedup-test-master-key-32b!!"))
	taskA := time.Now().UnixNano()
	taskB := taskA + 1

	var createdIDs []int64
	t.Cleanup(func() {
		for _, id := range createdIDs {
			_ = cs.Delete(context.Background(), id)
		}
	})

	id1, err := cs.AddCredential(ctx, &CredentialRecord{
		TaskID:   taskA,
		Username: "Admin",
		CredType: CredPassword,
		Secret:   "fixture-secret-1",
		Source:   "config.php",
		Verified: false,
	})
	if err != nil {
		t.Fatalf("first AddCredential: %v", err)
	}
	createdIDs = append(createdIDs, id1)

	// Same (task_id, lower(btrim(username)), cred_type, secret_hash) -> returns same ID and merges metadata.
	id2, err := cs.AddCredential(ctx, &CredentialRecord{
		TaskID:      taskA,
		HostAssetID: 88,
		Username:    "  admin ",
		CredType:    CredPassword,
		Secret:      "fixture-secret-1",
		Domain:      "CORP",
		Source:      "ssh login check",
		Verified:    true,
	})
	if err != nil {
		t.Fatalf("second AddCredential (dedup): %v", err)
	}
	if id2 != id1 {
		createdIDs = append(createdIDs, id2)
		t.Fatalf("expected deduplicated credential id=%d, got %d", id1, id2)
	}

	got, err := cs.Get(ctx, id1)
	if err != nil || got == nil {
		t.Fatalf("Get(%d): %v", id1, err)
	}
	if !got.Verified || got.HostAssetID != 88 || got.Domain != "CORP" {
		t.Fatalf("merged fields mismatch: %+v", got)
	}
	if !strings.Contains(got.Source, "config.php") || !strings.Contains(got.Source, "ssh login check") {
		t.Fatalf("merged source=%q missing expected parts", got.Source)
	}

	// Different secret -> must insert a distinct row.
	id3, err := cs.AddCredential(ctx, &CredentialRecord{
		TaskID:   taskA,
		Username: "admin",
		CredType: CredPassword,
		Secret:   "fixture-secret-2",
		Source:   "env",
	})
	if err != nil {
		t.Fatalf("AddCredential different secret: %v", err)
	}
	createdIDs = append(createdIDs, id3)
	if id3 == id1 {
		t.Fatal("different secret must not deduplicate")
	}

	// Different task_id -> must insert a distinct row.
	id4, err := cs.AddCredential(ctx, &CredentialRecord{
		TaskID:   taskB,
		Username: "admin",
		CredType: CredPassword,
		Secret:   "fixture-secret-1",
		Source:   "other task",
	})
	if err != nil {
		t.Fatalf("AddCredential different task: %v", err)
	}
	createdIDs = append(createdIDs, id4)
	if id4 == id1 {
		t.Fatal("different task_id must not deduplicate")
	}
}
