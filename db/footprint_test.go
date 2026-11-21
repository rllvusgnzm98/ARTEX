package db

import (
	"database/sql"
	"errors"
	"testing"
)

func TestTaskFootprint(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	for mask := -1; mask < 32; mask++ {
		opts := TaskCreateOptions{}
		values := [5]bool{}
		if mask >= 0 {
			for i := range values {
				values[i] = mask&(1<<i) != 0
			}
			opts.FootprintPace, opts.FootprintMinTouch, opts.FootprintNoDirtyData = &values[0], &values[1], &values[2]
			opts.FootprintNoDestructive, opts.FootprintNoHarmOthers = &values[3], &values[4]
		} else {
			values = [5]bool{true, true, true, true, true}
		}
		task, err := d.CreateTaskWithOptions("footprint test", "round trip", opts)
		if err != nil {
			t.Fatal(err)
		}
		defer d.DeleteTask(task.ID)
		pace, minTouch, noDirty, noDestructive, noHarm, err := d.TaskFootprint(task.ID)
		if got := [5]bool{pace, minTouch, noDirty, noDestructive, noHarm}; err != nil || got != values {
			t.Fatalf("mask %d: got %v err %v, want %v", mask, got, err, values)
		}
	}
	if _, _, _, _, _, err := d.TaskFootprint(-1); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing task error = %v, want sql.ErrNoRows", err)
	}
}
