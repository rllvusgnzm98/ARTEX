package server

import (
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

func TestTaskFootprintDefaults(t *testing.T) {
	for _, s := range []*Server{nil, {}, {m: &Manager{}}} {
		for _, id := range []int64{-1, 0, 1} {
			if got := s.taskFootprint(id); got != agent.DefaultFootprint() {
				t.Fatalf("task %d fallback = %+v", id, got)
			}
		}
	}
}

func TestTaskFootprintResolver(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config: %v", err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	defer pg.Close()
	off := false
	task, err := pg.CreateTaskWithOptions("footprint resolver", "read task switches", db.TaskCreateOptions{FootprintPace: &off, FootprintNoDestructive: &off})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.DeleteTask(task.ID)
	s := &Server{m: &Manager{pg: pg}}
	want := agent.DefaultFootprint()
	want.Pace, want.NoDestructive = false, false
	if got := s.taskFootprint(task.ID); got != want {
		t.Fatalf("resolver = %+v, want %+v", got, want)
	}
	if got := s.taskFootprint(0); got != agent.DefaultFootprint() {
		t.Fatalf("invalid task fallback = %+v", got)
	}
	if err := pg.DeleteTask(task.ID); err != nil {
		t.Fatal(err)
	}
	if got := s.taskFootprint(task.ID); got != agent.DefaultFootprint() {
		t.Fatalf("missing task fallback = %+v", got)
	}
	pg.Close()
	if got := s.taskFootprint(task.ID); got != agent.DefaultFootprint() {
		t.Fatalf("database error fallback = %+v", got)
	}
}
