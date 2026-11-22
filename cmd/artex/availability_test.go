package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDoctorShellAvailabilityStrictAndOptional(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX fixture")
	}
	data := isolateConfig(t)
	for _, strict := range []bool{false, true} {
		statuses := map[string]doctorStatus{}
		checkShellAvailability(t.Context(), data, strict, func(status doctorStatus, name, note string) { statuses[name] = status })
		if statuses["CLI ffuf"] != docOK || statuses["CLI nxc"] != docWarn {
			t.Fatalf("optional policy: %+v", statuses)
		}
	}
	t.Setenv("PATH", t.TempDir())
	if err := os.MkdirAll(filepath.Join(data, "tools"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "tools", "httpx"), []byte("#!/bin/sh\necho PythonHTTPX\n"), 0755); err != nil {
		t.Fatal(err)
	}
	for _, strict := range []bool{false, true} {
		checkShellAvailability(t.Context(), data, strict, func(status doctorStatus, name, note string) {
			if name == "CLI nxc" {
				if status != docWarn {
					t.Fatal("optional tool must not fail")
				}
				return
			}
			want := docWarn
			if strict {
				want = docFail
			}
			if status != want {
				t.Fatalf("%s status=%v want=%v", name, status, want)
			}
			if name == "CLI httpx" && !strings.Contains(note, "identity mismatch") {
				t.Fatal(note)
			}
		})
	}
}
