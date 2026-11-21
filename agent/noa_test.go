package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/agentcore"
)

func TestEnableNoaContextWindow(t *testing.T) {
	for _, window := range []int{128000, 256000, 0} {
		t.Run(fmt.Sprint(window), func(t *testing.T) {
			opts := agentcore.Options{Compaction: compactionConfig(window)}
			session := enableNoa(&opts, func() bool { return true }, t.TempDir(), "window-test", window, func(msg string) { t.Error(msg) })
			if session == nil {
				t.Fatal("noa not enabled")
			}
			want := window
			if want == 0 {
				want = defaultWindowK * 1000
			}
			if got := session.Config().ModelContextLimit; got != want {
				t.Errorf("ModelContextLimit=%d want %d", got, want)
			}
			if opts.Compactor == nil || opts.Compaction != nil {
				t.Fatal("noa must replace built-in compaction")
			}
		})
	}
}

func TestEnableNoaDisabled(t *testing.T) {
	opts := agentcore.Options{Compaction: compactionConfig(128000)}
	if session := enableNoa(&opts, nil, t.TempDir(), "disabled", 128000, nil); session != nil || opts.Compactor != nil || opts.Compaction == nil {
		t.Fatal("disabled noa changed compaction")
	}
}

func TestEnableNoaForwardsStateWarning(t *testing.T) {
	root := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(root, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	opts := agentcore.Options{Compaction: compactionConfig(128000)}
	var warning string
	session := enableNoa(&opts, func() bool { return true }, root, "failed", 128000, func(msg string) { warning = msg })
	if session == nil || opts.Compactor == nil || opts.Compaction != nil || !strings.Contains(warning, "not a directory") {
		t.Fatalf("noa state warning not forwarded: warning=%q", warning)
	}
}
