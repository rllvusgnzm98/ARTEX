package server

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/Autumn-27/norma/skill"
)

// skillDirCache reuses the parsed skill registry while the skill directory is
// unchanged. ToolAugment runs on every agent run; without this each run re-reads
// and re-parses every SKILL.md. The signature is path/size/mtime of each skill
// file LoadDir would read, so edits, adds and removals show up on the next run.
// The cached registry is shared read-only (callers only List it).
type skillDirCache struct {
	mu  sync.Mutex
	dir string
	sig string
	reg *skill.Registry
}

func (c *skillDirCache) load(dir string) (*skill.Registry, error) {
	sig, err := skillDirSignature(dir)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.reg != nil && c.dir == dir && c.sig == sig {
		return c.reg, nil
	}
	reg, err := skill.LoadDir(dir)
	if err != nil {
		return nil, err
	}
	c.dir, c.sig, c.reg = dir, sig, reg
	return reg, nil
}

// skillDirSignature mirrors skill.LoadDir's file selection: <dir>/<name>/SKILL.md
// and top-level *.md.
func skillDirSignature(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, e := range entries {
		var p string
		switch {
		case e.IsDir():
			p = filepath.Join(dir, e.Name(), "SKILL.md")
		case strings.HasSuffix(e.Name(), ".md"):
			p = filepath.Join(dir, e.Name())
		default:
			continue
		}
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		fmt.Fprintf(&b, "%s|%d|%d\n", p, fi.Size(), fi.ModTime().UnixNano())
	}
	return b.String(), nil
}
