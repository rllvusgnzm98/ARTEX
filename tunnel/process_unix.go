//go:build !windows

package tunnel

import (
	"os"
	"syscall"
)

func zeroSignal() syscall.Signal { return syscall.Signal(0) }

func processAliveFallback(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(zeroSignal()) == nil
}
