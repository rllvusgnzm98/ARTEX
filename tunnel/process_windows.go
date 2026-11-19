//go:build windows

package tunnel

import "syscall"

func zeroSignal() syscall.Signal { return 0 }
