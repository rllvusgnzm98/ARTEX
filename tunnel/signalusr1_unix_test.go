//go:build unix

package tunnel

import "syscall"

func signalUSR1(pid int) error {
	return syscall.Kill(pid, syscall.SIGUSR1)
}
