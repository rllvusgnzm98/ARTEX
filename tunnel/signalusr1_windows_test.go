//go:build windows

package tunnel

import "fmt"

func signalUSR1(int) error {
	return fmt.Errorf("SIGUSR1 is not supported on windows")
}
