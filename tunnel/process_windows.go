//go:build windows

package tunnel

import "syscall"

// processAliveFallback 在 Windows 上不能用 signal 0：os.Process.Signal 对非 Kill
// 一律返回 EWINDOWS。退出码 259（STILL_ACTIVE）表示进程尚未退出。
func processAliveFallback(pid int) bool {
	h, err := syscall.OpenProcess(syscall.PROCESS_QUERY_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer syscall.CloseHandle(h)
	var code uint32
	if err := syscall.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	const stillActive = 259
	return code == stillActive
}
