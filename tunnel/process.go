package tunnel

import (
	"os"
	"runtime"
	"strconv"
	"strings"
)

// processAlive 检测平台侧进程存活。
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	if runtime.GOOS == "linux" {
		_, err := os.Stat("/proc/" + strconv.Itoa(pid))
		return err == nil
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(zeroSignal()) == nil
}

func readCmdline(pid int) string {
	if runtime.GOOS != "linux" || pid <= 0 {
		return ""
	}
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err != nil {
		return ""
	}
	return strings.ReplaceAll(string(data), "\x00", " ")
}

// serverCmdlineMatches 杀台前核对 /proc/<pid>/cmdline，防 pid 复用误杀。
// 匹配计划里的 authfile，或 cmdline 含 chisel/suo5/stublisten。
func serverCmdlineMatches(p *Plan) bool {
	if p == nil || p.ServerPID <= 0 {
		return false
	}
	cl := readCmdline(p.ServerPID)
	if cl == "" {
		return false
	}
	if p.AuthFile != "" && strings.Contains(cl, p.AuthFile) {
		return true
	}
	return strings.Contains(cl, "chisel") || strings.Contains(cl, "suo5") || strings.Contains(cl, "stublisten")
}
