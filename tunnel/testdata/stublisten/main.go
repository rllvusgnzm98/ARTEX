// stublisten 是测试用的本地占位进程：只在 127.0.0.1 上绑定环境变量给出的端口，
// 收到 SIGINT/SIGTERM 后退出。不是 chisel/suo5，不含任何目标侧配方。
package main

import (
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
)

func bind(portStr string) net.Listener {
	p, err := strconv.Atoi(portStr)
	if err != nil || p <= 0 {
		return nil
	}
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p)))
	if err != nil {
		os.Stderr.WriteString("stublisten bind " + portStr + ": " + err.Error() + "\n")
		os.Exit(1)
	}
	return ln
}

func main() {
	var lns []net.Listener
	for _, key := range []string{"ARTEX_TUNNEL_STUB_SOCKS", "ARTEX_TUNNEL_STUB_LISTEN", "ARTEX_TUNNEL_STUB_LOCAL"} {
		if ln := bind(os.Getenv(key)); ln != nil {
			lns = append(lns, ln)
		}
	}
	if len(lns) == 0 {
		os.Stderr.WriteString("stublisten: no ports to bind\n")
		os.Exit(1)
	}
	defer func() {
		for _, ln := range lns {
			_ = ln.Close()
		}
	}()
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
}
