// stublisten 是测试用的本地占位进程：只在 127.0.0.1 上绑定环境变量给出的端口，
// 收到 SIGINT/SIGTERM 后退出。不是 chisel/suo5，不含任何目标侧配方。
// ARTEX_TUNNEL_STUB_DEFER_ENTRY=1 时先只绑 ListenPort，收到 SIGUSR1 后再绑
// socks/local，用于模拟「平台 server 已起、立足点尚未回连」的真实 chisel 时序。
package main

import (
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
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
	deferEntry := os.Getenv("ARTEX_TUNNEL_STUB_DEFER_ENTRY") == "1"
	var mu sync.Mutex
	var lns []net.Listener
	add := func(ln net.Listener) {
		if ln == nil {
			return
		}
		mu.Lock()
		lns = append(lns, ln)
		mu.Unlock()
	}
	if ln := bind(os.Getenv("ARTEX_TUNNEL_STUB_LISTEN")); ln != nil {
		add(ln)
	}
	if !deferEntry {
		add(bind(os.Getenv("ARTEX_TUNNEL_STUB_SOCKS")))
		add(bind(os.Getenv("ARTEX_TUNNEL_STUB_LOCAL")))
	}
	mu.Lock()
	n := len(lns)
	mu.Unlock()
	if n == 0 {
		os.Stderr.WriteString("stublisten: no ports to bind\n")
		os.Exit(1)
	}
	defer func() {
		mu.Lock()
		defer mu.Unlock()
		for _, ln := range lns {
			_ = ln.Close()
		}
	}()
	stop := make(chan os.Signal, 1)
	usr := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	if sig := usr1(); sig != nil {
		signal.Notify(usr, sig)
	}
	for {
		select {
		case <-stop:
			return
		case <-usr:
			if deferEntry {
				add(bind(os.Getenv("ARTEX_TUNNEL_STUB_SOCKS")))
				add(bind(os.Getenv("ARTEX_TUNNEL_STUB_LOCAL")))
				deferEntry = false
			}
		}
	}
}
