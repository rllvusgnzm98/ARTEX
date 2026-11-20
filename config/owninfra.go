package config

import (
	"net"
	"strconv"
	"strings"
	"sync"
)

// listenMu 保护 listenAddr。自身 host 的计算与 -addr 记录共用这把锁。
var (
	listenMu   sync.RWMutex
	listenAddr string
)

// SetListenAddr 记录主程序 -addr（host:port）。":8787" 表示全网卡，host 部分为空。
// 并发安全。不改变 CallbackAddr 的解析语义。
func SetListenAddr(addr string) {
	listenMu.Lock()
	listenAddr = strings.TrimSpace(addr)
	listenMu.Unlock()
}

func currentListen() (host string, port int) {
	listenMu.RLock()
	addr := listenAddr
	listenMu.RUnlock()
	return parseListen(addr)
}

// parseListen 拆 host:port。解析不出端口时端口为 0；整段无法拆开时 host 也为空。
func parseListen(addr string) (host string, port int) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", 0
	}
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 0 || n > 65535 {
		return h, 0
	}
	return h, n
}

// OwnInfraPort 返回 -addr 里的端口；解析不出为 0。
func OwnInfraPort() int {
	_, port := currentListen()
	return port
}

// OwnInfraHosts 返回平台自身 host，全部小写、去重，顺序稳定：
// callback 主机（CallbackAddr 的主机部分）、监听 host（非空时）、
// 配置 own_infra_hosts、回环地址 127.0.0.1 / ::1 / localhost。
func OwnInfraHosts() []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(h string) {
		h = normalizeInfraHost(h)
		if h == "" {
			return
		}
		if _, ok := seen[h]; ok {
			return
		}
		seen[h] = struct{}{}
		out = append(out, h)
	}
	add(CallbackAddr())
	if h, _ := currentListen(); h != "" {
		add(h)
	}
	for _, h := range Load().OwnInfraHosts {
		add(h)
	}
	add("127.0.0.1")
	add("::1")
	add("localhost")
	return out
}

// normalizeInfraHost 与 guard 的自身 host 归一一致：去空白、去端口、
// 去 IPv6 方括号、去尾部点、转小写。空结果表示跳过。
func normalizeInfraHost(h string) string {
	h = strings.TrimSpace(h)
	if h == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	if strings.HasPrefix(h, "[") {
		if i := strings.IndexByte(h, ']'); i >= 0 {
			h = h[1:i]
		}
	}
	h = strings.TrimSpace(h)
	h = strings.TrimRight(h, ".")
	return strings.ToLower(h)
}
