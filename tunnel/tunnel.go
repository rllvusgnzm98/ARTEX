// Package tunnel 提供隧道计划层：端口池分配、socks/portfwd 计划组装与回滚步骤。
// 本刀落地台账与计划；外部适配器（chisel/suo5）按需，默认路径不拉起真实进程、
// 不对真实目标打洞。部署参数完整写入 tunnels.deploy_params，供上游选择与回滚使用。
package tunnel

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// 隧道类型与适配器。
const (
	KindSocks     = "socks"
	KindPortfwd   = "portfwd"
	AdapterChisel = "chisel"
	AdapterSuo5   = "suo5"
)

// DefaultPortRange 是平台侧隧道端口池默认值（env ARTEX_TUNNEL_PORT_RANGE 可覆盖）。
const DefaultPortRange = "20000-21000"

// ParsePortRange 解析 "min-max" 端口池。纯函数。
func ParsePortRange(s string) (min, max int, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		s = DefaultPortRange
	}
	a, b, ok := strings.Cut(s, "-")
	if !ok {
		return 0, 0, fmt.Errorf("端口池格式应为 min-max（如 %s)，实际 %q", DefaultPortRange, s)
	}
	min, err1 := strconv.Atoi(strings.TrimSpace(a))
	max, err2 := strconv.Atoi(strings.TrimSpace(b))
	if err1 != nil || err2 != nil || min <= 0 || max > 65535 || min > max {
		return 0, 0, fmt.Errorf("非法端口池 %q（需 1-65535 且 min<=max)", s)
	}
	return min, max, nil
}

// AllocatePort 从端口池 [min,max] 挑一个既不在 used 集合、又能真实绑定成功的端口。
// canListen 注入真实绑定检查（生产用 net.Listen 试绑；测试用纯函数）。纯逻辑可测。
func AllocatePort(min, max int, used map[int]bool, canListen func(port int) bool) (int, error) {
	for p := min; p <= max; p++ {
		if used[p] {
			continue
		}
		if canListen != nil && !canListen(p) {
			continue
		}
		return p, nil
	}
	return 0, fmt.Errorf("端口池 %d-%d 无可用端口", min, max)
}

// CanListen 试绑 127.0.0.1:port；生产端口分配与测试均可注入或直接用。
func CanListen(port int) bool {
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}
