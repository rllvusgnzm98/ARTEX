// emp3r0r_wg.go 是本进程内的 userspace WireGuard peer 拉起逻辑。
// emp3r0r cc 的 operator HTTP 服务绑定在 gVisor netstack 上，只有 WG peer 可达；
// 这里用 wireguard-go（MIT）拉起一个 operator peer 接入 cc 的 overlay，
// 与 emp3r0r 自身 client 模式等价，但不链接 emp3r0r 任何代码。
package session

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// wgPeerDialer 拉起 operator WG peer，返回经 netstack 拨号的 DialContext 与
// 设备回收函数。凭据全部来自 Emp3r0rConfig（cc provisioning 产物）。
func wgPeerDialer(cfg Emp3r0rConfig) (ccDialFunc, func() error, error) {
	if strings.TrimSpace(cfg.OperatorKey) == "" {
		return nil, nil, fmt.Errorf("wg_operator_key 未配置")
	}
	opKey, err := wgtypes.ParseKey(strings.TrimSpace(cfg.OperatorKey))
	if err != nil {
		return nil, nil, fmt.Errorf("wg_operator_key 非法: %w", err)
	}
	if strings.TrimSpace(cfg.ServerKey) == "" {
		return nil, nil, fmt.Errorf("wg_server_public_key 未配置")
	}
	srvKey, err := wgtypes.ParseKey(strings.TrimSpace(cfg.ServerKey))
	if err != nil {
		return nil, nil, fmt.Errorf("wg_server_public_key 非法: %w", err)
	}
	opIP, err := netip.ParseAddr(strings.TrimSpace(cfg.OperatorIP))
	if err != nil {
		return nil, nil, fmt.Errorf("wg_operator_ip 非法: %w", err)
	}
	if strings.TrimSpace(cfg.ServerIP) == "" {
		return nil, nil, fmt.Errorf("wg_server_ip 未配置")
	}
	host, port, err := net.SplitHostPort(strings.TrimSpace(cfg.Endpoint))
	if err != nil || host == "" || port == "" {
		return nil, nil, fmt.Errorf("wg_endpoint 需要 host:port: %q", cfg.Endpoint)
	}

	// 与 cc 端同构：operator IP 挂 /24 netstack（subnet 由 ServerIP 所在段决定，
	// 这里直接用 operator IP 的 /24——cc provisioning 同一网段）。
	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{opIP}, nil, device.DefaultMTU)
	if err != nil {
		return nil, nil, fmt.Errorf("userspace netstack 创建失败: %w", err)
	}
	logger := device.NewLogger(device.LogLevelSilent, "(emp3r0r-wg) ")
	dev := device.NewDevice(tun, conn.NewDefaultBind(), logger)

	var sb strings.Builder
	fmt.Fprintf(&sb, "private_key=%s\n", hex.EncodeToString(opKey[:]))
	sb.WriteString("replace_peers=true\n")
	fmt.Fprintf(&sb, "public_key=%s\n", hex.EncodeToString(srvKey[:]))
	sb.WriteString("replace_allowed_ips=true\n")
	fmt.Fprintf(&sb, "allowed_ip=%s/32\n", strings.TrimSpace(cfg.ServerIP))
	fmt.Fprintf(&sb, "endpoint=%s\n", net.JoinHostPort(host, port))
	sb.WriteString("persistent_keepalive_interval=25\n")

	if err := dev.IpcSet(sb.String()); err != nil {
		dev.Close()
		return nil, nil, fmt.Errorf("wg 设备配置失败: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, nil, fmt.Errorf("wg 设备启动失败: %w", err)
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return tnet.DialContext(ctx, "tcp", addr)
	}, func() error { dev.Close(); return nil }, nil
}
