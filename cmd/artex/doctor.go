// doctor.go —— `artex doctor` 部署预检子命令。
// 只读检查：不启动服务、不写 DB；data 目录可写性用临时文件探测（随测随删）。
// 每项打印 OK/WARN/FAIL/SKIP + 一行说明，结尾汇总；有 FAIL 才退出码 1。
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Autumn-27/artex/config"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/tools"
)

// doctorDefaultAddr 必须与主程序 -addr 默认一致，均为 :8787（全网卡）。
// 不要改成 127.0.0.1:8787。
const doctorDefaultAddr = ":8787"

// isDoctorCommand reports whether process args request the doctor subcommand.
// Checked before the service flag set is parsed and before any subsystem starts.
func isDoctorCommand(args []string) bool {
	return len(args) > 1 && args[1] == "doctor"
}

// doctorStatus 是单项预检结论。SKIP 用于前置条件不满足（如 DB 不可达时查不了
// LLM profile）。
type doctorStatus int

const (
	docOK doctorStatus = iota
	docWarn
	docFail
	docSkip
)

func (s doctorStatus) String() string {
	switch s {
	case docOK:
		return "OK  "
	case docWarn:
		return "WARN"
	case docFail:
		return "FAIL"
	case docSkip:
		return "SKIP"
	}
	return "?"
}

type doctorItem struct {
	status doctorStatus
	name   string
	note   string
}

// runDoctor 跑全部预检并打印报告；返回进程退出码（有 FAIL → 1）。
func runDoctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	addr := fs.String("addr", doctorDefaultAddr, "HTTP listen address（与主程序 -addr 同义，默认 :8787）")
	dataDir := fs.String("data", filepath.Join(config.BaseDir(), "data"), "data directory（与主程序 -data 同义）")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	_ = addr // 保留与主程序同义的 -addr，供运维对照；:8787 不是告警条件。

	fmt.Printf("ARTEX doctor —— 部署预检（只读，不启动服务、不写 DB）\n\n")
	var items []doctorItem
	check := func(status doctorStatus, name, note string) {
		items = append(items, doctorItem{status, name, note})
		fmt.Printf("[%s] %s: %s\n", status, name, note)
	}

	// 1. PostgreSQL 可连接（复用现有配置解析；轻量 ping，不走 Open 的迁移/seed）
	dsn, source, dsnErr := db.DSN()
	profiles, dbOK := -1, false
	if dsnErr != nil {
		check(docFail, "PostgreSQL", dsnErr.Error())
	} else if n, err := db.Probe(dsn); err != nil {
		check(docFail, "PostgreSQL", fmt.Sprintf("连接失败（来源: %s）: %v", source, err))
	} else {
		dbOK, profiles = true, n
		check(docOK, "PostgreSQL", fmt.Sprintf("可连接（来源: %s; %s）", source, config.Redact(dsn)))
	}

	// 2. LLM profile 已配置（DB 不可达则 SKIP）
	if !dbOK {
		check(docSkip, "LLM profile", "DB 不可达，跳过（请先在 UI / llm_profiles 配置）")
	} else if profiles < 0 {
		check(docWarn, "LLM profile", "库未初始化（llm_profiles 表不存在），启动后请在 UI 配置")
	} else if profiles == 0 {
		check(docWarn, "LLM profile", "未配置任何 LLM profile，探索无法运行；请在 UI「LLM」页添加")
	} else {
		check(docOK, "LLM profile", fmt.Sprintf("已配置 %d 个", profiles))
	}

	// 3. data 目录可写（临时文件探测，随测随删）
	if st, err := os.Stat(*dataDir); err != nil {
		check(docWarn, "data 目录", fmt.Sprintf("%s 不存在（启动时会自动创建）", *dataDir))
	} else if !st.IsDir() {
		check(docFail, "data 目录", fmt.Sprintf("%s 不是目录", *dataDir))
	} else if f, err := os.CreateTemp(*dataDir, ".doctor-*"); err != nil {
		check(docFail, "data 目录", fmt.Sprintf("%s 不可写: %v", *dataDir, err))
	} else {
		name := f.Name()
		_ = f.Close()
		_ = os.Remove(name)
		check(docOK, "data 目录", *dataDir+" 可写")
	}

	// 4/5. 外部工具清单：可选随道工具逐项 + 军火库存在性汇总
	manifest, mErr := tools.Load(tools.ManifestPath())
	if mErr != nil && !os.IsNotExist(mErr) {
		check(docWarn, "工具清单", "解析失败（跳过工具检查）: "+mErr.Error())
	}
	var results []tools.CheckResult
	if manifest != nil {
		results = tools.Check(manifest, *dataDir)
	} else if os.IsNotExist(mErr) {
		// 清单缺失（开发态/裁剪部署）：随道工具按运行时同一套解析（env > data/tools）
		// 兜底查存在性。不检查 suo5-payloads。
		for _, name := range []string{"suo5", "chisel"} {
			env := "ARTEX_" + strings.ToUpper(name) + "_PATH"
			results = append(results, tools.CheckEntry(tools.Entry{
				Name: name, Path: "tools/" + name, Env: env, Category: "tunnel",
			}, *dataDir))
		}
		check(docWarn, "工具清单", "packaging/tools-manifest.json 缺失——随道工具按默认路径检查，军火库无法汇总")
	}

	// 4. 随道工具（chisel/suo5/ligolo-*）：存在性 + （清单钉了哈希时）sha256
	// 缺失一律 WARN，不得 FAIL，不得静默必装。
	{
		var parts []string
		worst := docOK
		for _, r := range results {
			if r.Entry.Category != "tunnel" {
				continue
			}
			parts = append(parts, doctorToolNote(r))
			if r.Status == tools.StatusMissing || r.Status == tools.StatusMismatch {
				worst = docWarn
			}
		}
		if len(parts) == 0 {
			check(docSkip, "随道工具", "清单中无随道项")
		} else {
			check(worst, "随道工具", strings.Join(parts, "; "))
		}
	}

	// 5. 军火库工具存在性汇总（存在 X/Y）；缺失只 WARN
	{
		var present, missing []string
		for _, r := range results {
			if r.Entry.Category != "arsenal" {
				continue
			}
			if r.Status == tools.StatusMissing {
				missing = append(missing, r.Entry.Name)
			} else {
				present = append(present, r.Entry.Name)
			}
		}
		total := len(present) + len(missing)
		switch {
		case total == 0:
			check(docSkip, "军火库工具", "清单缺失，无法汇总")
		case len(missing) == 0:
			check(docOK, "军火库工具", fmt.Sprintf("存在 %d/%d", len(present), total))
		default:
			check(docWarn, "军火库工具", fmt.Sprintf("存在 %d/%d（缺失: %s）——按需补齐到 %s",
				len(present), total, strings.Join(missing, ", "), filepath.Join(*dataDir, "tools")))
		}
	}

	// 6. 伪装门控本波未启用。必须显式 ARTEX_GATE=1 才会开启，默认关闭。
	// :8787（全网卡）不是告警条件；不要把「非 loopback 将默认开门控」写进来。
	check(docOK, "伪装门控", "本波未启用；必须显式设置 ARTEX_GATE=1 才会开启，默认关闭")

	// 7. ARTEX_CALLBACK_ADDR：隧道回连平台用
	// systemd 部署常用 EnvironmentFile 注入（packaging/artex.service 约定
	// /etc/artex.env），doctor 从 shell 直跑时读不到进程环境，需兜底解析该文件。
	cb := config.CallbackAddr()
	cbSrc := ""
	if cb == "" {
		if v, ok := readEnvFileValue("/etc/artex.env", "ARTEX_CALLBACK_ADDR"); ok {
			cb, cbSrc = v, "（来自 /etc/artex.env）"
		}
	}
	if cb != "" {
		check(docOK, "回连地址", "ARTEX_CALLBACK_ADDR = "+cb+cbSrc)
	} else {
		check(docWarn, "回连地址", "ARTEX_CALLBACK_ADDR 未设置——隧道回连平台不可用；立足点功能不受影响")
	}

	// 汇总：有 FAIL 才退出码 1
	var nOK, nWarn, nFail, nSkip int
	for _, it := range items {
		switch it.status {
		case docOK:
			nOK++
		case docWarn:
			nWarn++
		case docFail:
			nFail++
		case docSkip:
			nSkip++
		}
	}
	fmt.Printf("\n汇总：OK %d · WARN %d · FAIL %d · SKIP %d\n", nOK, nWarn, nFail, nSkip)
	if nFail > 0 {
		fmt.Println("存在 FAIL 项，请先修复再启动。")
		return 1
	}
	return 0
}

// doctorToolNote 渲染单个工具的自检片段（doctor 报告用）。
func doctorToolNote(r tools.CheckResult) string {
	switch r.Status {
	case tools.StatusOK:
		return fmt.Sprintf("%s OK(sha256 一致, %s)", r.Entry.Name, r.Path)
	case tools.StatusUnpinned:
		return fmt.Sprintf("%s 存在（未钉 sha256, %s)", r.Entry.Name, r.Path)
	case tools.StatusMismatch:
		return fmt.Sprintf("%s 哈希不匹配（期望 %s 实际 %s；可能自编译，仅警告）", r.Entry.Name, r.Entry.SHA256, r.Actual)
	default:
		return fmt.Sprintf("%s 缺失（期望 %s）", r.Entry.Name, r.Path)
	}
}

// readEnvFileValue 解析 systemd EnvironmentFile 风格的 KEY=VALUE 文件，返回指定
// 键的值。文件不存在或键缺失返回 ok=false；# 开头为注释。仅用于 doctor 兜底提示。
func readEnvFileValue(path, key string) (string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(k) != key {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		return v, v != ""
	}
	return "", false
}
