package agent

import (
	"context"

	"github.com/Autumn-27/artex/tools"
)

func ShellHintAvailability(ctx context.Context, dataDir string) []tools.Availability {
	var specs []tools.CommandSpec
	for _, seed := range ShellHintSeeds() {
		specs = append(specs, tools.CommandSpec{Name: seed.Key, Optional: seed.Key == "nxc"})
	}
	return tools.CheckCommands(ctx, specs, dataDir)
}

func shellEnv(dataDir string, extra []string) []string {
	return append(extra, "PATH="+tools.CommandPath(dataDir))
}

// ShellHintSeed is a kind=shell environment declaration: a CLI that may be
// present on PATH and advertised in the Bash tool description. It is not a
// callable tool, is not deferred, and is not discovered via SearchExtraTools.
type ShellHintSeed struct {
	Key  string // exact command name, used for LookPath
	Desc string
}

// shellHintDefaultAgents is the code-default binding for catalogued shell hints.
var shellHintDefaultAgents = []string{"worker", "pentest"}

// ShellHintDefaultAgents returns the default agent binding for seeded shell hints.
func ShellHintDefaultAgents() []string {
	out := make([]string, len(shellHintDefaultAgents))
	copy(out, shellHintDefaultAgents)
	return out
}

// ShellHintSeeds is the first-insert catalog of selected CLIs. Keys are exact
// command names. Descriptions state capability and when to use the tool; they
// do not encode harvest or movement procedures, and they do not treat these
// CLIs as required packaging defaults.
func ShellHintSeeds() []ShellHintSeed {
	return []ShellHintSeed{
		{Key: "ffuf", Desc: "用于 HTTP 目录、参数或虚拟主机等枚举与爆破。Bash 说明里已列出时优先用它，不要为同一类枚举手写 curl 或 Python 循环。"},
		{Key: "feroxbuster", Desc: "用于递归 Web 内容发现与目录枚举。Bash 说明里已列出时优先用它，不要为同一类发现手写 curl 或 Python 循环。"},
		{Key: "gobuster", Desc: "用于目录、DNS 或虚拟主机枚举。Bash 说明里已列出时优先用它，不要为同一类枚举手写 curl 或 Python 循环。"},
		{Key: "sqlmap", Desc: "用于在已授权范围内检测和验证注入（尤其是 SQL 注入）。Bash 说明里已列出时优先用它，不要为同一类注入探测手写 curl 或 Python 循环。"},
		{Key: "hydra", Desc: "用于在已授权范围内对明确服务做有限的口令喷洒或猜测。Bash 说明里已列出时优先用它，不要为同一类喷洒手写循环脚本。"},
		{Key: "nmap", Desc: "用于端口与服务发现、识别。Bash 说明里已列出时优先用它，不要为同一类扫描手写探测循环。"},
		{Key: "nuclei", Desc: "用于按模板做已知暴露面或漏洞的指纹与检测。Bash 说明里已列出时优先用它，不要为同一类检测手写请求循环。"},
		{Key: "whatweb", Desc: "用于 Web 技术栈指纹识别。Bash 说明里已列出时优先用它，不要为同一类指纹手写请求脚本。"},
		{Key: "commix", Desc: "用于在已授权范围内检测和验证命令注入。Bash 说明里已列出时优先用它，不要为同一类注入探测手写循环。"},
		{Key: "hashcat", Desc: "用于在已授权范围内对已取得的哈希做离线恢复。Bash 说明里已列出时优先用它，不要为同一类恢复手写爆破脚本。"},
		{Key: "john", Desc: "用于在已授权范围内对已取得的哈希或口令材料做离线恢复。Bash 说明里已列出时优先用它，不要为同一类恢复手写爆破脚本。"},
		{Key: "katana", Desc: "用于 Web 爬取与链接、端点发现。Bash 说明里已列出时优先用它，不要为同一类爬取手写爬虫循环。"},
		{Key: "httpx", Desc: "用于对一批目标做 HTTP 探活、状态与基础指纹。Bash 说明里已列出时优先用它，不要为同一类探活手写 curl 循环。"},
		{Key: "jq", Desc: "用于在 Bash 里解析和筛选 JSON。Bash 说明里已列出时优先用它，不要为同一类处理再写一层 Python 包装。"},
		{Key: "nxc", Desc: "已授权内网按需使用的环境声明，不是默认必装工具，也不写入 packaging 必装清单。能力边界是在已授权内网环境下检查常见 Windows/SMB 等管理协议的认证与可见信息；仅当 Bash 说明里已列出且任务需要时使用。不要为同一类事手写协议脚本。"},
		{Key: "impacket-secretsdump", Desc: "已授权内网按需使用的环境声明，随镜像提供，在授权范围内按需使用。能力边界是在已授权前提下处理 Windows 凭据材料的转储或解析；仅当 Bash 说明里已列出且任务需要时使用。不要为同一类事手写协议脚本。"},
		{Key: "impacket-psexec", Desc: "已授权内网按需使用的环境声明，随镜像提供，在授权范围内按需使用。能力边界是在已授权前提下进行 Windows 远程执行；仅当 Bash 说明里已列出且任务需要时使用。不要为同一类事手写协议脚本。"},
		{Key: "impacket-wmiexec", Desc: "已授权内网按需使用的环境声明，随镜像提供，在授权范围内按需使用。能力边界是在已授权前提下经 WMI 进行 Windows 远程执行；仅当 Bash 说明里已列出且任务需要时使用。不要为同一类事手写协议脚本。"},
		{Key: "impacket-smbclient", Desc: "已授权内网按需使用的环境声明，随镜像提供，在授权范围内按需使用。能力边界是在已授权前提下访问或列举 SMB 共享；仅当 Bash 说明里已列出且任务需要时使用。不要为同一类事手写协议脚本。"},
		{Key: "impacket-GetUserSPNs", Desc: "已授权内网按需使用的环境声明，随镜像提供，在授权范围内按需使用。能力边界是在已授权前提下查询 Kerberos 服务主体（SPN）信息；仅当 Bash 说明里已列出且任务需要时使用。不要为同一类事手写协议脚本。"},
	}
}

// ShellHintByKey returns the catalog entry for an exact command name, if any.
func ShellHintByKey(key string) (ShellHintSeed, bool) {
	for _, s := range ShellHintSeeds() {
		if s.Key == key {
			return s, true
		}
	}
	return ShellHintSeed{}, false
}
