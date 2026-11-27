package guard

import (
	"reflect"
	"testing"
)

func TestExtractHosts(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want []string
	}{
		{"curl URL", `curl https://api.example.com:8443/v1/login`, []string{"api.example.com"}},
		{"curl URL 管道", `curl -s http://a.example.com/ | grep x`, []string{"a.example.com"}},
		{"nmap IP", `nmap -sV -p 80,443 10.0.0.7`, []string{"10.0.0.7"}},
		{"nmap CIDR 字面量按主机对待", `nmap 192.168.1.0/24`, nil}, // 含 / 的字面量不提取(保守)
		{"ssh user@host", `ssh admin@jump.example.com`, []string{"jump.example.com"}},
		{"ssh user@ip", `ssh root@172.16.0.5`, []string{"172.16.0.5"}},
		{"nc host port", `nc 10.0.0.9 4444`, []string{"10.0.0.9"}},
		{"host:port 参数", `ncat example.com 443`, []string{"example.com"}},
		{"ping 主机名", `ping db.internal.example.com`, []string{"db.internal.example.com"}},
		{"wget URL", `wget http://files.example.com/a.sh -O /tmp/a.sh`, []string{"files.example.com"}},
		{"多个目标", `curl http://one.example.com/ && nmap 10.1.1.1 && ssh u@two.example.com`,
			[]string{"one.example.com", "10.1.1.1", "two.example.com"}},
		{"无目标命令", `ls -la /tmp`, nil},
		{"无目标命令2", `cat /etc/passwd | grep root`, nil},
		{"flag 值不当目标", `nmap -iL targets.txt`, nil},
		{"flag 值不当目标2", `curl -H example.com http://real.example.com/`, []string{"real.example.com"}},
		{"独立 IP 字面量", `echo 8.8.8.8`, []string{"8.8.8.8"}},
		{"工具路径全名", `/usr/bin/nmap 10.2.2.2`, []string{"10.2.2.2"}},
		{"sudo 前缀", `sudo nmap 10.3.3.3`, []string{"10.3.3.3"}},
		{"去重", `ping 10.0.0.1; nmap 10.0.0.1`, []string{"10.0.0.1"}},
		{"空命令", ``, nil},
	}
	for _, c := range cases {
		got := ExtractHosts(c.cmd)
		if len(got) == 0 {
			got = nil
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: ExtractHosts(%q) = %v, want %v", c.name, c.cmd, got, c.want)
		}
	}
}

func TestExtractHostsShellHintCLIs(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want []string
	}{
		{"ffuf -u URL", `ffuf -u https://api.example.com/FUZZ -w /tmp/words.txt`, []string{"api.example.com"}},
		{"feroxbuster --url", `feroxbuster --url https://files.example.com/`, []string{"files.example.com"}},
		{"gobuster dir -u", `gobuster dir -u https://www.example.com/ -w /tmp/words.txt`, []string{"www.example.com"}},
		{"gobuster dns -d", `gobuster dns -d internal.example.com`, []string{"internal.example.com"}},
		{"sqlmap -u", `sqlmap -u https://app.example.com/item`, []string{"app.example.com"}},
		{"nuclei -u URL", `nuclei -u https://scan.example.com`, []string{"scan.example.com"}},
		{"nuclei -u 裸主机", `nuclei -u scan.example.com`, []string{"scan.example.com"}},
		{"whatweb 位置参数", `whatweb shop.example.com`, []string{"shop.example.com"}},
		{"commix -u", `commix -u https://app.example.com/page`, []string{"app.example.com"}},
		{"katana --url=", `katana --url=https://site.example.com`, []string{"site.example.com"}},
		{"nxc smb IP", `nxc smb 10.0.0.7`, []string{"10.0.0.7"}},
		{"nxc smb 主机名", `nxc smb dc.example.com`, []string{"dc.example.com"}},
		{"nxc CIDR 仍不提取", `nxc smb 192.168.1.0/24`, nil},
		{"impacket-psexec user@ip", `impacket-psexec administrator@10.0.0.8`, []string{"10.0.0.8"}},
		{"impacket-wmiexec user@host", `impacket-wmiexec user@win.example.com`, []string{"win.example.com"}},
		{"impacket-smbclient", `impacket-smbclient user@10.0.0.9`, []string{"10.0.0.9"}},
		{"impacket-secretsdump", `impacket-secretsdump user@dc.example.com`, []string{"dc.example.com"}},
		{"impacket-GetUserSPNs -dc-ip", `impacket-GetUserSPNs example/user -dc-ip 10.0.0.10`, []string{"10.0.0.10"}},
		{"工具路径 + ffuf", `/usr/bin/ffuf -u https://api.example.com/`, []string{"api.example.com"}},
		{"sudo nxc", `sudo nxc smb 10.3.3.3`, []string{"10.3.3.3"}},
		{"curl -u 用户名不当目标", `curl -u admin:secret https://real.example.com/`, []string{"real.example.com"}},
	}
	for _, c := range cases {
		got := ExtractHosts(c.cmd)
		if len(got) == 0 {
			got = nil
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: ExtractHosts(%q) = %v, want %v", c.name, c.cmd, got, c.want)
		}
	}
}

func TestExtractHostsIgnoresLocalFilenamesRedirectsAndDownstreamCode(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want []string
	}{
		{
			"curl -o + grep",
			`curl -s http://10.0.164.137:3000/install -o install.html && grep -oE "x" install.html`,
			[]string{"10.0.164.137"},
		},
		{
			"curl redirect + cat",
			`curl -s http://10.0.164.137:3000/install > install.html && cat install.html`,
			[]string{"10.0.164.137"},
		},
		{
			"hydra -L -P wordlists",
			`hydra -L u.txt -P p.txt 10.0.164.136 telnet`,
			[]string{"10.0.164.136"},
		},
		{
			"downstream python urllib.parse",
			`curl http://10.0.164.137/ && python3 -c "import urllib.parse"`,
			[]string{"10.0.164.137"},
		},
		{
			"local file arg after curl",
			`curl -s http://10.0.164.136:3000/apps -o apps.html && grep foo layout.js`,
			[]string{"10.0.164.136"},
		},
	}
	for _, c := range cases {
		got := ExtractHosts(c.cmd)
		if len(got) == 0 {
			got = nil
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: ExtractHosts(%q) = %v, want %v", c.name, c.cmd, got, c.want)
		}
	}
}

func TestExtractHostsShellVarsAndNewReconCLIs(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want []string
	}{
		{"ip with shell var suffix", `curl "http://10.0.173.80$u"`, []string{"10.0.173.80"}},
		{"domain with brace var suffix", `curl "http://evil.com${path}"`, []string{"evil.com"}},
		{"pure shell var url", `curl "http://$h/api"`, nil},
		{"pure brace shell var host", `curl "http://${HOST}/api"`, nil},
		{"bare shell var token", `nmap $TARGET`, nil},
		{"naabu -host", `naabu -host sub.target.com -p 80,443`, []string{"sub.target.com"}},
		{"fscan -h", `fscan -h 10.0.0.5 -p 80,443`, []string{"10.0.0.5"}},
		{"gogo -i", `gogo -i 10.0.0.6 -p 80`, []string{"10.0.0.6"}},
	}
	for _, c := range cases {
		got := ExtractHosts(c.cmd)
		if len(got) == 0 {
			got = nil
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: ExtractHosts(%q) = %v, want %v", c.name, c.cmd, got, c.want)
		}
	}
}

func TestExtractHostsIgnoresNonNetworkSchemesAndSSHRemoteCommandArgs(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want []string
	}{
		{"php://output stream", `php -d phar.readonly=0 phpggc Laravel/RCE2 system id --phar phar -o php://output`, nil},
		{"nested php://filter in URL query", `curl -s "http://192.168.111.20:81/?page=php://filter/convert.base64-encode/resource=index.php"`, []string{"192.168.111.20"}},
		{"standalone php://filter in grep/python", `grep -o 'php://filter/resource=a.php' out.txt`, nil},
		{"phar://./ relative path", `php -r 'unlink("phar://./exploit.phar");'`, nil},
		{"file:// and data:// wrappers", `cat <(echo 'file:///etc/passwd data://text/plain;base64,SGVsbG8=')`, nil},
		{"ssh remote command tokens ignored", `ssh -i id_rsa -o StrictHostKeyChecking=no root@192.168.111.20 'python3 rce_run.py && sh build.sh && ping -c1 192.168.52.30'`, []string{"192.168.111.20", "192.168.52.30"}},
		{"ssh remote iptables words are not hosts", `ssh -i id_rsa root@192.168.111.20 "iptables -t filter -L OUTPUT"`, []string{"192.168.111.20"}},
		{"ssh -J proxy jump + remote URL", `ssh -J jump@10.0.0.1 root@10.0.0.2 'id; curl http://10.0.0.3/'`, []string{"10.0.0.3", "10.0.0.1", "10.0.0.2"}},
	}
	for _, c := range cases {
		got := ExtractHosts(c.cmd)
		if len(got) == 0 {
			got = nil
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: ExtractHosts(%q) = %v, want %v", c.name, c.cmd, got, c.want)
		}
	}
}

func TestExtractHostsRoEFalsePositiveCleanup(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want []string
	}{
		{
			"SOAP/XML xmlns namespaces and schema hosts ignored",
			`curl -s -X POST http://192.168.111.20:7001/wls-wsat/CoordinatorPortType -d '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:work="http://www.bea.com/2004/06/soap/workarea/" xmlns:custom="http://ns.vendor.internal/v1"><soapenv:Body/></soapenv:Envelope>'`,
			[]string{"192.168.111.20"},
		},
		{
			"Spring and Microsoft XML schema hosts ignored",
			`curl -s http://10.0.0.5:8080/api -d '<beans xmlns="http://www.springframework.org/schema/beans" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" xsi:schemaLocation="http://www.w3.org/2001/XMLSchema http://www.springframework.org/schema/beans/spring-beans.xsd"/>'`,
			[]string{"10.0.0.5"},
		},
		{
			"post-ex and script file extensions ignored",
			`curl http://10.0.0.5/ sam.save system.hiv urllib.parse lsass.dmp hklm.reg admin.kirbi krb5.ccache exploit.py invoke.ps1 agent.exe helper.dll Exploit.class run.log`,
			[]string{"10.0.0.5"},
		},
		{
			"netmask broadcast and unspecified IPs ignored",
			`ifconfig eth0 192.168.52.30 netmask 255.255.255.0 broadcast 255.255.255.255 && python3 -m http.server --bind 0.0.0.0 8000 && echo 0.0.0.0:8080 255.0.0.0`,
			[]string{"192.168.52.30"},
		},
		{
			"smbclient single-target reset with UNC share",
			`smbclient //192.168.52.30/C$ -U admin%pass -c "get flag.out secret.dat"`,
			[]string{"192.168.52.30"},
		},
		{
			"rpcclient single-target reset",
			`rpcclient -U admin%pass 192.168.52.30 -c "enumdomusers; queryuser foo.bar"`,
			[]string{"192.168.52.30"},
		},
		{
			"evil-winrm -i single-target reset",
			`evil-winrm -i 192.168.52.30 -u admin -p pass -s payload.out`,
			[]string{"192.168.52.30"},
		},
		{
			"nxc single-target reset after protocol subcommand and host",
			`nxc smb 192.168.52.30 -u admin -p pass -x "cmd /c type loot.out"`,
			[]string{"192.168.52.30"},
		},
		{
			"impacket prefixed tools single-target reset",
			`impacket-smbexec corp/admin:pass@dc.corp.local "cmd /c dir share.out"`,
			[]string{"dc.corp.local"},
		},
		{
			"impacket-wmiexec single-target reset",
			`impacket-wmiexec admin@10.0.0.8 "powershell -c Get-Item foo.bar"`,
			[]string{"10.0.0.8"},
		},
	}
	for _, c := range cases {
		got := ExtractHosts(c.cmd)
		if len(got) == 0 {
			got = nil
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: ExtractHosts(%q) = %v, want %v", c.name, c.cmd, got, c.want)
		}
	}
}
