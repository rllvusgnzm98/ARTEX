package guard

import (
	"reflect"
	"testing"
)

func TestExtractBriefHosts(t *testing.T) {
	cases := []struct {
		name string
		text string
		want []string
	}{
		{
			"explicit GET instruction URL",
			`必须先 GET http://10.0.100.58 做 VPN 健康检测，然后再开始渗透。`,
			[]string{"10.0.100.58"},
		},
		{
			"https URL host with path and port",
			`目标 https://app.target-corp.cn:8443/login ，拿下后台。`,
			[]string{"app.target-corp.cn"},
		},
		{
			"bare IP with directive verb",
			`先扫描 192.168.111.20 确认存活。`,
			[]string{"192.168.111.20"},
		},
		{
			"bare IP with port and directive",
			`必须访问 10.0.100.58:8080 确认 VPN 健康。`,
			[]string{"10.0.100.58"},
		},
		{
			"english directive verbs",
			`You must curl 10.1.2.3 first, then probe the network.`,
			[]string{"10.1.2.3"},
		},
		{
			"IP without directive verb not collected",
			`目标网段里有一台 10.0.0.99。`,
			nil,
		},
		{
			"callback context excluded",
			`本机地址 10.8.0.5，攻击机回连地址 10.8.0.6，必须先访问 10.0.100.58 做检测。`,
			[]string{"10.0.100.58"},
		},
		{
			"example.com placeholder excluded",
			`参考示例 http://example.com/demo 的写法，然后扫描 10.0.0.7。`,
			[]string{"10.0.0.7"},
		},
		{
			"documentation IP placeholder excluded",
			`文档示例 192.0.2.1 和 203.0.113.9，先访问 10.0.100.58。`,
			[]string{"10.0.100.58"},
		},
		{
			"template variables excluded",
			`访问 http://{{TARGET_HOST}}/ 和 http://${IP}:8080/ 前请先确认。`,
			nil,
		},
		{
			"loopback and unspecified excluded",
			`先 curl http://127.0.0.1:8080/health 再检查 10.0.0.8。`,
			[]string{"10.0.0.8"},
		},
		{
			"no addresses at all",
			`这是一段没有任何地址的任务描述。`,
			nil,
		},
		{
			"dedup and order",
			`先访问 10.0.100.58，再 GET http://10.0.100.58/status，最后扫描 10.0.0.9。`,
			[]string{"10.0.100.58", "10.0.0.9"},
		},
		{
			"multiple URLs",
			`需要确认 http://vpn.lab.local/ 和 https://mail.lab.local/ 都可访问。`,
			[]string{"vpn.lab.local", "mail.lab.local"},
		},
		{
			"url trailing punctuation stripped",
			`必须先访问 http://10.0.100.58。然后再行动。`,
			[]string{"10.0.100.58"},
		},
		{
			"negated chinese URL and bare IP excluded",
			`目标 https://app.target-corp.cn/，严禁访问 https://prod.target-corp.cn/，不要扫描 10.0.0.66。`,
			[]string{"app.target-corp.cn"},
		},
		{
			"negated english out-of-scope URL excluded",
			`Audit https://staging.acme.test/; out of scope: https://billing.acme.test/, do not probe 10.9.9.9.`,
			[]string{"staging.acme.test"},
		},
		{
			"callback and OOB URL excluded",
			`攻击机回调地址 http://10.8.0.2:8787/o/test，OOB webhook https://oob.attacker.test/cb，请先访问 https://target.lab.local/。`,
			[]string{"target.lab.local"},
		},
	}
	for _, c := range cases {
		got := ExtractBriefHosts(c.text)
		if len(got) == 0 {
			got = nil
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: ExtractBriefHosts(%q) = %v, want %v", c.name, c.text, got, c.want)
		}
	}
}
