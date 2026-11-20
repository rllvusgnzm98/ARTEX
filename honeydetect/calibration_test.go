package honeydetect

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestCalibrationRealBannersStayQuiet 锁住收紧后的误报边界:
// 常见真实 FTP/HTTP 横幅与 ajax.js 一类静态资源必须是 0 分;
// 签名原文(含 /x.js 与 OpenCanary 特征)必须命中。
func TestCalibrationRealBannersStayQuiet(t *testing.T) {
	e := NewEngine(filepath.Join(t.TempDir(), "missing.json"))

	cases := []struct {
		name      string
		view      ServiceView
		wantName  string // 非空:证据里必须有这条签名
		wantBelow bool   // 命中了,但单条弱签名不得进入 high
	}{
		{name: "vsftpd", view: ServiceView{Port: 21, Banner: "220 (vsFTPd 3.0.3)"}},
		{name: "proftpd", view: ServiceView{Port: 21, Banner: "220 ProFTPD 1.3.7a Server (Debian) [::ffff:192.0.2.10]"}},
		{name: "pure-ftpd", view: ServiceView{Port: 21, Banner: "220---------- Welcome to Pure-FTPd [privsep] [TLS] ----------"}},
		{name: "filezilla ftp", view: ServiceView{Port: 21, Banner: "220-FileZilla Server 1.8.1"}},
		{name: "iis ftp", view: ServiceView{Port: 21, Banner: "220 Microsoft FTP Service"}},
		{name: "iis http", view: ServiceView{Port: 80, Banner: "Microsoft-IIS/10.0"}},
		{name: "pyftpdlib", view: ServiceView{Port: 21, Banner: "220 pyftpdlib 1.5.7 ready."}},
		{name: "ajax.js script", view: ServiceView{Port: 8080, Body: `<script src="ajax.js"></script>`}},
		{name: "ajax.js path", view: ServiceView{Port: 8080, Body: `/static/ajax.js`}},
		{name: "real apache 2.2.22", view: ServiceView{Port: 80, Banner: "Apache/2.2.22 (Ubuntu)", Body: "<html>it works</html>"}},
		{name: "ftp ready wrong port", view: ServiceView{Port: 2121, Banner: "220 FTP server ready"}},

		{name: "hfish /x.js", view: ServiceView{Port: 8080, Body: `<script src="/x.js"></script>`}, wantName: "hfish_default_web_xjs"},
		{name: "opencanary ftp", view: ServiceView{Port: 21, Banner: "220 FTP server ready"}, wantName: "opencanary_default_ftp_banner", wantBelow: true},
		{name: "opencanary ssh", view: ServiceView{Port: 22, Banner: "SSH-2.0-OpenSSH_5.1p1 Debian-4"}, wantName: "opencanary_default_ssh_banner"},
		{name: "opencanary http skin", view: ServiceView{Port: 80, Banner: "Apache/2.2.22 (Ubuntu)", Body: `<div id="sds-login"></div>`}, wantName: "opencanary_default_http_server"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			score, ev := e.Evaluate(c.view)
			hits := e.EvaluateHits(c.view)
			blob := strings.Join(ev, ";")
			if c.wantName == "" {
				if score != 0 || ev != nil || len(hits) != 0 {
					t.Fatalf("real service must score 0, score=%v ev=%v hits=%+v", score, ev, hits)
				}
				return
			}
			if score <= 0 || !strings.Contains(blob, c.wantName) {
				t.Fatalf("signature string must hit %s, score=%v ev=%v", c.wantName, score, ev)
			}
			found := false
			for _, h := range hits {
				if h.Name == c.wantName {
					found = true
					if c.wantBelow && (!h.Weak || score >= highScore) {
						t.Fatalf("single weak hit must stay below high: score=%v hit=%+v", score, h)
					}
				}
			}
			if !found {
				t.Fatalf("EvaluateHits missing %s: %+v", c.wantName, hits)
			}
		})
	}
}
