package honeydetect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeSigs 在临时目录落一份签名文件并返回路径。
func writeSigs(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "honeypot.json")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

const testSigs = `{"signatures":[
  {"name":"cowrie_default_ssh_banner","product":"Cowrie","confidence":0.99,"source":"t","match":{"banner_substr":"OpenSSH_6.0p1 Debian-4+deb7u2"}},
  {"name":"hfish_default_web_xjs","product":"HFish","confidence":0.85,"source":"t","match":{"port":8080,"http_body_substr":"x.js"}},
  {"name":"dionaea_default_cert_subject","product":"Dionaea","confidence":0.95,"source":"t","match":{"cert_subject_substr":"Nepenthes Development Team"}},
  {"name":"empty_match_never_hits","product":"X","confidence":1.0,"source":"t","match":{}}
]}`

func TestEvaluateHitsHighestConfidence(t *testing.T) {
	e := NewEngine(writeSigs(t, testSigs))
	score, ev := e.Evaluate(ServiceView{Port: 22, Banner: "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2"})
	if score != 0.99 || len(ev) != 1 {
		t.Fatalf("cowrie banner: score=%v ev=%v", score, ev)
	}
}

func TestEvaluateAllConditionsMustMatch(t *testing.T) {
	e := NewEngine(writeSigs(t, testSigs))
	if score, _ := e.Evaluate(ServiceView{Port: 80, Body: "see x.js"}); score != 0 {
		t.Fatalf("port mismatch should not hit, score=%v", score)
	}
	if score, _ := e.Evaluate(ServiceView{Port: 8080, Body: "see x.js"}); score != 0.85 {
		t.Fatalf("port+body hit: score=%v", score)
	}
}

func TestEvaluateCertAndCaseFold(t *testing.T) {
	e := NewEngine(writeSigs(t, testSigs))
	score, _ := e.Evaluate(ServiceView{CertSubject: "C=DE, CN=nepenthes development team, O=dionaea.carnivore.it"})
	if score != 0.95 {
		t.Fatalf("cert subject case-fold hit: score=%v", score)
	}
}

func TestEvaluateNoMatch(t *testing.T) {
	e := NewEngine(writeSigs(t, testSigs))
	score, ev := e.Evaluate(ServiceView{Port: 22, Banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"})
	if score != 0 || ev != nil {
		t.Fatalf("no match: score=%v ev=%v", score, ev)
	}
}

// TestMissingOrCorruptFileDegradesQuietly：文件缺失或损坏时安静回落到内嵌库，不报错、不空载。
func TestMissingOrCorruptFileDegradesQuietly(t *testing.T) {
	banner := "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2"
	e := NewEngine(filepath.Join(t.TempDir(), "nonexistent.json"))
	score, _ := e.Evaluate(ServiceView{Banner: banner})
	if score != 0.99 {
		t.Fatalf("missing file should fall back to embedded Cowrie sig, got %v", score)
	}
	e2 := NewEngine(writeSigs(t, `{not json`))
	score, _ = e2.Evaluate(ServiceView{Banner: banner})
	if score != 0.99 {
		t.Fatalf("corrupt file should fall back to embedded Cowrie sig, got %v", score)
	}
}

func TestHotReloadByMtime(t *testing.T) {
	p := writeSigs(t, `{"signatures":[]}`)
	e := NewEngine(p)
	if score, _ := e.Evaluate(ServiceView{Banner: "OpenSSH_6.0p1 Debian-4+deb7u2"}); score != 0 {
		t.Fatalf("empty sigs should score 0, got %v", score)
	}
	if err := os.WriteFile(p, []byte(testSigs), 0o644); err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(p, later, later); err != nil {
		t.Fatal(err)
	}
	if score, _ := e.Evaluate(ServiceView{Banner: "OpenSSH_6.0p1 Debian-4+deb7u2"}); score != 0.99 {
		t.Fatalf("hot reload should pick up new sigs, score=%v", score)
	}
}

func TestBundledSignaturesLoad(t *testing.T) {
	sigs := parseSignatures(embeddedSignatures)
	if len(sigs) == 0 {
		t.Fatal("内嵌签名库为空或解析失败")
	}
	if len(sigs) != 11 {
		t.Fatalf("内嵌公开开源蜜罐默认指纹应为 11 条, got %d", len(sigs))
	}
	allowed := map[string]bool{
		"Cowrie": true, "OpenCanary": true, "Kippo": true,
		"Glastopf": true, "HFish": true, "Dionaea": true,
	}
	for _, s := range sigs {
		if s.Name == "" || s.Product == "" || s.Source == "" {
			t.Fatalf("签名缺 name/product/source: %+v", s)
		}
		if !allowed[s.Product] {
			t.Fatalf("签名 %s 产品 %q 不是本刀允许的公开开源蜜罐默认指纹", s.Name, s.Product)
		}
		if s.Confidence < 0.85 || s.Confidence > 0.99 {
			t.Fatalf("签名 %s 置信度 %.2f 不在 0.85-0.99 区间", s.Name, s.Confidence)
		}
		if s.Match.empty() {
			t.Fatalf("签名 %s 没有任何匹配条件", s.Name)
		}
		blob := strings.ToLower(s.Name + " " + s.Product)
		for _, bad := range []string{"flag", "ctf", "tsec", "红日", "challenge-", "题号"} {
			if strings.Contains(blob, bad) {
				t.Fatalf("不得写入靶场/题号特化指纹: %+v", s)
			}
		}
	}
	e := NewEngine(filepath.Join(t.TempDir(), "nonexistent.json"))
	score, _ := e.Evaluate(ServiceView{Port: 22, Banner: "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2"})
	if score != 0.99 {
		t.Fatalf("内嵌 Cowrie 签名未命中, score=%v", score)
	}
	score, _ = e.Evaluate(ServiceView{CertIssuer: "C=DE, CN=Nepenthes Development Team, O=dionaea.carnivore.it, OU=anv"})
	if score != 0.9 {
		t.Fatalf("内置 Dionaea issuer 签名未命中, score=%v", score)
	}
}

func TestWeakScoreAndNotBanner(t *testing.T) {
	body := `{"signatures":[
	  {"name":"w1","product":"X","confidence":0.95,"weak":true,"severity":"low","source":"t","match":{"banner_substr":"WEAK-ONE"}},
	  {"name":"w2","product":"X","confidence":0.85,"weak":true,"severity":"low","source":"t","match":{"banner_substr":"WEAK-TWO"}},
	  {"name":"strong","product":"X","confidence":0.99,"severity":"high","source":"t","match":{"banner_substr":"STRONG-HIT"}},
	  {"name":"mid","product":"X","confidence":0.85,"severity":"medium","source":"t","match":{"banner_substr":"MID-HIT"}},
	  {"name":"excluded","product":"X","confidence":0.99,"source":"t","match":{"banner_substr":"READY","not_banner_substr":"vsftpd"}}
	]}`
	e := NewEngine(writeSigs(t, body))

	score, ev := e.Evaluate(ServiceView{Banner: "banner WEAK-ONE"})
	if score >= highScore || len(ev) != 1 {
		t.Fatalf("single weak must not score high: score=%v ev=%v", score, ev)
	}
	hits := e.EvaluateHits(ServiceView{Banner: "banner WEAK-ONE"})
	if len(hits) != 1 || !hits[0].Weak || hits[0].Severity != "low" || hits[0].Name != "w1" {
		t.Fatalf("EvaluateHits single weak: %+v", hits)
	}

	score, ev = e.Evaluate(ServiceView{Banner: "WEAK-ONE plus WEAK-TWO"})
	if score < highScore || len(ev) != 2 {
		t.Fatalf("two weak signatures should score high: score=%v ev=%v", score, ev)
	}

	if score, _ := e.Evaluate(ServiceView{Banner: "STRONG-HIT"}); score != 0.99 {
		t.Fatalf("strong signature keeps its confidence, score=%v", score)
	}
	if score, _ := e.Evaluate(ServiceView{Banner: "MID-HIT"}); score != 0.85 {
		t.Fatalf("sub-high strong signature keeps 0.85, score=%v", score)
	}
	if score, ev := e.Evaluate(ServiceView{Banner: "STRONG-HIT WEAK-ONE"}); score != 0.99 || len(ev) != 2 {
		t.Fatalf("strong plus weak uses the strong score: score=%v ev=%v", score, ev)
	}

	if score, _ := e.Evaluate(ServiceView{Banner: "220 READY vsftpd"}); score != 0 {
		t.Fatalf("not_banner_substr should exclude, score=%v", score)
	}
	if score, _ := e.Evaluate(ServiceView{Banner: "220 READY"}); score != 0.99 {
		t.Fatalf("banner without the excluded token should hit, score=%v", score)
	}
	if hits := e.EvaluateHits("not a view"); hits != nil {
		t.Fatalf("non-view EvaluateHits = %+v", hits)
	}
}
