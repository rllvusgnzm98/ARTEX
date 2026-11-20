package agent

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestInsertAssetsSchemaExposesHoneypotObservationFields(t *testing.T) {
	ts := NewToolSet(nil, "")
	schema := ts.insertAssets().InputSchema()
	props, _ := schema["properties"].(map[string]any)
	assets, _ := props["assets"].(map[string]any)
	items, _ := assets["items"].(map[string]any)
	iprops, _ := items["properties"].(map[string]any)
	for _, key := range []string{"banner", "body", "cert_subject", "cert_issuer"} {
		if iprops[key] == nil {
			t.Fatalf("insert_assets 对外 schema 缺少 %s", key)
		}
	}
}

func readHoneypot(t *testing.T, d *db.DB, id int64) (score float64, evidence string) {
	t.Helper()
	if err := d.QueryRow(`SELECT honeypot_score, COALESCE(honeypot_evidence,'') FROM assets WHERE id=$1`, id).Scan(&score, &evidence); err != nil {
		t.Fatalf("read honeypot: %v", err)
	}
	return score, evidence
}

func firstResultID(t *testing.T, out map[string]any) int64 {
	t.Helper()
	if errs, _ := out["errors"].([]any); len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	results, _ := out["results"].([]any)
	if len(results) == 0 {
		t.Fatal("no results")
	}
	row, _ := results[0].(map[string]any)
	id, _ := row["id"].(float64)
	if id == 0 {
		t.Fatalf("missing id: %#v", row)
	}
	return int64(id)
}

func TestInsertAssetsHoneypotEvalUsesBodyAndCert(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("honeypot eval fields fixture", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)

	es := d.Exploration(task.ExplorationID)
	ts := NewToolSet(es, "fixture")
	ts.SetAssetStore(d.Assets(), d.Companies())
	ts.SetTaskID(task.ID)

	// 合成观测只使用已有公开签名中的子串，不是攻击步骤。
	const glastopfURL = "http://203.0.113.80/"
	const hfishURL = "http://203.0.113.81:8080/"
	const dionaeaIP = "203.0.113.82"
	const bannerOnlyIP = "203.0.113.83"
	const titleOnlyURL = "http://203.0.113.84/"
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM assets WHERE url IN ($1,$2,$3) OR ip IN ($4,$5)`, glastopfURL, hfishURL, titleOnlyURL, dionaeaIP, bannerOnlyIP)
	})

	glastopf := callInsertAssets(t, ts, map[string]any{
		"assets": []any{map[string]any{
			"type": "service",
			"url":  glastopfURL,
			"body": "index of My Resource/ (fixture page)",
		}},
	})
	gid := firstResultID(t, glastopf)
	gScore, gEv := readHoneypot(t, d, gid)
	if gScore < 0.89 || !strings.Contains(gEv, "glastopf_default_page") {
		t.Fatalf("依赖 body 的 Glastopf 签名应在官方挂点命中: score=%v ev=%s", gScore, gEv)
	}

	hfish := callInsertAssets(t, ts, map[string]any{
		"assets": []any{map[string]any{
			"type": "service",
			"url":  hfishURL,
			"body": "login form includes /x.js (fixture)",
		}},
	})
	hid := firstResultID(t, hfish)
	hScore, hEv := readHoneypot(t, d, hid)
	if hScore < 0.84 || !strings.Contains(hEv, "hfish_default_web_xjs") {
		t.Fatalf("依赖 body+端口 的 HFish 签名应命中: score=%v ev=%s", hScore, hEv)
	}

	dionaea := callInsertAssets(t, ts, map[string]any{
		"assets": []any{map[string]any{
			"type":         "service",
			"service_name": "tls",
			"ip":           dionaeaIP,
			"port":         443,
			"cert_subject": "C=DE, CN=Nepenthes Development Team, O=dionaea.carnivore.it",
		}},
	})
	did := firstResultID(t, dionaea)
	dScore, dEv := readHoneypot(t, d, did)
	if dScore < 0.94 || !strings.Contains(dEv, "dionaea_default_cert_subject") {
		t.Fatalf("依赖证书的 Dionaea 签名应命中: score=%v ev=%s", dScore, dEv)
	}

	// 只传 Port/Banner：既有 banner 签名仍能命中
	bannerOnly := callInsertAssets(t, ts, map[string]any{
		"assets": []any{map[string]any{
			"type":         "service",
			"service_name": "ssh",
			"ip":           bannerOnlyIP,
			"port":         22,
			"banner":       "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2",
		}},
	})
	bid := firstResultID(t, bannerOnly)
	bScore, bEv := readHoneypot(t, d, bid)
	if bScore < 0.98 || !strings.Contains(bEv, "cowrie_default_ssh_banner") {
		t.Fatalf("只传 Port/Banner 时既有 banner 行为应保持: score=%v ev=%s", bScore, bEv)
	}

	// 只传 Title，无 body/证书：不得误命中 body/证书签名
	titleOnly := callInsertAssets(t, ts, map[string]any{
		"assets": []any{map[string]any{
			"type":       "service",
			"url":        titleOnlyURL,
			"page_title": "Welcome",
		}},
	})
	tid := firstResultID(t, titleOnly)
	tScore, tEv := readHoneypot(t, d, tid)
	if tScore != 0 || strings.Contains(tEv, "glastopf") || strings.Contains(tEv, "hfish") || strings.Contains(tEv, "dionaea") {
		t.Fatalf("只传 Title 时不应命中 body/证书签名: score=%v ev=%s", tScore, tEv)
	}

	facts, err := es.ListByKind(db.KindFact, 50)
	if err != nil {
		t.Fatal(err)
	}
	var sawGlastopf, sawHFish, sawDionaea, sawBanner bool
	for _, f := range facts {
		text := string(f.Payload)
		if strings.Contains(text, "glastopf_default_page") {
			sawGlastopf = true
		}
		if strings.Contains(text, "hfish_default_web_xjs") {
			sawHFish = true
		}
		if strings.Contains(text, "dionaea_default_cert_subject") {
			sawDionaea = true
		}
		if strings.Contains(text, "cowrie_default_ssh_banner") {
			sawBanner = true
		}
		if strings.Contains(text, "honeypot_score") && !strings.Contains(text, "疑似蜜罐") {
			// payload 应含分数字段；不要求特定格式以外的内容
		}
	}
	if !sawGlastopf || !sawHFish || !sawDionaea || !sawBanner {
		raw, _ := json.Marshal(facts)
		t.Fatalf("命中后应回写 fact: glastopf=%v hfish=%v dionaea=%v banner=%v payload=%s", sawGlastopf, sawHFish, sawDionaea, sawBanner, raw)
	}
}
