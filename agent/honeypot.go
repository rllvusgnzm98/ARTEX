package agent

// 蜜罐静态签名识别在 agent 侧的挂点与 planner 处置纪律。
// - evaluateHoneypot: service 资产落库后跑 honeydetect 评估,score>0 时回写
//   honeypot_score/evidence,并写一条 fact(planner 态势可见)。全部 best-effort。
// - plannerHoneypotRules: 代码固定尾,追加在 planner system,不可被 DB 正文覆盖。
//   这是提示词纪律,不是默认硬闸;硬拦截若要做另开刀。

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/honeydetect"
)

// plannerHoneypotRules 是 planner 的蜜罐处置纪律:误报优先于漏报。
// 双信号才封锁该方向,单信号只降级交互;疑似蜜罐上不投递、不爆破。
const plannerHoneypotRules = `

**蜜罐处置纪律(不可编辑)**:
1. 态势里的 honeypot_assets 是静态签名命中的疑似蜜罐资产,属【单信号】:对它们**降级交互**——只用被动/只读手段继续观察,**不投递工具/载荷、不爆破、不利用**;仅凭单信号不得封锁方向。
2. 只有【双信号命中】(静态签名 + 行为/登录后特征,如 /proc/meminfo 连读不变、ps 时间戳固定、egress 回连声称成功却无流量到达)才判定确认蜜罐,**停止在该方向派意图**;涉及反制型(MySQL 读客户端文件、客户端诱导)时,连客户端连接都不发起。
3. 疑似蜜罐资产上已有意图在跑的,让它以最低交互收尾,不追加高价值动作;侦察与利用资源优先投向无蜜罐信号的方向。
4. 全阴性【不等于】非蜜罐(高交互/加固蜜罐对自动化识别免疫):对无信号目标同样不投放高价值 exploit、控制噪声。`

// HoneypotDisposition 是单双信号契约的代码固定值(误报优先于漏报)。
// 本刀只用它锁死纪律,不把它做成 preToolUse 默认硬闸。
const (
	HoneypotDispositionNone           = "none"
	HoneypotDispositionDegrade        = "degrade"
	HoneypotDispositionBlockDirection = "block-direction"
)

// HoneypotDispositionFor 把静态签名命中与行为信号映射为处置档:
// 单信号只降级,双信号才封锁该方向。
func HoneypotDispositionFor(staticHit, behavioralHit bool) string {
	if staticHit && behavioralHit {
		return HoneypotDispositionBlockDirection
	}
	if staticHit || behavioralHit {
		return HoneypotDispositionDegrade
	}
	return HoneypotDispositionNone
}

func honeypotConfidence(score float64) string {
	if score >= 0.9 {
		return "high"
	}
	return "medium"
}

// serviceViewFromItem 把 insert_assets 观测字段填进 ServiceView。
// HTTP 用 URL 端口；非 HTTP 用显式 port。body/证书不落独立列，只参与评估。
func serviceViewFromItem(item assetInputItem, httpService bool) honeydetect.ServiceView {
	port := item.Port
	if httpService {
		if p := urlPort(item.URL); p != 0 {
			port = p
		}
	}
	return honeydetect.ServiceView{
		Port:        port,
		Banner:      item.Banner,
		Title:       item.PageTitle,
		Body:        item.Body,
		CertSubject: item.CertSubject,
		CertIssuer:  item.CertIssuer,
	}
}

// ServiceViewFromFields 供控制台/API upsert 复用同一套评估输入（字段名对齐 ServiceView）。
func ServiceViewFromFields(url string, port int, banner, title, body, certSubject, certIssuer string) honeydetect.ServiceView {
	if url != "" {
		if p := urlPort(url); p != 0 {
			port = p
		}
	}
	return honeydetect.ServiceView{
		Port:        port,
		Banner:      banner,
		Title:       title,
		Body:        body,
		CertSubject: certSubject,
		CertIssuer:  certIssuer,
	}
}

// ApplyHoneypotEvaluation 用既有 honeydetect 签名库评估，命中则回写
// honeypot_score / honeypot_evidence。不是默认硬闸，不影响资产登记成败。
func ApplyHoneypotEvaluation(as *db.AssetStore, assetID int64, v honeydetect.ServiceView) (score float64, evidence []string) {
	if assetID <= 0 {
		return 0, nil
	}
	score, evidence = honeydetect.Evaluate(v)
	if score > 0 && as != nil {
		_ = as.SetHoneypotScore(assetID, score, evidence)
	}
	return score, evidence
}

// evaluateHoneypot 是 service 资产落库后的签名评分挂点。best-effort:
// 任何失败都只影响蜜罐标记,不影响资产登记。命中时再写一条 fact。
func (t *ToolSet) evaluateHoneypot(assetID int64, v honeydetect.ServiceView) {
	score, evidence := ApplyHoneypotEvaluation(t.as, assetID, v)
	if score <= 0 {
		return
	}
	if t.ts == nil || t.taskID <= 0 {
		return
	}
	conf := honeypotConfidence(score)
	payload := map[string]any{
		"summary":             fmt.Sprintf("疑似蜜罐资产 #%d:静态签名命中(score=%.2f, %s)", assetID, score, conf),
		"detail":              "命中签名: " + strings.Join(evidence, "; ") + "。处置:单信号只降级交互(被动/只读),不投递/不爆破/不利用;双信号命中才封锁方向。",
		"confidence":          "observed",
		"honeypot_score":      score,
		"honeypot_confidence": conf,
		"honeypot_signatures": evidence,
	}
	_, _ = t.ts.AddNode(db.KindFact, payload, 5, "confirmed", t.worker, []int64{assetID})
}

// urlPort 从 URL 取端口(缺省按 scheme),取不到返回 0。
func urlPort(raw string) int {
	u, err := url.Parse(raw)
	if err != nil {
		return 0
	}
	if p := u.Port(); p != "" {
		var n int
		if _, err := fmt.Sscanf(p, "%d", &n); err == nil {
			return n
		}
		return 0
	}
	switch strings.ToLower(u.Scheme) {
	case "http":
		return 80
	case "https":
		return 443
	}
	return 0
}
