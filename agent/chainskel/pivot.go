package chainskel

import (
	"encoding/json"
	"strings"
)

// pivotMarker 是骨架行里"转向"条目的字段标记(9 类骨架统一为
// "- 场景:...|判据:...|转向:..." 的蒸馏格式)。
const pivotMarker = "转向:"

// PivotHints 从类别骨架中抽出"转向"类条目,拼成停滞干预消息里的类别化转向
// 建议段:tags 优先(规整+合法性过滤,至多 MaxTagsPerIntent 个),空时回退
// summary 关键词匹配(Match);每个命中类别取前 max 条"转向:"后的内容。
// 无匹配类别、骨架缺失、或骨架里抽不到转向条目时返回 ""(调用方用通用措辞)。
func PivotHints(tags []string, summary string, max int) string {
	if max <= 0 {
		return ""
	}
	var cats []string
	for _, t := range NormalizeChainTags(tags) {
		if Valid(t) {
			cats = append(cats, t)
		}
		if len(cats) >= MaxTagsPerIntent {
			break
		}
	}
	if len(cats) == 0 {
		cats = Match(summary)
	}
	if len(cats) == 0 {
		return ""
	}
	var lines []string
	for _, c := range cats {
		sk, ok := Skeleton(c)
		if !ok {
			continue // 骨架缺失:静默跳过
		}
		n := 0
		for _, line := range strings.Split(sk, "\n") {
			idx := strings.Index(line, pivotMarker)
			if idx < 0 {
				continue
			}
			hint := strings.TrimSpace(line[idx+len(pivotMarker):])
			if hint == "" {
				continue
			}
			lines = append(lines, "["+c+"] "+hint)
			n++
			if n >= max {
				break
			}
		}
	}
	if len(lines) == 0 {
		return ""
	}
	return "同类场景的可选转向路径(摘自反问决策链骨架,按本意图攻击面选取,逐条评估是否适用):\n- " +
		strings.Join(lines, "\n- ")
}

// PivotHintsForIntent 是 PivotHints 的意图 payload 入口(server/engine 接线用):
// 从 payload 解出 chain_tags/summary 后走同一逻辑;payload 解析失败返回 ""。
func PivotHintsForIntent(payload json.RawMessage, max int) string {
	var p struct {
		Summary   string   `json:"summary"`
		ChainTags []string `json:"chain_tags"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return ""
	}
	return PivotHints(p.ChainTags, p.Summary, max)
}

func RefsGuideForIntent(_ json.RawMessage) string { return "" }
