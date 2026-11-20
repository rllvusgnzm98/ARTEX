package db

// 批 6 L1 蜜罐静态签名识别(HONEYPOT-DETECTION-DESIGN.md 二·L1):db 层只做
// 存取,签名匹配逻辑全部在 honeydetect 包。评分与证据由 server/agent 挂点在
// service 资产落库后写入;planner 注入与 UI 经这里读出。

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// SetHoneypotScore 写入资产的蜜罐评分与证据。重复评估取更高分,证据(JSON 数组
// 文本)合并去重;评分不升且证据无新增时不动行(幂等)。
func (s *AssetStore) SetHoneypotScore(assetID int64, score float64, evidence []string) error {
	if assetID <= 0 || score <= 0 {
		return nil
	}
	var curScore float64
	var curEvidence string
	if err := s.db.QueryRow(
		`SELECT honeypot_score, COALESCE(honeypot_evidence,'') FROM assets WHERE id = $1`,
		assetID).Scan(&curScore, &curEvidence); err != nil {
		return err
	}
	merged := MergeHoneypotEvidence(curEvidence, evidence)
	if score < curScore {
		score = curScore // 取更高分
	}
	if score == curScore && merged == curEvidence {
		return nil
	}
	_, err := s.db.Exec(
		`UPDATE assets SET honeypot_score = $2, honeypot_evidence = $3 WHERE id = $1`,
		assetID, score, merged)
	return err
}

// MergeHoneypotEvidence 把新命中证据合并进已有证据(JSON 数组文本),去重;
// 旧值不是合法 JSON 数组时按无旧值处理(不丢新证据)。
func MergeHoneypotEvidence(existing string, add []string) string {
	var items []string
	if existing != "" {
		_ = json.Unmarshal([]byte(existing), &items)
	}
	seen := map[string]bool{}
	for _, it := range items {
		seen[it] = true
	}
	for _, it := range add {
		if it == "" || seen[it] {
			continue
		}
		seen[it] = true
		items = append(items, it)
	}
	if len(items) == 0 {
		return ""
	}
	b, err := json.Marshal(items)
	if err != nil {
		return existing
	}
	return string(b)
}

// HoneypotAsset 是 planner 注入用的一行疑似蜜罐资产。
type HoneypotAsset struct {
	ID       int64
	Label    string // url,否则 host:port
	Score    float64
	Evidence string // JSON 数组文本
}

// HoneypotAssetsByTask 列出本任务 score>0 的资产,按评分降序,limit<=0 默认 20。
func (s *AssetStore) HoneypotAssetsByTask(taskID int64, limit int) ([]HoneypotAsset, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := s.db.Query(`
SELECT id, COALESCE(url,''), COALESCE(domain,''), COALESCE(ip,''), port,
       honeypot_score, COALESCE(honeypot_evidence,'')
FROM assets
WHERE $1 = ANY(task_ids) AND honeypot_score > 0
ORDER BY honeypot_score DESC, id DESC
LIMIT $2`, taskID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HoneypotAsset
	for rows.Next() {
		var h HoneypotAsset
		var urlv, domain, ip string
		var port *int
		if err := rows.Scan(&h.ID, &urlv, &domain, &ip, &port, &h.Score, &h.Evidence); err != nil {
			return nil, err
		}
		h.Label = honeypotLabel(urlv, domain, ip, port)
		out = append(out, h)
	}
	return out, rows.Err()
}

func honeypotLabel(urlv, domain, ip string, port *int) string {
	switch {
	case urlv != "":
		return urlv
	case port != nil:
		host := domain
		if host == "" {
			host = ip
		}
		return fmt.Sprintf("%s:%d", host, *port)
	default:
		if domain != "" {
			return domain
		}
		return ip
	}
}

// HoneypotViewsByIDs 返回这些 id 的蜜罐视图(含 score=0,调用方自行过滤)。
// 顺序与 ids 一致,重复 id 只出现一次,不存在的 id 跳过。ids 为空返回 nil。
func (s *AssetStore) HoneypotViewsByIDs(ids []int64) ([]HoneypotAsset, error) {
	if s == nil || len(ids) == 0 {
		return nil, nil
	}
	placeholders := make([]string, len(ids))
	args := make([]any, len(ids))
	for i, id := range ids {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = id
	}
	q := `
SELECT id, COALESCE(url,''), COALESCE(domain,''), COALESCE(ip,''), port,
       honeypot_score, COALESCE(honeypot_evidence,'')
FROM assets WHERE id IN (` + strings.Join(placeholders, ",") + `)`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byID := map[int64]HoneypotAsset{}
	for rows.Next() {
		h, err := scanHoneypotAsset(rows)
		if err != nil {
			return nil, err
		}
		byID[h.ID] = h
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var out []HoneypotAsset
	seen := map[int64]bool{}
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		if h, ok := byID[id]; ok {
			out = append(out, h)
		}
	}
	return out, nil
}

// HoneypotViewsByHost 返回本任务里 host 精确命中的资产(含 score=0)。
// host 与 ip / domain / root_domain 或 URL hostname 相等才算,不做子串包含。
func (s *AssetStore) HoneypotViewsByHost(taskID int64, host string) ([]HoneypotAsset, error) {
	if s == nil || taskID <= 0 {
		return nil, nil
	}
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" {
		return nil, nil
	}
	rows, err := s.db.Query(`
SELECT id, COALESCE(url,''), COALESCE(domain,''), COALESCE(ip,''), COALESCE(root_domain,''),
       port, honeypot_score, COALESCE(honeypot_evidence,'')
FROM assets
WHERE $1 = ANY(task_ids)
  AND (
    lower(COALESCE(ip,'')) = $2
    OR lower(COALESCE(domain,'')) = $2
    OR lower(COALESCE(root_domain,'')) = $2
    OR strpos(lower(COALESCE(url,'')), $2) > 0
  )
ORDER BY honeypot_score DESC, id DESC`, taskID, host)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HoneypotAsset
	for rows.Next() {
		var h HoneypotAsset
		var urlv, domain, ip, root string
		var port *int
		if err := rows.Scan(&h.ID, &urlv, &domain, &ip, &root, &port, &h.Score, &h.Evidence); err != nil {
			return nil, err
		}
		if !honeypotHostMatch(host, urlv, domain, ip, root) {
			continue
		}
		h.Label = honeypotLabel(urlv, domain, ip, port)
		out = append(out, h)
	}
	return out, rows.Err()
}

func scanHoneypotAsset(rows interface{ Scan(...any) error }) (HoneypotAsset, error) {
	var h HoneypotAsset
	var urlv, domain, ip string
	var port *int
	err := rows.Scan(&h.ID, &urlv, &domain, &ip, &port, &h.Score, &h.Evidence)
	if err != nil {
		return HoneypotAsset{}, err
	}
	h.Label = honeypotLabel(urlv, domain, ip, port)
	return h, nil
}

func honeypotHostMatch(host, urlv, domain, ip, root string) bool {
	if host == "" {
		return false
	}
	if strings.EqualFold(ip, host) || strings.EqualFold(domain, host) || strings.EqualFold(root, host) {
		return true
	}
	if urlv == "" {
		return false
	}
	u, err := url.Parse(urlv)
	if err != nil {
		return false
	}
	return strings.EqualFold(strings.TrimSuffix(u.Hostname(), "."), host)
}
