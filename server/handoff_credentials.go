// handoff 凭据继承：只带父任务自有、且与立足点相关的凭据。不复制 secret。
package server

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/Autumn-27/artex/db"
)

const (
	inheritUnverifiedEnv = "ARTEX_INHERIT_UNVERIFIED"
	maxInheritedCreds    = 20
)

// inheritCredentials 把父任务自有凭据里与子任务立足点相关的那些记到继承表。
// 默认只收 verified；ARTEX_INHERIT_UNVERIFIED=1 时再收未验证的 hash_nt。
// 返回成功写入的条数与父任务凭据里因解密失败被跳过的条数——后者不等于
// “没有相关凭据”，调用方要把它区分展示。调用方在失败时只记日志，仍完成移交。
func (s *Server) inheritCredentials(parentTaskID, childTaskID int64) (inherited, skipped int, err error) {
	if s == nil || s.credStore == nil {
		return 0, 0, nil
	}
	ctx := context.Background()
	listed, err := s.credStore.ListByTask(ctx, parentTaskID)
	if err != nil {
		return 0, 0, err
	}
	skipped = len(listed.Skipped)
	if skipped > 0 {
		log.Printf("[handoff] 父任务 %d 有 %d 条凭据解密失败，已跳过继承（子任务 %d）", parentTaskID, skipped, childTaskID)
	}
	allowUnverifiedHash := os.Getenv(inheritUnverifiedEnv) == "1"
	eligible := make([]*db.CredentialRecord, 0, len(listed.Items))
	for _, c := range listed.Items {
		if credEligible(c, allowUnverifiedHash) {
			eligible = append(eligible, c)
		}
	}
	if len(eligible) == 0 {
		return 0, skipped, nil
	}
	if s.m == nil || s.m.Assets() == nil || s.m.PG() == nil {
		return 0, skipped, fmt.Errorf("asset store 未启用")
	}
	childScopes, err := s.m.Assets().ListTaskScope(childTaskID)
	if err != nil {
		return 0, skipped, err
	}
	hostIP := childFootholdIP(childScopes)
	if hostIP == "" {
		return 0, skipped, fmt.Errorf("子任务 %d 没有立足点 /32", childTaskID)
	}
	parentScopes, err := s.m.Assets().ListTaskScope(parentTaskID)
	if err != nil {
		return 0, skipped, err
	}
	domain, err := footholdDomain(ctx, s.m.PG(), hostIP)
	if err != nil {
		return 0, skipped, err
	}
	hosts, err := s.credentialHosts(eligible)
	if err != nil {
		return 0, skipped, err
	}
	picks := selectInherited(eligible, hosts, hostIP, domain, companyIDs(parentScopes))
	if len(picks) > maxInheritedCreds {
		picks = picks[:maxInheritedCreds]
	}
	var first error
	n := 0
	for _, p := range picks {
		err := s.credStore.Inherit(ctx, db.CredentialInheritance{
			ChildTaskID:  childTaskID,
			SourceTaskID: parentTaskID,
			CredentialID: p.cred.ID,
			ScopeBasis:   p.basis,
			Score:        p.score,
			Reason:       p.reason,
		})
		if err != nil {
			log.Printf("[handoff] inherit credential %d parent=%d child=%d: %v", p.cred.ID, parentTaskID, childTaskID, err)
			if first == nil {
				first = err
			}
			continue
		}
		n++
	}
	return n, skipped, first
}

func credEligible(c *db.CredentialRecord, allowUnverifiedHash bool) bool {
	if c == nil {
		return false
	}
	if c.Verified {
		return true
	}
	return allowUnverifiedHash && c.CredType == db.CredHashNT
}

type inheritedPick struct {
	cred   *db.CredentialRecord
	basis  string
	score  float64
	reason string
}

// selectInherited 按相关性挑凭据。basis 从精确到宽：立足点主机、同 /24、
// 同域、同企业范围。都不中则不继承。verified 的分数整体高于未验证。
func selectInherited(creds []*db.CredentialRecord, hosts map[int64]*db.Asset, hostIP, footholdDomain string, companies map[int64]struct{}) []inheritedPick {
	out := make([]inheritedPick, 0, len(creds))
	for _, c := range creds {
		if c == nil {
			continue
		}
		basis, ok := inheritBasis(c, hosts[c.HostAssetID], hostIP, footholdDomain, companies)
		if !ok {
			continue
		}
		out = append(out, inheritedPick{
			cred:   c,
			basis:  basis,
			score:  inheritanceScore(basis, c.Verified),
			reason: "移交继承 " + basis,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].score != out[j].score {
			return out[i].score > out[j].score
		}
		return out[i].cred.ID < out[j].cred.ID
	})
	return out
}

func inheritBasis(cred *db.CredentialRecord, host *db.Asset, hostIP, footholdDomainName string, companies map[int64]struct{}) (string, bool) {
	hostAddr := ""
	var companyID int64
	if host != nil {
		hostAddr = strings.TrimSpace(host.IP)
		if host.CompanyID != nil {
			companyID = *host.CompanyID
		}
	}
	if hostAddr != "" && sameHostIP(hostAddr, hostIP) {
		return db.InheritFootholdHost, true
	}
	if hostAddr != "" && sameSegment(hostAddr, hostIP) {
		return db.InheritSameSegment, true
	}
	if domainEqual(cred.Domain, footholdDomainName) {
		return db.InheritDomain, true
	}
	if companyID > 0 {
		if _, ok := companies[companyID]; ok {
			return db.InheritCompany, true
		}
	}
	return "", false
}

// inheritanceScore 是 ScoreReuse 的等价排序：已验证优先，其次 basis 越精确越高。
// 验证加分大于任意两条 basis 的分差，所以未验证凭据不会排到已验证前面。
func inheritanceScore(basis string, verified bool) float64 {
	var base float64
	switch basis {
	case db.InheritFootholdHost:
		base = 40
	case db.InheritSameSegment:
		base = 30
	case db.InheritDomain:
		base = 20
	case db.InheritCompany:
		base = 10
	case db.InheritManual:
		base = 5
	}
	if verified {
		return base + 100
	}
	return base
}

func childFootholdIP(scopes []db.TaskScope) string {
	fallback := ""
	for _, sc := range scopes {
		if sc.Kind != "ip" || sc.Net == "" {
			continue
		}
		ip, network, err := net.ParseCIDR(sc.Net)
		if err != nil || ip == nil {
			continue
		}
		ones, bits := network.Mask.Size()
		if !((bits == 32 && ones == 32) || (bits == 128 && ones == 128)) {
			continue
		}
		host := ip.String()
		if sc.Source == "manual" && (strings.Contains(sc.Reason, "handoff") || strings.Contains(sc.Reason, "立足点")) {
			return host
		}
		if fallback == "" {
			fallback = host
		}
	}
	return fallback
}

func companyIDs(scopes []db.TaskScope) map[int64]struct{} {
	out := map[int64]struct{}{}
	for _, sc := range scopes {
		if sc.Kind == "company" && sc.CompanyID != nil && *sc.CompanyID > 0 {
			out[*sc.CompanyID] = struct{}{}
		}
	}
	return out
}

func footholdDomain(ctx context.Context, pg *db.DB, ip string) (string, error) {
	var domain string
	err := pg.QueryRowContext(ctx, `
SELECT COALESCE(domain,'')
FROM assets
WHERE ip::text = $1 AND COALESCE(domain,'') <> ''
ORDER BY id
LIMIT 1`, ip).Scan(&domain)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return domain, err
}

func (s *Server) credentialHosts(creds []*db.CredentialRecord) (map[int64]*db.Asset, error) {
	ids := make([]int64, 0, len(creds))
	seen := map[int64]struct{}{}
	for _, c := range creds {
		if c.HostAssetID <= 0 {
			continue
		}
		if _, ok := seen[c.HostAssetID]; ok {
			continue
		}
		seen[c.HostAssetID] = struct{}{}
		ids = append(ids, c.HostAssetID)
	}
	out := map[int64]*db.Asset{}
	if len(ids) == 0 {
		return out, nil
	}
	assets, err := s.m.Assets().GetByIDs(ids)
	if err != nil {
		return nil, err
	}
	for _, a := range assets {
		if a != nil {
			out[a.ID] = a
		}
	}
	return out, nil
}

func sameHostIP(a, b string) bool {
	pa := net.ParseIP(strings.TrimSpace(a))
	pb := net.ParseIP(strings.TrimSpace(b))
	return pa != nil && pb != nil && pa.Equal(pb)
}

func sameSegment(a, b string) bool {
	sa := footholdSegment(strings.TrimSpace(a))
	sb := footholdSegment(strings.TrimSpace(b))
	return sa != "" && sa == sb
}

func domainEqual(credDomain, assetDomain string) bool {
	c := db.DomainKey(credDomain)
	a := db.DomainKey(assetDomain)
	return c != "" && c == a
}
