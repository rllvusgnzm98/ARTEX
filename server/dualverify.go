package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/agent/dualverify"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/guard"
	actool "github.com/Autumn-27/norma/tool"
)

type dualVerifyInput struct {
	Target       dualverify.Request `json:"target"`
	Plant        dualverify.Request `json:"plant"`
	Cleanup      dualverify.Request `json:"cleanup"`
	ResourceID   string             `json:"resource_id"`
	Marker       string             `json:"marker"`
	A            json.RawMessage    `json:"a_credential_id"`
	B            json.RawMessage    `json:"b_credential_id"`
	Expired      json.RawMessage    `json:"b_expired_credential_id"`
	Revoked      json.RawMessage    `json:"b_revoked_credential_id"`
	WrongIssuer  json.RawMessage    `json:"b_wrong_issuer_credential_id"`
	OtherTenant  json.RawMessage    `json:"b_other_tenant_credential_id"`
	Read         *bool              `json:"read"`
	Write        bool               `json:"write"`
	SessionToken bool               `json:"session_token"`
	TenantRole   bool               `json:"tenant_role"`
	AllowWrite   bool               `json:"allow_write"`
	AssetIDs     []int64            `json:"asset_ids"`
	VulnClass    string             `json:"vulnclass"`
	FindingID    json.RawMessage    `json:"finding_id"`
}

func dualVerifySchema() map[string]any {
	request := func() map[string]any {
		return objSchema(map[string]any{
			"method":  strParam("读使用 GET/HEAD；写使用 POST/PUT/PATCH/DELETE"),
			"url":     strParam("无秘密的 HTTP(S) 模板，支持 {{RESOURCE_ID}}/{{MARKER}}"),
			"headers": map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}, "description": "认证头含且仅含一个 {{AUTH}}；禁止真实秘密"},
			"body":    strParam("无秘密的正文模板"),
		}, "method", "url", "headers")
	}
	props := map[string]any{
		"target": request(), "plant": request(), "cleanup": request(),
		"resource_id": strParam("A 拥有的私有资源 ID"),
		"marker":      strParam("A 私有资源中已存在的唯一且非敏感标记（自行预置）；写入模式可留空自动生成。标记会出现在报告中，不要填真实秘密。"),
		"asset_ids":   map[string]any{"type": "array", "items": map[string]any{"type": "integer"}},
		"vulnclass":   strParam("可选漏洞分类；默认 idor 或 token-trust"),
	}
	for _, key := range []string{"a_credential_id", "b_credential_id", "b_expired_credential_id", "b_revoked_credential_id", "b_wrong_issuer_credential_id", "b_other_tenant_credential_id", "finding_id"} {
		props[key] = map[string]any{"anyOf": []any{map[string]any{"type": "integer", "minimum": 1}, map[string]any{"type": "string", "pattern": "^[1-9][0-9]*$"}}, "description": "本任务或有效继承的凭据 ID（finding_id 为本任务漏洞 ID）；不接受秘密"}
	}
	for _, key := range []string{"read", "write", "session_token", "tenant_role", "allow_write"} {
		props[key] = map[string]any{"type": "boolean", "default": key == "read"}
	}
	props["allow_write"] = map[string]any{"type": "boolean", "default": false, "description": "操作员明确授权写入；仍须同时提供 plant 和 cleanup（含 {{MARKER}}）"}
	return objSchema(props, "target", "resource_id", "a_credential_id", "b_credential_id")
}

func (s *Server) dualVerifyTools() []actool.CoreTool {
	if s.credStore == nil {
		return nil
	}
	return []actool.CoreTool{actool.Build(actool.Spec{
		Name:        "dual_account_verify",
		Description: "有界双账号访问控制验证：只传凭据 ID，经任务记录代理执行公开/A/B 控制对；缺失令牌、范围或记录时诚实标记未验证。仅 verified 或独立令牌/跨租户缺陷可用 recommended_findings 调用 report_finding；controls_hold 本身不是漏洞。写入须操作员授权并成对清理。",
		Schema:      dualVerifySchema(), ReadOnly: func(json.RawMessage) bool { return false }, Permissions: sessionPerm,
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			return s.executeDualVerify(ctx, in)
		},
	})}
}

func (s *Server) seedDualVerifyTool() {
	if s.m == nil || s.m.pg == nil {
		return
	}
	agents, _ := json.Marshal([]string{"worker"})
	for _, tool := range s.dualVerifyTools() {
		schema, _ := json.Marshal(tool.InputSchema())
		if err := s.m.pg.SeedTool(tool.Name(), tool.Description(), schema, agents); err != nil {
			log.Printf("[tools] seed dual_account_verify 失败: %v", err)
		}
	}
}

func (s *Server) dualVerifySecret(ctx context.Context, taskID, id int64) (string, error) {
	if id <= 0 {
		return "", errors.New("凭据 ID 必须为正整数")
	}
	rec, err := s.credStore.Get(ctx, id)
	if err != nil || rec == nil {
		return "", errors.New("凭据不存在或无法读取")
	}
	belongs := rec.TaskID == taskID
	if !belongs {
		metas, err := s.credStore.ListInheritedMeta(ctx, taskID)
		if err != nil {
			return "", errors.New("无法确认凭据继承关系")
		}
		for _, m := range metas {
			if m.CredentialID == id {
				belongs = true
				break
			}
		}
	}
	if !belongs {
		return "", errors.New("凭据不属于本任务且未有效继承")
	}
	if rec.Secret == "" {
		return "", errors.New("凭据内容为空")
	}
	return rec.Secret, nil
}

func validateDualVerifyTemplate(r dualverify.Request, write bool) error {
	count := 0
	for k, v := range r.Headers {
		if strings.EqualFold(k, "Host") || strings.HasPrefix(strings.ToLower(k), "proxy-") || strings.EqualFold(k, dualVerifyTraceHeader) {
			return errors.New("禁止覆盖路由或验证关联头")
		}
		if strings.Contains(v, "{{AUTH}}") {
			name := strings.ToLower(k)
			if !strings.Contains(name, "auth") && !strings.Contains(name, "cookie") && !strings.Contains(name, "token") && !strings.Contains(name, "api-key") {
				return errors.New("{{AUTH}} 只能出现在认证头")
			}
			count += strings.Count(v, "{{AUTH}}")
		}
	}
	if count != 1 || strings.Contains(r.URL+r.Body, "{{AUTH}}") {
		return errors.New("请求认证头必须含且仅含一个 {{AUTH}}，URL/正文不得含认证信息")
	}
	for _, token := range dualVerifyTokens {
		if strings.Contains(r.URL+r.Body, token) {
			return errors.New("只能提供通用 {{AUTH}} 模板，不得预置账号令牌")
		}
		for _, v := range r.Headers {
			if strings.Contains(v, token) {
				return errors.New("只能提供通用 {{AUTH}} 模板")
			}
		}
	}
	u, err := url.Parse(r.URL)
	if err != nil || u.User != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return errors.New("请求必须为无内嵌凭据的 HTTP(S) URL")
	}
	if write && !strings.Contains(r.URL+r.Body, "{{MARKER}}") {
		return errors.New("plant/cleanup 必须引用 {{MARKER}}，限定写入/清理对象")
	}
	return nil
}

func dualVerifyInputHasSecret(in any, secrets map[string]string) bool {
	switch v := in.(type) {
	case string:
		for _, secret := range secrets {
			if secret != "" && strings.Contains(v, secret) {
				return true
			}
		}
	case map[string]any:
		for k, x := range v {
			if dualVerifyInputHasSecret(k, secrets) || dualVerifyInputHasSecret(x, secrets) {
				return true
			}
		}
	case []any:
		for _, x := range v {
			if dualVerifyInputHasSecret(x, secrets) {
				return true
			}
		}
	}
	return false
}

func dualVerifyMarker(a dualVerifyInput) (string, error) {
	provided := strings.TrimSpace(a.Marker)
	willPlant := a.Write && a.AllowWrite
	if provided != "" {
		if strings.ContainsAny(provided, "{}\r\n") || len([]rune(provided)) < 8 || len(provided) > 256 {
			return "", errors.New("marker 必须至少 8 个字符、最多 256 字节，且不能包含花括号或换行")
		}
		return provided, nil
	}
	if willPlant {
		marker, err := dualverify.NewMarker()
		if err != nil {
			return "", errors.New("生成私有标记失败")
		}
		return marker, nil
	}
	return "", errors.New("请提供 marker（已自行预置在 A 私有资源中的唯一且非敏感标记），或启用 write + allow_write 自动种植标记")
}

func (s *Server) executeDualVerify(ctx context.Context, in json.RawMessage) (actool.Result, error) {
	var a dualVerifyInput
	if err := json.Unmarshal(in, &a); err != nil {
		return actool.Errorf("dual_account_verify 参数无效"), nil
	}
	marker, err := dualVerifyMarker(a)
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	taskID := agent.RunInfoFrom(ctx).TaskID
	if taskID <= 0 || s.m == nil || s.m.pg == nil || s.credStore == nil {
		return actool.Errorf("dual_account_verify 需要任务上下文与凭据库"), nil
	}
	secrets := map[string]string{}
	for _, cred := range []struct {
		actor    string
		raw      json.RawMessage
		required bool
	}{
		{"A", a.A, true}, {"B", a.B, true}, {"B_expired", a.Expired, false}, {"B_revoked", a.Revoked, false}, {"B_wrong_issuer", a.WrongIssuer, false}, {"B_other_tenant", a.OtherTenant, false},
	} {
		if !cred.required && (len(cred.raw) == 0 || string(cred.raw) == "null") {
			continue
		}
		secret, err := s.dualVerifySecret(ctx, taskID, parseProfileID(cred.raw))
		if err != nil {
			return actool.Errorf(cred.actor + "：" + err.Error()), nil
		}
		secrets[cred.actor] = secret
	}
	if secrets["A"] == secrets["B"] {
		return actool.Errorf("A/B 必须为不同账号凭据，不能使用相同秘密"), nil
	}
	var decoded any
	_ = json.Unmarshal(in, &decoded)
	if dualVerifyInputHasSecret(decoded, secrets) {
		return actool.Errorf("参数模板包含凭据秘密；仅允许凭据 ID 与 {{AUTH}}"), nil
	}
	if strings.ContainsAny(a.ResourceID, "{}\r\n") {
		return actool.Errorf("resource_id 必须是具体资源 ID，不能含占位符或换行"), nil
	}
	if err := validateDualVerifyTemplate(a.Target, false); err != nil {
		return actool.Errorf(err.Error()), nil
	}
	if a.Write {
		for _, req := range []dualverify.Request{a.Plant, a.Cleanup} {
			if err := validateDualVerifyTemplate(req, true); err != nil {
				return actool.Errorf(err.Error()), nil
			}
		}
	}
	fp := s.taskFootprint(taskID)
	read := a.Read == nil || *a.Read
	// 宿主额外要求显式操作员授权；纯计划仍记录写入被抑制。
	plan, err := dualverify.BuildPlan(dualverify.Spec{Target: a.Target, Plant: a.Plant, Cleanup: a.Cleanup, ResourceID: a.ResourceID, Marker: marker, Read: read, Write: a.Write, SessionToken: a.SessionToken, TenantRole: a.TenantRole, AllowWrite: a.AllowWrite, Footprint: dualverify.Footprint{MinTouch: fp.MinTouch || !a.AllowWrite, NoDirtyData: fp.NoDirtyData}})
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	for i := range plan.Steps {
		plan.Steps[i].Request.Headers[dualVerifyTraceHeader] = marker + ":" + plan.Steps[i].ID
		if actor := plan.Steps[i].Actor; actor != "public" && secrets[actor] == "" {
			plan.Notes = append(plan.Notes, actor+"：未提供凭据，步骤未执行、未验证；不伪造拒绝路径。")
		}
	}
	if !a.SessionToken {
		plan.Notes = append(plan.Notes, "明确未验证：未启用 session_token 令牌拒绝检查。")
	}
	if !a.TenantRole {
		plan.Notes = append(plan.Notes, "明确未验证：未启用 tenant_role 跨租户检查。")
	}
	if a.Write && !a.AllowWrite {
		plan.Notes = append(plan.Notes, "write not attempted：未获得 allow_write 操作员授权。")
	}
	addr, ca := s.m.TaskProxyForTask(taskID)
	client, err := dualVerifyClient(addr, ca)
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	defer client.CloseIdleConnections()
	scopeOf := func(host string) (dualverify.Scope, bool) {
		verdict, mode, err := s.roeVerdictFor(taskID, host)
		if err != nil {
			return dualverify.ScopeEmpty, mode == "strict"
		}
		switch verdict {
		case guard.ScopeIn:
			return dualverify.ScopeIn, false
		case guard.ScopeOut:
			return dualverify.ScopeOut, mode == "strict"
		default:
			return dualverify.ScopeEmpty, false
		}
	}
	start := time.Now()
	observations, runErr := runDualVerify(ctx, client, plan, secrets, scopeOf, addr != "")
	end := time.Now()
	if runErr != nil {
		plan.Notes = append(plan.Notes, runErr.Error())
	}
	result, err := dualverify.Evaluate(plan, observations)
	if err != nil {
		return actool.Errorf("验证结果计算失败"), nil
	}
	bindNotes := []string{"未提供 finding_id；使用 recommended_finding 调用 report_finding，非漏洞结论不得提交。"}
	if len(a.FindingID) > 0 && string(a.FindingID) != "null" {
		if fid := parseProfileID(a.FindingID); fid > 0 {
			bindNotes = s.bindDualVerifyTraffic(ctx, taskID, fid, plan, result, start, end, addr != "")
		} else {
			bindNotes = []string{"finding_id 无效，未绑定证据"}
		}
	}
	plan.Notes = append(plan.Notes, bindNotes...)
	report := dualverify.Report(result, plan)
	summaries := []map[string]any{}
	for i, sr := range result.Steps {
		step := plan.Steps[i]
		summaries = append(summaries, map[string]any{"step_id": step.ID, "actor": step.Actor, "action": step.Action, "expect": step.Expect, "require_marker": step.RequireMarker, "status": sr.Observation.Status, "marker": sr.Observation.MarkerSeen, "pass": sr.Pass, "trusted": sr.Trusted, "scope": sr.Observation.Scope, "out_of_scope": sr.Observation.OutOfScope, "proxy_bypass": sr.Observation.ProxyBypass, "not_executed": sr.Observation.NotExecuted, "reason": sr.Reason})
	}
	recommendations := []map[string]any{}
	addFinding := func(class, summary string) {
		if a.VulnClass != "" {
			class = a.VulnClass
		}
		recommendations = append(recommendations, map[string]any{"vulnclass": class, "severity": "high", "summary": summary, "evidence": report, "asset_ids": a.AssetIDs})
	}
	if result.Verdict == dualverify.Verified {
		addFinding("idor", "B 读取到 A 私有资源的唯一标记（双账号对照已验证）")
	}
	for _, defect := range result.Defects {
		if defect.Kind == "cross-tenant" {
			addFinding("idor", defect.Actor+" 跨租户读取到 A 的私有标记（跨租户访问控制缺陷）")
		} else {
			addFinding("token-trust", defect.Actor+" 应拒绝令牌被接受（令牌信任缺陷）")
		}
	}
	var recommended any
	if len(recommendations) > 0 {
		recommended = recommendations[0]
	}
	return jsonResult(map[string]any{"verdict": result.Verdict, "reason": result.Reason, "report": report, "defects": result.Defects, "steps": summaries, "recommended_finding": recommended, "recommended_findings": recommendations, "finding_id": parseProfileID(a.FindingID), "evidence_binding_notes": bindNotes, "write_not_attempted": plan.WriteNotAttempted, "recording_proxy_configured": addr != ""})
}

func (s *Server) bindDualVerifyTraffic(ctx context.Context, taskID, findingID int64, p dualverify.Plan, r dualverify.Result, start, end time.Time, proxied bool) []string {
	if !proxied {
		return []string{"proxy-bypass：无记录代理，未绑定流量证据"}
	}
	if r.Verdict != dualverify.Verified && len(r.Defects) == 0 {
		return []string{"非已验证漏洞，未绑定流量证据"}
	}
	f, err := s.m.pg.GetFinding(findingID)
	if err != nil || f == nil || f.TaskID == nil || *f.TaskID != taskID {
		return []string{"finding_id 不属于本任务或无法读取，未绑定证据"}
	}
	if s.m.traffic == nil {
		return []string{"流量存储不可用，未绑定证据"}
	}
	notes := []string{}
	refs := []db.TrafficRef{}
	used := map[string]bool{}
	for i, step := range p.Steps {
		sr := r.Steps[i]
		if !sr.Trusted || sr.Observation.Status == 0 {
			continue
		}
		u, err := url.Parse(step.Request.URL)
		if err != nil {
			continue
		}
		matches := []string{}
		searchOK := true
		for page := 0; page < 4; page++ {
			rows, err := s.m.traffic.Search(u.Hostname(), page, 500)
			if err != nil {
				searchOK = false
				break
			}
			for _, row := range rows {
				if row.TS < start.Unix() || row.TS > end.Unix() || row.Method != step.Request.Method || row.URL != step.Request.URL || row.Status != sr.Observation.Status {
					continue
				}
				req, _, err := s.m.traffic.Get(row.ID)
				if err == nil && dualVerifyTraceMatches(req, p.Marker+":"+step.ID) {
					matches = append(matches, row.ID)
				}
			}
			if len(rows) < 500 {
				break
			}
			if page == 3 {
				searchOK = false
			}
		}
		if !searchOK || len(matches) != 1 || used[matches[0]] {
			notes = append(notes, fmt.Sprintf("%s：无法唯一关联记录流量，已跳过绑定", step.ID))
			continue
		}
		role := "supporting"
		switch step.ID {
		case "public":
			role = "baseline"
		case "owner":
			role = "verification"
		case "probe":
			role = "proof"
		case "B_expired", "B_revoked", "B_wrong_issuer":
			role = "verification"
			if sr.Observation.Status >= 200 && sr.Observation.Status < 300 {
				role = "proof"
			}
		}
		used[matches[0]] = true
		refs = append(refs, db.TrafficRef{TrafficID: matches[0], Role: role, Note: "dual_account_verify " + step.ID})
	}
	if len(refs) == 0 {
		return append(notes, "未找到可确信关联的流量；未绑定证据")
	}
	if _, err := s.evidenceStore().Bind(ctx, findingID, refs); err != nil {
		return append(notes, "证据绑定失败；验证结论保留，未声称绑定成功")
	}
	return append(notes, fmt.Sprintf("已向 finding_id=%d 绑定 %d 条唯一关联的流量证据", findingID, len(refs)))
}

func dualVerifyTraceMatches(raw, want string) bool {
	header, _, _ := strings.Cut(strings.ReplaceAll(raw, "\r\n", "\n"), "\n\n")
	count := 0
	for _, line := range strings.Split(header, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(key), dualVerifyTraceHeader) {
			if strings.TrimSpace(value) != want {
				return false
			}
			count++
		}
	}
	return count == 1
}
