package intercept

import (
	"bytes"
	"encoding/json"

	"github.com/Autumn-27/artex/db"
)

// RedactStoredToolInput 是凭据相关工具入参在持久化或对外展示时的清洗结果。
// Match() 必须继续看原始 input，不得在规则匹配前调用本函数。
func RedactStoredToolInput(toolName string, input []byte) []byte {
	if len(input) == 0 {
		return input
	}
	return []byte(db.RedactCredentialPayload(toolName, string(input)))
}

// PublicPending 返回可供列表/详情接口下发的脱敏台账行。
func PublicPending(p db.InterceptPending) db.InterceptPending {
	p.ToolInput = json.RawMessage(RedactStoredToolInput(p.ToolName, p.ToolInput))
	return p
}

// PublicPendings 批量脱敏 pending 列表。
func PublicPendings(items []db.InterceptPending) []db.InterceptPending {
	out := make([]db.InterceptPending, len(items))
	for i, p := range items {
		out[i] = PublicPending(p)
	}
	return out
}

// PublicApproval 脱敏历史/任务拦截行。
func PublicApproval(row db.InterceptApprovalRow) db.InterceptApprovalRow {
	row.InterceptPending = PublicPending(row.InterceptPending)
	return row
}

// PublicApprovals 批量脱敏审批历史。
func PublicApprovals(items []db.InterceptApprovalRow) []db.InterceptApprovalRow {
	out := make([]db.InterceptApprovalRow, len(items))
	for i, r := range items {
		out[i] = PublicApproval(r)
	}
	return out
}

// RedactStoredModelInput 清洗即将落库或下发的 audit.model_input：
// 对 arguments（及同等位置的 tool_input）套用 RedactStoredToolInput，
// 不得把原始秘密参数写进存储或详情。输入不是对象时原样返回。
// 不改 ModelInputDigest；digest 可以对送进判官的原文计算，但不能用来还原明文。
func RedactStoredModelInput(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 || !json.Valid(raw) {
		return raw
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return raw
	}
	var tool string
	if t, ok := obj["tool_name"]; ok {
		_ = json.Unmarshal(t, &tool)
	}
	changed := false
	for _, key := range []string{"arguments", "tool_input"} {
		args, ok := obj[key]
		if !ok {
			continue
		}
		redacted := json.RawMessage(RedactStoredToolInput(tool, args))
		if !bytes.Equal(redacted, args) {
			obj[key] = redacted
			changed = true
		}
	}
	if !changed {
		return raw
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return raw
	}
	return out
}

// PublicDetail 脱敏单条审批详情中的 tool_input，以及 audit.model_input 里的参数。
// 旧行若仍存有明文 arguments，也在下发前打码；不改写调用方手里的原对象，也不用 digest 还原明文。
func PublicDetail(d *db.InterceptDetail) *db.InterceptDetail {
	if d == nil {
		return nil
	}
	cp := *d
	cp.InterceptApprovalRow = PublicApproval(d.InterceptApprovalRow)
	if d.Audit != nil {
		a := *d.Audit
		a.ModelInput = RedactStoredModelInput(a.ModelInput)
		cp.Audit = &a
	}
	return &cp
}
