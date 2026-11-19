package intercept

import (
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

// PublicDetail 脱敏单条审批详情中的 tool_input。
func PublicDetail(d *db.InterceptDetail) *db.InterceptDetail {
	if d == nil {
		return nil
	}
	cp := *d
	cp.InterceptApprovalRow = PublicApproval(d.InterceptApprovalRow)
	return &cp
}
