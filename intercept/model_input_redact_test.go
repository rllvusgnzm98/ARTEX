package intercept

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

const modelInputFixtureSecret = "fixture-pass"

func credentialReviewArgs() json.RawMessage {
	return json.RawMessage(`{"cred_type":"password","secret":"fixture-pass","source":"fixture source","username":"fixture-admin"}`)
}

func TestAuditForRedactsModelInputArgumentsButKeepsDigest(t *testing.T) {
	args := credentialReviewArgs()
	input, err := BuildReviewInput(context.Background(), "add_credential", args)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), modelInputFixtureSecret) {
		t.Fatal("夹具应含假口令，才能证明打码生效")
	}
	dec := Decision{Action: "allow", ModelFallback: true, ModelInput: raw, ModelInputDigest: digestInput(raw)}
	a := auditFor(context.Background(), dec, args, "allowed")
	if strings.Contains(string(a.ModelInput), modelInputFixtureSecret) {
		t.Fatalf("落库 model_input 不得含明文口令: %s", a.ModelInput)
	}
	var saved ReviewInput
	if err := json.Unmarshal(a.ModelInput, &saved); err != nil || saved.Tool != "add_credential" || saved.Version != 4 {
		t.Fatalf("打码后仍应是审查快照: %+v %v", saved, err)
	}
	if a.ModelInputDigest != digestInput(raw) || a.ModelInputDigest != dec.ModelInputDigest {
		t.Fatal("ModelInputDigest 必须保留对送进模型原文的摘要")
	}
	// digest 不得被拿来还原明文
	if string(a.ModelInput) == string(raw) {
		t.Fatal("落库 model_input 不得仍是原文")
	}
}

func TestPublicDetailRedactsLegacyModelInputArguments(t *testing.T) {
	args := credentialReviewArgs()
	input, err := BuildReviewInput(context.Background(), "add_credential", args)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(input)
	digest := digestInput(raw)
	legacy := &db.InterceptDetail{
		InterceptApprovalRow: db.InterceptApprovalRow{
			InterceptPending: db.InterceptPending{ToolName: "add_credential", ToolInput: json.RawMessage(RedactStoredToolInput("add_credential", args))},
		},
		Audit: &db.InterceptAudit{ModelInput: raw, ModelInputDigest: digest},
	}
	if !strings.Contains(string(legacy.Audit.ModelInput), modelInputFixtureSecret) {
		t.Fatal("旧行夹具应含明文，才能证明读出防御")
	}
	pub := PublicDetail(legacy)
	if pub == nil || pub.Audit == nil {
		t.Fatal("PublicDetail 应返回详情")
	}
	if strings.Contains(string(pub.Audit.ModelInput), modelInputFixtureSecret) {
		t.Fatalf("详情读出不得含明文口令: %s", pub.Audit.ModelInput)
	}
	if pub.Audit.ModelInputDigest != digest {
		t.Fatal("读出不得改 digest，也不得用 digest 还原明文")
	}
	if !strings.Contains(string(legacy.Audit.ModelInput), modelInputFixtureSecret) {
		t.Fatal("PublicDetail 不得改写调用方手里的旧行")
	}
}

func TestJudgeReviewerSeesRawArgumentsAuditStoresRedacted(t *testing.T) {
	d := openInterceptTestDB(t)
	ic := New(d)
	prior := ic.GetJudgeConfig()
	t.Cleanup(func() { _ = ic.SetJudgeConfig(prior); ic.SetReviewer(nil) })
	if err := ic.SetJudgeConfig(JudgeConfig{Enabled: true, FailAction: "allow", TimeoutSeconds: 5, AskTimeoutSeconds: 1, AskTimeoutAction: "deny"}); err != nil {
		t.Fatal(err)
	}
	args := credentialReviewArgs()
	var seen ReviewInput
	ic.SetReviewer(func(_ context.Context, _ int64, _ string, in ReviewInput) (Decision, error) {
		seen = in
		return Decision{Action: "allow", Message: "ok", ProfileID: 1}, nil
	})
	dec, ok := ic.Judge(context.Background(), "add_credential", args)
	if !ok {
		t.Fatal("模型兜底开启时应走审查")
	}
	if !strings.Contains(string(seen.Arguments), modelInputFixtureSecret) {
		t.Fatal("判官仍须看到未打码的审查输入")
	}
	if !strings.Contains(string(dec.ModelInput), modelInputFixtureSecret) {
		t.Fatal("Decision.ModelInput 应保留送进模型的原文；打码发生在落库/下发")
	}
	if dec.ModelInputDigest != digestInput(dec.ModelInput) {
		t.Fatal("digest 应对实际送进模型的原文")
	}
	a := auditFor(context.Background(), dec, args, "allowed")
	if strings.Contains(string(a.ModelInput), modelInputFixtureSecret) {
		t.Fatalf("落库 model_input 不得含明文: %s", a.ModelInput)
	}
	if a.ModelInputDigest != dec.ModelInputDigest {
		t.Fatal("落库不得改写原文 digest")
	}
}

func TestDisabledJudgePathLeavesModelInputEmpty(t *testing.T) {
	d := openInterceptTestDB(t)
	ic := New(d)
	prior := ic.GetJudgeConfig()
	t.Cleanup(func() { _ = ic.SetJudgeConfig(prior); ic.SetReviewer(nil) })
	if err := ic.SetJudgeConfig(JudgeConfig{Enabled: false, FailAction: "allow"}); err != nil {
		t.Fatal(err)
	}
	ic.SetReviewer(func(context.Context, int64, string, ReviewInput) (Decision, error) {
		t.Fatal("关闭模型兜底时不应调用判官")
		return Decision{}, nil
	})
	dec, ok := ic.Judge(context.Background(), "add_credential", credentialReviewArgs())
	if ok {
		t.Fatal("关闭模型兜底时 Judge 应返回 false")
	}
	if len(dec.ModelInput) != 0 || dec.ModelInputDigest != "" || dec.Action != "" {
		t.Fatalf("关闭路径不得带上审查快照: %+v", dec)
	}
	// 规则审批写入仍只打码 tool_input，不发明文 model_input
	a := auditFor(context.Background(), Decision{Action: "ask", Message: "rule ask"}, credentialReviewArgs(), "pending")
	if len(a.ModelInput) != 0 || a.ModelInputDigest != "" {
		t.Fatalf("规则路径不应写入 model_input: %+v", a)
	}
}
