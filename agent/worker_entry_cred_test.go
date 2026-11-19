package agent

import "testing"

func TestIsSideEffectToolIncludesAddCredential(t *testing.T) {
	if !IsSideEffectTool("add_credential") {
		t.Fatal("add_credential 会改状态，必须进入 IsSideEffectTool")
	}
	if IsSideEffectTool("list_credentials") || IsSideEffectTool("credential_reuse_plan") {
		t.Fatal("只读凭据工具不应算副作用")
	}
}
