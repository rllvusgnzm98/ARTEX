package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/agent/chainskel"
	"github.com/Autumn-27/artex/agent/patchverify"
	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

type patchVerifyInput struct {
	patchverify.Spec
	VulnerableFile string                 `json:"vulnerable_file"`
	FixedFile      string                 `json:"fixed_file"`
	Regression     patchverify.Regression `json:"regression"`
	VulnClass      string                 `json:"vulnclass"`
	Severity       string                 `json:"severity"`
	AssetIDs       []int64                `json:"asset_ids"`
}

func patchVerifySchema() map[string]any {
	object := func(fields ...string) map[string]any {
		props := make(map[string]any, len(fields))
		for _, field := range fields {
			props[field] = strParam(field)
		}
		return props
	}
	closed := func(fields map[string]any) map[string]any {
		schema := objSchema(fields)
		schema["additionalProperties"] = false
		return schema
	}
	pins := object("vendor", "product", "version", "build", "architecture", "sample_sha256")
	pins["backport_state"] = map[string]any{"type": "string", "enum": []string{"upstream-fixed", "backported", "unknown"}}
	check := closed(map[string]any{"evidence_ref": strParam("脱敏证据引用"), "reached": map[string]any{"type": "boolean"}})
	observation := object("input_id", "input_sha256", "result_sha256", "evidence_ref")
	observation["outcome"] = map[string]any{"type": "string", "enum": []string{"effect", "no_effect", "normal", "denied"}}
	pair := closed(map[string]any{"vulnerable": closed(observation), "fixed": closed(observation)})
	preflight := object("tool", "version", "platform", "sample_sha256", "evidence_ref")
	preflight["dependencies"] = map[string]any{"type": "array", "items": strParam("依赖版本；无依赖记录 none")}
	preflight["passed"] = map[string]any{"type": "boolean", "description": "在声明的旧版样本哈希上完成的已记录工具预检"}
	return closed(map[string]any{
		"vulnerable": closed(pins), "fixed": closed(pins),
		"vulnerable_file":   strParam("旧版样本的任务工作区相对路径"),
		"fixed_file":        strParam("修复样本的任务工作区相对路径"),
		"preflight":         closed(preflight),
		"root_cause":        closed(object("advisory", "fix_commit", "function", "file")),
		"reachability":      closed(map[string]any{"input": check, "call": check, "config": check}),
		"safe_to_reproduce": map[string]any{"type": "boolean"},
		"safe_reason":       strParam("有界无害验证依据或无法安全验证的原因；不提供输入或秘密"),
		"regression": closed(map[string]any{
			"differential": pair, "normal": pair, "denied": pair,
			"environment_diff": strParam("两次环境差异；一致也应明确记录"),
			"isolation_ref":    strParam("隔离环境证明引用"),
		}),
		"vulnclass": strParam("用于建议提报的漏洞分类（可选）"),
		"severity":  map[string]any{"type": "string", "enum": []string{"critical", "high", "medium", "low"}, "description": "可选评估级别；未提供时不生成建议提报"},
		"asset_ids": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}},
	})
}

func (s *Server) patchVerifyTools() []actool.CoreTool {
	return []actool.CoreTool{roTool("patch_verify",
		"仅评估已有的脱敏补丁回归证据并核验工作区样本哈希；仅接受显式 patch/audit/rev/firmware/supply 意图。不执行样本、不接收输入内容、不生成 PoC。仅 verified 的证据可用于 report_finding。",
		patchVerifySchema(), s.executePatchVerify)}
}

func (s *Server) seedPatchVerifyTool() {
	if s.m == nil || s.m.pg == nil {
		return
	}
	agents, _ := json.Marshal([]string{"worker"})
	for _, tool := range s.patchVerifyTools() {
		schema, _ := json.Marshal(tool.InputSchema())
		if err := s.m.pg.SeedTool(tool.Name(), tool.Description(), schema, agents); err != nil {
			log.Printf("[tools] seed patch_verify 失败: %v", err)
		}
	}
}

func explicitPatchTag(payload json.RawMessage) string {
	var p struct {
		ChainTags []string `json:"chain_tags"`
	}
	if json.Unmarshal(payload, &p) != nil {
		return ""
	}
	for _, tag := range chainskel.NormalizeChainTags(p.ChainTags) {
		if patchverify.AllowedTag(tag) {
			return tag
		}
	}
	return ""
}

func patchSampleHash(root *os.Root, path string) (string, error) {
	if path == "" || !filepath.IsLocal(path) {
		return "", errors.New("invalid sample path")
	}
	info, err := root.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxWorkspaceUpload {
		return "", errors.New("sample must be a regular workspace file within the size limit")
	}
	f, err := root.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !os.SameFile(info, st) {
		return "", errors.New("sample changed while opening")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, maxWorkspaceUpload+1))
	if err != nil || n != info.Size() {
		return "", errors.New("sample changed while hashing")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (s *Server) crossCheckPatchSamples(taskID string, a patchVerifyInput) bool {
	path, err := s.taskWorkspaceRoot(taskID)
	if err != nil {
		return false
	}
	data, err := os.OpenRoot(s.m.dir)
	if err != nil {
		return false
	}
	defer data.Close()
	tasks, err := openPatchSampleDirectory(data, "tasks")
	if err != nil {
		return false
	}
	defer tasks.Close()
	root, err := openPatchSampleDirectory(tasks, filepath.Base(path))
	if err != nil {
		return false
	}
	defer root.Close()
	checked := false
	for _, sample := range []struct{ path, hash string }{
		{a.VulnerableFile, a.Vulnerable.SampleSHA256},
		{a.FixedFile, a.Fixed.SampleSHA256},
	} {
		if sample.path == "" && sample.hash == "" {
			continue
		}
		hash, err := patchSampleHash(root, sample.path)
		if err != nil || !strings.EqualFold(hash, sample.hash) {
			return false
		}
		checked = true
	}
	return checked
}

func openPatchSampleDirectory(parent *os.Root, name string) (*os.Root, error) {
	info, err := parent.Lstat(name)
	if err != nil || !info.IsDir() {
		return nil, errors.New("invalid workspace directory")
	}
	root, err := parent.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	st, err := root.Stat(".")
	if err != nil || !os.SameFile(info, st) {
		root.Close()
		return nil, errors.New("workspace directory changed while opening")
	}
	return root, nil
}

func (s *Server) executePatchVerify(ctx context.Context, in json.RawMessage) (actool.Result, error) {
	ri := agent.RunInfoFrom(ctx)
	if s.m == nil || ri.TaskID <= 0 || ri.ExplorationID <= 0 || ri.IntentID <= 0 {
		return actool.Errorf("patch_verify 需要 worker 任务和意图上下文"), nil
	}
	taskID := strconv.FormatInt(ri.TaskID, 10)
	task, ok := s.m.Task(taskID)
	if !ok || task.Store == nil || task.Store.ID() != ri.ExplorationID {
		return actool.Errorf("patch_verify 无法读取当前任务意图"), nil
	}
	node, err := task.Store.GetNode(ri.IntentID)
	if err != nil || node == nil || node.Kind != db.KindIntent {
		return actool.Errorf("patch_verify 无法读取当前任务意图"), nil
	}
	tag := explicitPatchTag(node.Payload)
	if tag == "" {
		return actool.Errorf("patch_verify 需要意图显式设置 patch/audit/rev/firmware/supply chain_tags"), nil
	}

	var a patchVerifyInput
	dec := json.NewDecoder(bytes.NewReader(in))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil || dec.Decode(new(any)) != io.EOF {
		return actool.Errorf("patch_verify 参数无效；只接受已声明的证据元数据，不接受输入内容"), nil
	}
	a.Tag = tag
	plan, err := patchverify.BuildPlan(a.Spec)
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	result := patchverify.Evaluate(plan, a.Regression)
	hashesChecked := s.crossCheckPatchSamples(taskID, a)
	if !hashesChecked && result.Verdict == patchverify.Verified {
		result = patchverify.Result{Verdict: patchverify.Blocked, Reason: "workspace sample files missing, unreadable or hash mismatch"}
	}
	report := patchverify.Report(result, plan, a.Regression)
	if !hashesChecked {
		report += "\nWorkspace sample hash cross-check incomplete or failed.\n"
	}
	out := map[string]any{"verdict": result.Verdict, "reason": result.Reason, "report": report,
		"intent_id": ri.IntentID, "tag": tag, "sample_hash_cross_check": hashesChecked,
		"evidence_hint": "核对报告中的证据引用后，以 report_finding 的 evidence 和当前 intent_id 交接。未验证结论不应提报为已确认漏洞。"}
	if result.Verdict == patchverify.Verified {
		switch a.Severity {
		case "critical", "high", "medium", "low":
			class := strings.TrimSpace(a.VulnClass)
			if class == "" {
				class = "patch-regression"
			}
			finding := map[string]any{"vulnclass": class, "severity": a.Severity,
				"summary": "补丁回归证据满足可达性与对照判据", "evidence": report,
				"intent_id": ri.IntentID, "asset_ids": a.AssetIDs}
			out["recommended_finding"] = finding
			out["recommended_findings"] = []any{finding}
		}
	}
	return jsonResult(out)
}
