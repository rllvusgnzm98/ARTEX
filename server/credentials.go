// credentials.go 装配凭据一等实体的三个 host 工具：add_credential /
// list_credentials / credential_reuse_plan。收割/提权类二进制不进默认必装。
package server

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// initCredentials 建凭据落库访问层（secret AES-GCM，密钥由 jwtKey 派生，
// 与 sessions 不同域标签）。失败只记日志，不拖垮启动。
// 注意：轮换 jwt.key 会使已存 secret 无法解密；本波不做迁移。
func (s *Server) initCredentials() {
	if s.m == nil || s.m.pg == nil {
		return
	}
	s.credStore = db.NewCredentialStore(s.m.pg, s.jwtKey)
}

// credentialTools 返回三个凭据工具。credStore 为 nil（DB 未就绪）时不提供。
func (s *Server) credentialTools() []actool.CoreTool {
	if s.credStore == nil {
		return nil
	}
	return []actool.CoreTool{
		s.addCredentialTool(),
		s.listCredentialsTool(),
		s.credentialReusePlanTool(),
	}
}

func (s *Server) addCredentialTool() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "add_credential",
		Description: "【凭据登记】把从目标读到的口令/hash/密钥/ticket 登记为平台管理的凭据（secret AES-GCM 加密落库）。" +
			"来源（source）写清楚从哪来，并尽量带上 ssh/rdp/smb 等服务关键词，复用打分会用到。" +
			"登记结果只回 credential_id，不明文回显 secret。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"username":      strParam("用户名（可空，如 ticket/token 无用户名时留空）"),
				"cred_type":     strParam("凭据类型:password / hash_nt / hash_lm / hash_sha1 / ticket / ssh_key / token"),
				"secret":        strParam("凭据内容（加密存储，不明文落库，也不写入日志/列表）"),
				"domain":        strParam("域（可选；域凭据在复用打分中加分）"),
				"source":        strParam("来源描述（必填）：从哪台主机/什么方式得到"),
				"host_asset_id": map[string]any{"type": "integer", "description": "凭据来源主机的资产 id（可选；用于同网段打分）"},
			},
			"required": []any{"cred_type", "secret", "source"},
		},
		ReadOnly:    func(json.RawMessage) bool { return false },
		Permissions: sessionPerm,
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a struct {
				Username    string `json:"username"`
				CredType    string `json:"cred_type"`
				Secret      string `json:"secret"`
				Domain      string `json:"domain"`
				Source      string `json:"source"`
				HostAssetID int64  `json:"host_asset_id"`
			}
			_ = json.Unmarshal(in, &a)
			if !db.ValidCredType(a.CredType) {
				return actool.Errorf("非法 cred_type " + a.CredType + "(password/hash_nt/hash_lm/hash_sha1/ticket/ssh_key/token)"), nil
			}
			if a.Secret == "" {
				return actool.Errorf("secret 必填"), nil
			}
			if a.Source == "" {
				return actool.Errorf("source 必填(复用打分与溯源都依赖它)"), nil
			}
			ri := agent.RunInfoFrom(ctx)
			if ri.TaskID <= 0 {
				return actool.Errorf("凭据必须在任务上下文登记(非任务运行无 task 归属)"), nil
			}
			rec := &db.CredentialRecord{
				TaskID: ri.TaskID, HostAssetID: a.HostAssetID, Username: a.Username,
				CredType: a.CredType, Secret: a.Secret, Domain: a.Domain, Source: a.Source,
			}
			id, err := s.credStore.Create(ctx, rec)
			if err != nil {
				log.Printf("[credentials] add_credential 落库失败 task=%d: %v", ri.TaskID, err)
				return actool.Errorf("凭据落库失败:" + err.Error()), nil
			}
			log.Printf("[credentials] add_credential id=%d task=%d type=%s", id, ri.TaskID, a.CredType)
			return jsonResult(map[string]any{"credential_id": id})
		},
	})
}

func (s *Server) listCredentialsTool() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "list_credentials",
		Description: "列出本任务自有凭据，以及仍有效的继承凭据（脱敏：不返回明文 secret，只给 secret_masked）。" +
			"每条带 inherited、source_task_id、scope_basis；自有条目 inherited=false。" +
			"要在本任务复用某条凭据，用 credential_reuse_plan 拿带必要字段的建议。",
		Schema: map[string]any{
			"type":       "object",
			"properties": map[string]any{},
		},
		ReadOnly:    func(json.RawMessage) bool { return true },
		Permissions: sessionPerm,
		Run: func(ctx context.Context, _ json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			ri := agent.RunInfoFrom(ctx)
			if ri.TaskID <= 0 {
				return actool.Errorf("list_credentials 需要任务上下文"), nil
			}
			listed, err := s.credStore.ListInherited(ctx, ri.TaskID)
			if err != nil {
				return actool.Errorf("读取凭据失败:" + err.Error()), nil
			}
			items, skipped := db.PublicCredentials(listed)
			return jsonResult(map[string]any{
				"credentials": items,
				"count":       len(listed.Items),
				"skipped":     skipped,
			})
		},
	})
}

func (s *Server) credentialReusePlanTool() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "credential_reuse_plan",
		Description: "【凭据复用打分】对本任务自有凭据和仍有效的继承凭据 × 本任务范围内的主机资产跑复用打分" +
			"（同网段/域凭据/服务重叠/PtH/已验证），返回得分最高的 top 10 条建议。" +
			"只带官方范围、资产记在来源任务上的子任务也能出候选。" +
			"每条建议含工人在本任务复用所需的必要字段（含 secret）；这些字段只出现在本工具返回中，不得写入列表或日志。",
		Schema: map[string]any{
			"type":       "object",
			"properties": map[string]any{},
		},
		ReadOnly:    func(json.RawMessage) bool { return true },
		Permissions: sessionPerm,
		Run: func(ctx context.Context, _ json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			ri := agent.RunInfoFrom(ctx)
			if ri.TaskID <= 0 {
				return actool.Errorf("credential_reuse_plan 需要任务上下文"), nil
			}
			listed, err := s.credStore.ListInherited(ctx, ri.TaskID)
			if err != nil {
				return actool.Errorf("读取凭据失败:" + err.Error()), nil
			}
			creds := listed.Items
			if len(creds) == 0 {
				// 不可解行在 Skipped：已有登记，只是当前密钥解不开。
				// 不得说「还没有登记凭据」，也不去解密失败行或把明文写进列表/日志。
				if len(listed.Skipped) > 0 {
					return actool.Text("本任务已登记凭据，但当前无法解密，因此无复用建议"), nil
				}
				return actool.Text("本任务还没有登记凭据(add_credential 先登记),无复用建议"), nil
			}
			assets, err := s.m.pg.Assets().QueryDSLInScope("", "ip", ri.TaskID, 2000, 0)
			if err != nil {
				return actool.Errorf("读取资产失败:" + err.Error()), nil
			}
			cands, byID := reuseCandidates(assets)
			type row struct {
				CredID   int64    `json:"cred_id"`
				Username string   `json:"username"`
				CredType string   `json:"cred_type"`
				Secret   string   `json:"secret"`
				Domain   string   `json:"domain,omitempty"`
				AssetID  int64    `json:"asset_id"`
				IP       string   `json:"ip"`
				Score    int      `json:"score"`
				Reasons  []string `json:"reasons"`
			}
			flat := []row{}
			for _, c := range creds {
				var src *db.ReuseCandidate
				if c.HostAssetID != 0 {
					src = byID[c.HostAssetID]
				}
				fields := db.CredentialReuseFields(c)
				secret, _ := fields["secret"].(string)
				domain, _ := fields["domain"].(string)
				for _, sug := range db.ScoreReuse(c, src, cands) {
					flat = append(flat, row{c.ID, c.Username, c.CredType, secret, domain, sug.AssetID, sug.IP, sug.Score, sug.Reasons})
				}
			}
			for i := 0; i < len(flat); i++ {
				for j := i + 1; j < len(flat); j++ {
					if flat[j].Score > flat[i].Score ||
						(flat[j].Score == flat[i].Score && (flat[j].CredID < flat[i].CredID ||
							(flat[j].CredID == flat[i].CredID && flat[j].AssetID < flat[i].AssetID))) {
						flat[i], flat[j] = flat[j], flat[i]
					}
				}
			}
			if len(flat) > 10 {
				flat = flat[:10]
			}
			return jsonResult(map[string]any{
				"suggestions":      flat,
				"credential_count": len(creds),
				"asset_count":      len(cands),
			})
		},
	})
}

// reuseCandidates 把 ip 资产投影为打分候选（服务名取自 open_ports）。
func reuseCandidates(assets []*db.Asset) ([]db.ReuseCandidate, map[int64]*db.ReuseCandidate) {
	out := []db.ReuseCandidate{}
	byID := map[int64]*db.ReuseCandidate{}
	for _, a := range assets {
		if a == nil || a.IP == "" {
			continue
		}
		services := []string{}
		for _, p := range a.OpenPorts {
			if svc, ok := p["service"].(string); ok && svc != "" {
				services = append(services, svc)
			}
		}
		out = append(out, db.ReuseCandidate{
			AssetID: a.ID, IP: a.IP, CSegment: a.CSegment, Services: services,
		})
		byID[a.ID] = &out[len(out)-1]
	}
	return out, byID
}

func (s *Server) seedCredentialTools() {
	if s.m == nil || s.m.pg == nil {
		return
	}
	workerAgents, _ := json.Marshal([]string{"worker"})
	for _, t := range s.credentialTools() {
		schema, _ := json.Marshal(t.InputSchema())
		if err := s.m.PG().SeedTool(t.Name(), t.Description(), schema, workerAgents); err != nil {
			log.Printf("[tools] seed %s 失败: %v", t.Name(), err)
		}
	}
}

// GET /api/credentials?task_id= — 控制台脱敏列表，不含明文 secret。
func (s *Server) intranetListCredentials(w http.ResponseWriter, r *http.Request) {
	if s.credStore == nil {
		writeErr(w, 503, "凭据子系统未就绪(DB 未连接)")
		return
	}
	taskID, ok := parseTaskIDQuery(w, r)
	if !ok {
		return
	}
	var listed db.CredentialList
	var err error
	if taskID > 0 {
		listed, err = s.credStore.ListInherited(r.Context(), taskID)
	} else {
		listed, err = s.credStore.ListAll(r.Context())
	}
	if err != nil {
		writeErr(w, 500, "凭据读取失败: "+err.Error())
		return
	}
	items, skipped := db.PublicCredentials(listed)
	writeJSON(w, 200, map[string]any{"items": items, "skipped": skipped})
}

// observeCredentialVerified 只在平台已经观测到成功（例如 register_session 探针通过并落库）之后调用。
// 凭据属于本任务，或 credential_inheritances 上有指向本任务的 active 行，才 SetVerified(true)。
// 模型文本、越权 id、读取失败都不置位。credID<=0 表示调用方没要求处理。
// 返回的 warning 非空时是非致命说明；verified 为 true 表示已经置位。
func (s *Server) observeCredentialVerified(ctx context.Context, taskID, credID int64) (warning string, verified bool) {
	if credID <= 0 {
		return "", false
	}
	if s == nil || s.credStore == nil {
		return "credential_id 已忽略：凭据子系统未就绪", false
	}
	if taskID <= 0 {
		return "credential_id 已忽略：当前没有任务上下文", false
	}
	rec, err := s.credStore.Get(ctx, credID)
	if err != nil {
		log.Printf("[credentials] verify lookup id=%d task=%d: %v", credID, taskID, err)
		return "credential_id 已忽略：凭据读取失败", false
	}
	belongs := rec != nil && rec.TaskID == taskID
	if !belongs {
		metas, merr := s.credStore.ListInheritedMeta(ctx, taskID)
		if merr != nil {
			log.Printf("[credentials] verify inherit lookup id=%d task=%d: %v", credID, taskID, merr)
			return "credential_id 已忽略：继承关系读取失败", false
		}
		for _, m := range metas {
			if m.CredentialID == credID {
				belongs = true
				break
			}
		}
	}
	if !belongs {
		return "credential_id 不属于本任务，已忽略，不影响本次登记", false
	}
	if err := s.credStore.SetVerified(ctx, credID, true); err != nil {
		log.Printf("[credentials] SetVerified id=%d task=%d: %v", credID, taskID, err)
		return "凭据属于本任务，但标记已验证失败", false
	}
	return "", true
}

// workerCredentialSeed 渲染本任务仍有效的继承凭据线索。查失败或没有继承凭据时返回空串，
// 不带 secret，也不影响 worker 启动。
func (s *Server) workerCredentialSeed(ctx context.Context, taskID int64) string {
	if s == nil || s.credStore == nil || taskID <= 0 {
		return ""
	}
	if ctx == nil {
		ctx = context.Background()
	}
	metas, err := s.credStore.ListInheritedMeta(ctx, taskID)
	if err != nil {
		log.Printf("[credentials] worker credential seed task=%d: %v", taskID, err)
		return ""
	}
	return agent.RenderWorkerCredentialSeed(metas)
}

// POST /api/tasks/{id}/credentials/inherit — 从父任务 / 来源任务幂等重同步继承。
// 无父任务、无来源任务时返回 inherited=0，不报 500。
func (s *Server) intranetSyncInheritedCredentials(w http.ResponseWriter, r *http.Request) {
	if s.credStore == nil {
		writeErr(w, 503, "凭据子系统未就绪(DB 未连接)")
		return
	}
	if s.m == nil || s.m.PG() == nil {
		writeErr(w, 503, "任务管理器未就绪")
		return
	}
	taskID, err := pathID(r, "id")
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	task, err := s.m.PG().GetTask(taskID)
	if err != nil {
		writeErr(w, 500, "任务读取失败: "+err.Error())
		return
	}
	if task == nil {
		writeErr(w, 404, "任务不存在")
		return
	}
	parents := credentialParentTaskIDs(task)
	if len(parents) == 0 {
		writeJSON(w, 200, map[string]any{"inherited": 0})
		return
	}
	total := 0
	skipped := 0
	var first error
	for _, parentID := range parents {
		n, sk, ierr := s.inheritCredentials(parentID, taskID)
		total += n
		skipped += sk
		if ierr != nil && first == nil {
			first = ierr
		}
	}
	if first != nil && total == 0 {
		writeErr(w, 500, "凭据继承失败: "+first.Error())
		return
	}
	if first != nil {
		log.Printf("[credentials] resync inherit task=%d partial: %v", taskID, first)
	}
	writeJSON(w, 200, map[string]any{"inherited": total, "skipped": skipped})
}

// DELETE /api/tasks/{id}/credentials/inherit/{credID} — 撤销一条仍有效的继承。不存在返回 404。
func (s *Server) intranetRevokeInheritedCredential(w http.ResponseWriter, r *http.Request) {
	if s.credStore == nil {
		writeErr(w, 503, "凭据子系统未就绪(DB 未连接)")
		return
	}
	taskID, err := pathID(r, "id")
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	credID, err := pathID(r, "credID")
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := s.credStore.RevokeInherited(r.Context(), taskID, credID); err != nil {
		if strings.Contains(err.Error(), "没有可撤销的继承凭据") {
			writeErr(w, 404, err.Error())
			return
		}
		writeErr(w, 500, "撤销继承失败: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"revoked": true})
}

// credentialParentTaskIDs 合并 parent_ref 与直接来源任务，去掉自身和重复项。
func credentialParentTaskIDs(task *db.Task) []int64 {
	if task == nil {
		return nil
	}
	seen := map[int64]struct{}{}
	out := []int64{}
	add := func(id int64) {
		if id <= 0 || id == task.ID {
			return
		}
		if _, ok := seen[id]; ok {
			return
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	if task.ParentRef != "" {
		if id, err := strconv.ParseInt(task.ParentRef, 10, 64); err == nil {
			add(id)
		}
	}
	for _, id := range task.SourceTaskIDs {
		add(id)
	}
	return out
}
