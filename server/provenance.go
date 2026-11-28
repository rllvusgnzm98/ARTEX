package server

import (
	"log"
	"runtime"
	"runtime/debug"

	"github.com/Autumn-27/artex/config"
)

// buildIdentity 返回不可变的构建身份：提交 SHA、工作区是否有未提交改动。
//
// 版本标签（BuildVersion）不是提交身份：它可被 -ldflags 覆盖、release 用的是 tag、
// plain go build 与 dev.sh 的 go run 则一律退化成 "dev"。Go 工具链会把 VCS 信息编进
// 二进制（实测 go build 有 vcs.revision/vcs.modified，go run 没有），所以这里如实返回
// ok=false 表示「这一轮没有提交级证据」，而不是拿当前检出倒推。
func buildIdentity() (commit string, dirty, ok bool) {
	bi, available := debug.ReadBuildInfo()
	if !available {
		return "", false, false
	}
	for _, setting := range bi.Settings {
		switch setting.Key {
		case "vcs.revision":
			commit = setting.Value
		case "vcs.modified":
			dirty = setting.Value == "true"
		}
	}
	if commit == "" {
		return "", false, false
	}
	return commit, dirty, true
}

// runtimeProvenance 组装「这一轮到底是什么在跑」的证据：真实二进制版本、Go 运行时与
// 平台、生效的配置，以及脱敏后的有效配置。
//
// 重规划冷却等参数默认内建并支持环境变量覆盖（见 resolvePlanCooldown），配置文件里
// 没有开关，所以只看 config.json 无法判断某一轮用的是哪套阈值——必须把当时生效的值
// 一并记下。
func (e *Engine) runtimeProvenance() map[string]any {
	cfg := config.EffectiveSummary()
	// 每主机礼貌限速可由 Settings 在运行期改写（Manager.SetHostPace 持久化并即时应用），
	// config 侧只看得到启动默认值，生效值只有 Manager 知道——溯源必须记后者。
	if e != nil && e.m != nil {
		cfg["host_pace_rps"] = e.m.HostPace()
	}
	var cooldownSec int64
	if e != nil {
		cooldownSec = int64(e.PlanCooldown().Seconds())
	}
	out := map[string]any{
		"build_version": BuildVersion,
		"go_version":    runtime.Version(),
		"os":            runtime.GOOS,
		"arch":          runtime.GOARCH,
		"stop_loss": map[string]any{
			"enabled": false,
		},
		"planner_cooldown_seconds": cooldownSec,
		"config":                   cfg,
	}
	// 提交身份与版本标签分开记：没有 VCS 证据时如实留空（go run 就是这种），不要让
	// 一个 "dev" 冒充「记录过」。
	if commit, dirty, ok := buildIdentity(); ok {
		out["build_commit"] = commit
		out["build_commit_dirty"] = dirty
		out["build_commit_source"] = "vcs"
	} else {
		out["build_commit_source"] = "unknown"
	}
	return out
}

// stampRunProvenance 在任务第一次真正执行时落一次运行溯源。与 deadline 盖章不同，
// 它对所有任务都做（没有 timeout 的任务同样需要知道自己是哪个 build 跑的），并且
// 只在数据库里还没有证据时写入，重启或升级后不改写既有记录。
func (e *Engine) stampRunProvenance(t *Task) {
	if _, loaded := e.provStamped.LoadOrStore(t.ID, true); loaded {
		return
	}
	if err := e.m.StampTaskRunProvenance(t.ID, BuildVersion, e.runtimeProvenance()); err != nil {
		log.Printf("[provenance] task %s 记录运行版本/有效配置失败: %v", t.ID, err)
		e.provStamped.Delete(t.ID) // 允许下次重试；失败不影响任务继续跑
		e.m.pg.Health().RecordWriteFailure(t.ExpID, "run_provenance: "+err.Error())
	}
}
