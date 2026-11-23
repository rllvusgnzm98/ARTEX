package server

import (
	"log"
	"runtime"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/config"
)

// runtimeProvenance 组装「这一轮到底是什么在跑」的证据：真实二进制版本、Go 运行时与
// 平台、生效的止损阈值，以及脱敏后的有效配置。
//
// 止损阈值是硬编码的（见 engine 里的 DefaultStopLossPolicy），配置文件里没有开关，
// 所以只看 config.json 无法判断某一轮用的是哪套阈值——必须把当时生效的值一并记下，
// 否则跑分对比没法区分「上下文优化生效」和「换了止损阈值」。
func runtimeProvenance() map[string]any {
	sl := agent.DefaultStopLossPolicy()
	return map[string]any{
		"build_version": BuildVersion,
		"go_version":    runtime.Version(),
		"os":            runtime.GOOS,
		"arch":          runtime.GOARCH,
		"stop_loss": map[string]any{
			"safety_ceiling_seconds": int64(sl.SafetyCeiling.Seconds()),
			"idle_probe_limit":       sl.IdleProbeLimit,
			"repeat_command_limit":   sl.RepeatCommandLimit,
		},
		"config": config.EffectiveSummary(),
	}
}

// stampRunProvenance 在任务第一次真正执行时落一次运行溯源。与 deadline 盖章不同，
// 它对所有任务都做（没有 timeout 的任务同样需要知道自己是哪个 build 跑的），并且
// 只在数据库里还没有证据时写入，重启或升级后不改写既有记录。
func (e *Engine) stampRunProvenance(t *Task) {
	if _, loaded := e.provStamped.LoadOrStore(t.ID, true); loaded {
		return
	}
	if err := e.m.StampTaskRunProvenance(t.ID, BuildVersion, runtimeProvenance()); err != nil {
		log.Printf("[provenance] task %s 记录运行版本/有效配置失败: %v", t.ID, err)
		e.provStamped.Delete(t.ID) // 允许下次重试；失败不影响任务继续跑
		e.m.pg.Health().RecordWriteFailure(t.ExpID, "run_provenance: "+err.Error())
	}
}
