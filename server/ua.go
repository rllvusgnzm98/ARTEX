package server

import "github.com/Autumn-27/artex/agent"

// uaForTask 返回本任务稳定分配的客户端 UA:池子读 settings 键 web_ua_pool
// (JSON 字符串数组,每次 run 现读、改池即时生效),未配置用默认池;
// 同一 taskID 始终拿到同一个 UA,不按请求随机更换。
func (s *Server) uaForTask(taskID int64) string {
	raw := ""
	if s.m != nil && s.m.pg != nil {
		if v, _, err := s.m.pg.GetSetting(settingWebUAPool); err == nil {
			raw = v
		}
	}
	return agent.PickUA(agent.UAPoolFromSetting(raw), taskID)
}
