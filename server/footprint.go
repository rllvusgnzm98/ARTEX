package server

import "github.com/Autumn-27/artex/agent"

func (s *Server) taskFootprint(taskID int64) agent.FootprintToggles {
	if taskID <= 0 || s == nil || s.m == nil || s.m.pg == nil {
		return agent.DefaultFootprint()
	}
	pace, minTouch, noDirtyData, noDestructive, noHarmOthers, err := s.m.pg.TaskFootprint(taskID)
	if err != nil {
		return agent.DefaultFootprint()
	}
	return agent.FootprintToggles{
		Pace: pace, MinTouch: minTouch, NoDirtyData: noDirtyData,
		NoDestructive: noDestructive, NoHarmOthers: noHarmOthers,
	}
}
