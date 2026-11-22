package server

import (
	"context"
	"encoding/json"
	"log"
	"time"

	actool "github.com/Autumn-27/norma/tool"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

type toolUsageRecorder interface {
	InsertToolUsage(*db.ToolUsage) error
}

// meteredTool records one row immediately before a catalog tool is invoked. It
// embeds the resolved tool so schema overrides, defaults and permission behavior
// remain unchanged.
type meteredTool struct {
	actool.CoreTool
	recorder toolUsageRecorder
	toolKey  string
	agentKey string
	ri       agent.RunInfo
}

func meterTool(t actool.CoreTool, recorder toolUsageRecorder, toolKey, agentKey string, ri agent.RunInfo) actool.CoreTool {
	if recorder == nil {
		return t
	}
	return &meteredTool{CoreTool: t, recorder: recorder, toolKey: toolKey, agentKey: agentKey, ri: ri}
}

func (m *meteredTool) Call(ctx context.Context, input json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	usage := &db.ToolUsage{
		ToolKey:       m.toolKey,
		AgentKey:      m.agentKey,
		TaskID:        m.ri.TaskID,
		ExplorationID: m.ri.ExplorationID,
		IntentID:      m.ri.IntentID,
		SessionID:     m.ri.SessionID,
	}
	var err error
	if contextual, ok := m.recorder.(interface {
		InsertToolUsageCtx(context.Context, *db.ToolUsage) error
	}); ok {
		err = contextual.InsertToolUsageCtx(writeCtx, usage)
	} else {
		err = m.recorder.InsertToolUsage(usage)
	}
	if err != nil {
		log.Printf("[toolusage] insert %s: %v", m.toolKey, err)
	}
	return m.CoreTool.Call(ctx, input, tc)
}
