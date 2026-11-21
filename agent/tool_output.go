package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/llm"
	actool "github.com/Autumn-27/norma/tool"
)

const toolOutputCap = 30000

// Attach after all host tools (including noa and WebFetch) have been added.
func attachToolOutputSpilling(opts *agentcore.Options) {
	base := opts.Tools
	if base == nil {
		base = actool.DefaultTools()
	}
	opts.Tools = make([]actool.CoreTool, len(base))
	for i, t := range base {
		opts.Tools[i] = &outputSpillTool{CoreTool: t}
	}
}

type outputSpillTool struct{ actool.CoreTool }

func (t *outputSpillTool) AcceptsRawInput() bool {
	raw, ok := t.CoreTool.(interface{ AcceptsRawInput() bool })
	return ok && raw.AcceptsRawInput()
}

func (t *outputSpillTool) Call(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	var inner actool.ToolContext
	if tc != nil {
		inner = *tc
	}
	// Read adds a bonus to this limit; leave arithmetic headroom.
	inner.MaxOutputChars = int(^uint(0)>>1) / 2
	res, err := t.CoreTool.Call(ctx, in, &inner)
	if err != nil {
		return res, err
	}
	res.Content = append([]llm.ContentBlock(nil), res.Content...)
	for i, block := range res.Content {
		if block.Type == llm.BlockText {
			res.Content[i].Text = t.capture(tc, block.Text)
		}
	}
	return res, nil
}

func (t *outputSpillTool) capture(tc *actool.ToolContext, output string) string {
	limit := toolOutputCap
	if tc != nil && tc.MaxOutputChars > 0 {
		limit = tc.MaxOutputChars
	}
	if len(output) <= limit {
		return output
	}
	headEnd, tailStart := limit/2, len(output)-(limit-limit/2)
	for headEnd > 0 && !utf8.RuneStart(output[headEnd]) {
		headEnd--
	}
	for tailStart < len(output) && !utf8.RuneStart(output[tailStart]) {
		tailStart++
	}
	lost := tailStart - headEnd
	path, err := spillToolOutput(tc, output)
	var marker string
	if err != nil {
		agentID, toolUseID := "", ""
		if tc != nil {
			agentID, toolUseID = tc.AgentID, tc.ToolUseID
		}
		log.Printf("[tool-output] tool=%s agent=%s tool_use=%s spill FAILED: %v; middle %d bytes lost", t.Name(), agentID, toolUseID, err, lost)
		message := err.Error()
		if len(message) > 512 {
			message = strings.ToValidUTF8(message[:512], "�") + "..."
		}
		marker = fmt.Sprintf("[output truncated; spill FAILED: %s; middle %d bytes lost — re-run with narrower output]", message, lost)
	} else {
		ref := path
		if tc != nil && tc.WorkingDir != "" {
			if rel, err := filepath.Rel(tc.WorkingDir, path); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				ref = rel
			}
		}
		marker = fmt.Sprintf("[Output too large: full %d bytes / %d lines; full output: %s]", len(output), strings.Count(output, "\n")+1, ref)
	}
	// CaptureOnce must recognize both outcomes rather than silently capturing again.
	return output[:headEnd] + "\n\n... <persisted-output>" + marker + "</persisted-output>\n\n" + output[tailStart:]
}

func spillToolOutput(tc *actool.ToolContext, output string) (string, error) {
	if tc == nil || tc.OutputDir == "" {
		return "", fmt.Errorf("output directory is not configured")
	}
	dir, err := filepath.Abs(tc.OutputDir)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(dir, "output-*.txt")
	if err != nil {
		return "", err
	}
	n, writeErr := io.WriteString(f, output)
	closeErr := f.Close()
	if writeErr == nil && n != len(output) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		_ = os.Remove(f.Name())
		return "", writeErr
	}
	return f.Name(), nil
}
