// Package claudecode adapts Claude Code's PreToolUse hook protocol to the
// engine. Claude Code invokes a hook with a JSON payload on stdin and treats a
// non-zero (specifically 2) exit as a block, with stderr shown as the reason.
package claudecode

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/networkdefendersecurity/zta/internal/adapter"
	"github.com/networkdefendersecurity/zta/internal/policy"
)

func init() { adapter.Register(Adapter{}) }

// Adapter implements adapter.Adapter for Claude Code.
type Adapter struct{}

func (Adapter) Name() string { return "claude-code" }

// payload is the subset of the PreToolUse hook JSON we consume.
type payload struct {
	ToolName  string         `json:"tool_name"`
	ToolInput map[string]any `json:"tool_input"`
}

func (Adapter) Parse(r io.Reader) (*policy.Event, error) {
	var in payload
	if err := json.NewDecoder(r).Decode(&in); err != nil {
		return nil, fmt.Errorf("decode hook payload: %w", err)
	}
	return adapter.ClaudeStyleEvent("claude-code", in.ToolName, in.ToolInput)
}

func (Adapter) Respond(stdout, stderr io.Writer, d policy.Decision) int {
	if d.Allow {
		return 0
	}
	// Claude Code feeds the hook's stderr back to the model on a non-zero exit.
	fmt.Fprintf(stderr, "zta: blocked by policy [%s/%s]: %s\n", d.Control, d.Rule, d.Reason)
	return 2
}
