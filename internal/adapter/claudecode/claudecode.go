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
	str := func(k string) string {
		s, _ := in.ToolInput[k].(string)
		return s
	}

	ev := &policy.Event{Agent: "claude-code", Raw: in.ToolInput}
	switch in.ToolName {
	case "Bash":
		ev.Action = policy.ActionExec
		ev.Command = str("command")
	case "Read":
		ev.Action = policy.ActionFileRead
		ev.Path = str("file_path")
	case "Write":
		ev.Action = policy.ActionFileWrite
		ev.Path = str("file_path")
		ev.Content = str("content")
	case "Edit":
		ev.Action = policy.ActionFileWrite
		ev.Path = str("file_path")
		ev.Content = str("new_string")
	case "NotebookEdit":
		ev.Action = policy.ActionFileWrite
		ev.Path = str("notebook_path")
		ev.Content = str("new_source")
	default:
		return nil, adapter.ErrPassthrough
	}
	return ev, nil
}

func (Adapter) Respond(w io.Writer, d policy.Decision) int {
	if d.Allow {
		return 0
	}
	fmt.Fprintf(w, "zta: blocked by policy [%s/%s]: %s\n", d.Control, d.Rule, d.Reason)
	return 2
}
