// Package cursor adapts Cursor's hooks (introduced in Cursor 1.7) to the engine.
// Cursor invokes a hook per event with a JSON payload on stdin and reads the
// verdict from a JSON object on stdout: {"permission":"allow|deny|ask"}. An exit
// code of 2 also blocks, which we use to stay fail-closed on a deny.
//
// The relevant blocking events carry different shapes:
//   - beforeShellExecution: top-level "command"
//   - preToolUse:           "tool_name" + "tool_input" (Claude-style)
//   - beforeReadFile:       "file_path"
package cursor

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/networkdefendersecurity/zta/internal/adapter"
	"github.com/networkdefendersecurity/zta/internal/policy"
)

func init() { adapter.Register(Adapter{}) }

// Adapter implements adapter.Adapter for Cursor.
type Adapter struct{}

func (Adapter) Name() string { return "cursor" }

type payload struct {
	Command   string         `json:"command"`   // beforeShellExecution
	ToolName  string         `json:"tool_name"` // preToolUse
	ToolInput map[string]any `json:"tool_input"`
	FilePath  string         `json:"file_path"` // beforeReadFile
}

func (Adapter) Parse(r io.Reader) (*policy.Event, error) {
	var in payload
	if err := json.NewDecoder(r).Decode(&in); err != nil {
		return nil, fmt.Errorf("decode cursor hook payload: %w", err)
	}
	switch {
	case in.Command != "":
		return &policy.Event{Agent: "cursor", Action: policy.ActionExec, Command: in.Command}, nil
	case in.ToolName != "":
		return adapter.ClaudeStyleEvent("cursor", in.ToolName, in.ToolInput)
	case in.FilePath != "":
		return &policy.Event{Agent: "cursor", Action: policy.ActionFileRead, Path: in.FilePath}, nil
	default:
		return nil, adapter.ErrPassthrough
	}
}

func (Adapter) Respond(stdout, stderr io.Writer, d policy.Decision) int {
	if d.Allow {
		fmt.Fprintln(stdout, `{"permission":"allow"}`)
		return 0
	}
	msg := fmt.Sprintf("zta: blocked by policy [%s/%s]: %s", d.Control, d.Rule, d.Reason)
	out, _ := json.Marshal(map[string]string{"permission": "deny", "agent_message": msg, "user_message": msg})
	fmt.Fprintln(stdout, string(out))
	return 2 // also blocks, keeping us fail-closed if the JSON is ignored
}
