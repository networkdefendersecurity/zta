// Package codex adapts OpenAI Codex CLI's PreToolUse hook to the engine. Codex
// uses a Claude-Code-compatible hook schema: a JSON payload on stdin and a
// non-zero (2) exit with the reason on stderr to deny. Its file-edit tool is
// apply_patch rather than Write/Edit.
//
// Coverage note: Codex's PreToolUse currently fires for Bash, apply_patch, and
// MCP calls, and not for every shell path — pair it with Codex's built-in OS
// sandbox (sandbox_mode / approval_policy) for defense in depth.
package codex

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/networkdefendersecurity/zta/internal/adapter"
	"github.com/networkdefendersecurity/zta/internal/policy"
)

func init() { adapter.Register(Adapter{}) }

// Adapter implements adapter.Adapter for Codex CLI.
type Adapter struct{}

func (Adapter) Name() string { return "codex" }

type payload struct {
	ToolName  string         `json:"tool_name"`
	ToolInput map[string]any `json:"tool_input"`
	SessionID string         `json:"session_id"`
}

func (Adapter) Parse(r io.Reader) (*policy.Event, error) {
	var in payload
	if err := json.NewDecoder(r).Decode(&in); err != nil {
		return nil, fmt.Errorf("decode codex hook payload: %w", err)
	}
	if in.ToolName == "apply_patch" {
		// apply_patch's input shape is not stable across versions; gate on the
		// patch text as write content (so secret-in-code rules still apply)
		// rather than guessing a file_path key.
		if patch := firstString(in.ToolInput, "input", "patch", "content"); patch != "" {
			return &policy.Event{Agent: "codex", Action: policy.ActionFileWrite, Content: patch, Session: in.SessionID}, nil
		}
		return nil, adapter.ErrPassthrough
	}
	ev, err := adapter.ClaudeStyleEvent("codex", in.ToolName, in.ToolInput)
	if ev != nil {
		ev.Session = in.SessionID
	}
	return ev, err
}

func (Adapter) Respond(stdout, stderr io.Writer, d policy.Decision) int {
	if d.Allow {
		return 0
	}
	fmt.Fprintf(stderr, "zta: blocked by policy [%s/%s]: %s\n", d.Control, d.Rule, d.Reason)
	return 2
}

// firstString returns the first non-empty string value among keys.
func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}
