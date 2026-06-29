// Package copilot adapts GitHub Copilot CLI's preToolUse hook to the engine.
// Copilot passes a JSON payload on stdin with camelCase fields (toolName,
// toolArgs) and reads the verdict from a JSON object on stdout:
// {"permissionDecision":"allow|deny|ask","permissionDecisionReason":"..."}.
// Copilot is fail-closed by design (a hook error denies the call); we also exit
// 2 on a deny.
//
// toolArgs key names vary by tool/version, so command and content extraction
// tries the common keys and falls back to all string values — a wrong guess
// must never let a dangerous command through unscanned.
package copilot

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/networkdefendersecurity/zta/internal/adapter"
	"github.com/networkdefendersecurity/zta/internal/policy"
)

func init() { adapter.Register(Adapter{}) }

// Adapter implements adapter.Adapter for Copilot CLI.
type Adapter struct{}

func (Adapter) Name() string { return "copilot" }

type payload struct {
	ToolName  string         `json:"toolName"`
	ToolArgs  map[string]any `json:"toolArgs"`
	SessionID string         `json:"sessionId"`
}

func (Adapter) Parse(r io.Reader) (*policy.Event, error) {
	var in payload
	if err := json.NewDecoder(r).Decode(&in); err != nil {
		return nil, fmt.Errorf("decode copilot hook payload: %w", err)
	}
	name := strings.ToLower(in.ToolName)
	var ev *policy.Event
	switch {
	case strings.Contains(name, "bash"), strings.Contains(name, "shell"), strings.Contains(name, "exec"), strings.Contains(name, "run"):
		cmd := firstString(in.ToolArgs, "command", "cmd", "script")
		if cmd == "" {
			cmd = allStrings(in.ToolArgs) // fall back: never miss the command text
		}
		ev = &policy.Event{Agent: "copilot", Action: policy.ActionExec, Command: cmd, Raw: in.ToolArgs}
	case strings.Contains(name, "edit"), strings.Contains(name, "write"), strings.Contains(name, "create"), strings.Contains(name, "patch"):
		ev = &policy.Event{
			Agent:   "copilot",
			Action:  policy.ActionFileWrite,
			Path:    firstString(in.ToolArgs, "path", "file_path", "filePath", "filename"),
			Content: firstNonEmpty(firstString(in.ToolArgs, "content", "newContent", "new_str", "text"), allStrings(in.ToolArgs)),
			Raw:     in.ToolArgs,
		}
	case strings.Contains(name, "view"), strings.Contains(name, "read"), strings.Contains(name, "cat"):
		ev = &policy.Event{
			Agent:  "copilot",
			Action: policy.ActionFileRead,
			Path:   firstString(in.ToolArgs, "path", "file_path", "filePath", "filename"),
		}
	default:
		return nil, adapter.ErrPassthrough
	}
	ev.Session = in.SessionID
	return ev, nil
}

func (Adapter) Respond(stdout, stderr io.Writer, d policy.Decision) int {
	if d.Allow {
		fmt.Fprintln(stdout, `{"permissionDecision":"allow"}`)
		return 0
	}
	msg := fmt.Sprintf("zta: blocked by policy [%s/%s]: %s", d.Control, d.Rule, d.Reason)
	out, _ := json.Marshal(map[string]string{"permissionDecision": "deny", "permissionDecisionReason": msg})
	fmt.Fprintln(stdout, string(out))
	return 2
}

func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// allStrings concatenates every string value in m (sorted by key for
// determinism) so command/content text is matched even under an unexpected key.
func allStrings(m map[string]any) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, " ")
}
