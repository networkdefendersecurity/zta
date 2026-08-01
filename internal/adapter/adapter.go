// Package adapter translates between a specific coding agent's native
// interception format and the normalized policy.Event/Decision the engine uses.
// Each supported agent registers one Adapter; the sandbox tier handles agents
// that expose no usable interception point.
package adapter

import (
	"errors"
	"io"
	"sort"
	"strings"

	"github.com/networkdefendersecurity/zta/internal/policy"
)

// ErrPassthrough signals that an event is outside the policy's scope (e.g. a
// tool this guard doesn't gate) and should be allowed without evaluation.
var ErrPassthrough = errors.New("event not subject to policy")

// Adapter wires one agent's interception protocol to the engine.
type Adapter interface {
	// Name is the stable identifier used on the command line (e.g. "claude-code").
	Name() string
	// Parse reads one interception payload and normalizes it. It returns
	// ErrPassthrough for events the guard does not gate.
	Parse(r io.Reader) (*policy.Event, error)
	// Respond emits the decision in the agent's expected format and returns the
	// process exit code the agent interprets (0 allow, non-zero block). Some
	// agents read the verdict from a JSON object on stdout, others from a
	// message on stderr plus the exit code, so both streams are provided.
	Respond(stdout, stderr io.Writer, d policy.Decision) int
}

// ClaudeStyleEvent maps the Claude Code / Codex hook schema — a tool_name plus a
// tool_input object — to a normalized Event. It returns ErrPassthrough for tools
// the policy does not gate. Shared by the claude-code and codex adapters.
func ClaudeStyleEvent(agent, toolName string, toolInput map[string]any) (*policy.Event, error) {
	get := func(k string) string { s, _ := toolInput[k].(string); return s }
	ev := &policy.Event{Agent: agent}
	switch toolName {
	case "Bash":
		ev.Action, ev.Command = policy.ActionExec, get("command")
	case "Read":
		ev.Action, ev.Path = policy.ActionFileRead, get("file_path")
	case "Write":
		ev.Action, ev.Path, ev.Content = policy.ActionFileWrite, get("file_path"), get("content")
	case "Edit":
		ev.Action, ev.Path, ev.Content = policy.ActionFileWrite, get("file_path"), get("new_string")
	case "NotebookEdit":
		ev.Action, ev.Path, ev.Content = policy.ActionFileWrite, get("notebook_path"), get("new_source")
	case "WebFetch":
		ev.Action, ev.URL = policy.ActionNetwork, get("url")
	default:
		// MCP tool calls are named mcp__<server>__<tool>; gate them by name.
		if strings.HasPrefix(toolName, "mcp__") {
			ev.Action, ev.Tool = policy.ActionMCP, toolName
			return ev, nil
		}
		return nil, ErrPassthrough
	}
	return ev, nil
}

var registry = map[string]Adapter{}

// Register makes an adapter available by name. Called from adapter init().
func Register(a Adapter) { registry[a.Name()] = a }

// Get returns the adapter registered under name, or false.
func Get(name string) (Adapter, bool) {
	a, ok := registry[name]
	return a, ok
}

// Names returns the registered adapter names, sorted.
func Names() []string {
	out := make([]string, 0, len(registry))
	for n := range registry {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
