// Package policy defines the agent-agnostic security policy model: the
// normalized event an adapter produces, the decision the engine returns, and
// the rule sets that drive it. Secure defaults are compiled into the binary so
// the tool is safe with no config file; an optional JSON file overrides them.
package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
)

// Action is the normalized class of operation an agent is attempting.
type Action string

const (
	ActionExec      Action = "exec"       // run a shell command
	ActionFileRead  Action = "file_read"  // read a file
	ActionFileWrite Action = "file_write" // create/modify a file
	ActionNetwork   Action = "network"    // fetch a URL (e.g. WebFetch)
	ActionMCP       Action = "mcp"        // invoke an MCP tool
)

// Event is an agent operation normalized into a single shape the engine can
// evaluate regardless of which coding agent produced it. Adapters build these.
type Event struct {
	Action  Action // what kind of operation
	Command string // shell command, for ActionExec
	Path    string // target file, for file actions
	Content string // content being written, for ActionFileWrite
	URL     string // target URL, for ActionNetwork
	Tool    string // tool name, for ActionMCP (e.g. mcp__github__create_issue)
	Agent   string // originating agent, e.g. "claude-code"
	Session string // agent session id, for log attribution (optional)
}

// Decision is the engine's verdict on an Event.
type Decision struct {
	Allow   bool   // true = permit the operation
	Reason  string // human-readable explanation when blocked
	Control string // zero-trust control id, e.g. "AC-01"
	Rule    string // name of the rule that matched
}

// Rule is a single named regex check tied to a control. The compiled form is
// cached after Compile.
type Rule struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
	Control string `json:"control"`
	Reason  string `json:"reason"`

	re *regexp.Regexp
}

// Match reports whether s matches the rule's compiled pattern.
func (r *Rule) Match(s string) bool { return r.re != nil && r.re.MatchString(s) }

// Policy is the full set of rules the engine enforces, plus the project root
// used to scope policy-integrity protection to this repo (not every .claude/
// directory on disk).
type Policy struct {
	DenyExec      []*Rule `json:"deny_exec"`      // blocked shell commands
	DenyPath      []*Rule `json:"deny_path"`      // files off-limits to any access
	ProtectWrite  []*Rule `json:"protect_write"`  // paths write-protected within the project
	SecretContent []*Rule `json:"secret_content"` // secret patterns blocked from being written
	DenyNetwork   []*Rule `json:"deny_network"`   // blocked fetch URLs (SSRF, scheme escapes)
	DenyMCP       []*Rule `json:"deny_mcp"`       // blocked MCP tool names (opt-in; empty by default)

	// ProjectRoot scopes ProtectWrite to this directory. Set at runtime, never
	// serialized.
	ProjectRoot string `json:"-"`
}

// Compile prepares all rule regexes for matching. Call once after loading.
func (p *Policy) Compile() error {
	for _, set := range [][]*Rule{p.DenyExec, p.DenyPath, p.ProtectWrite, p.SecretContent, p.DenyNetwork, p.DenyMCP} {
		for _, r := range set {
			re, err := regexp.Compile(r.Pattern)
			if err != nil {
				return fmt.Errorf("rule %q: invalid pattern: %w", r.Name, err)
			}
			r.re = re
		}
	}
	return nil
}

// Load returns the embedded default policy, overlaid with any rule sets present
// in the JSON file at path. An empty path (or a missing file when optional)
// yields the defaults. The returned policy is compiled and ready to use.
func Load(path string, optional bool) (*Policy, error) {
	p := Default()
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			if optional && os.IsNotExist(err) {
				return p, p.Compile()
			}
			return nil, err
		}
		// Unmarshal over the defaults: any rule set the file specifies replaces
		// that default set; sets it omits are kept.
		if err := json.Unmarshal(b, p); err != nil {
			return nil, fmt.Errorf("parse policy %s: %w", path, err)
		}
	}
	return p, p.Compile()
}
