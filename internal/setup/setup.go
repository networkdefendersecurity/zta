// Package setup implements `zta init`: it wires zta enforcement into a repo for
// a given coding agent, scaffolds the supporting policy docs, and reports what
// it changed. It is idempotent and supports a dry run so users can preview
// changes before anything is written.
package setup

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/networkdefendersecurity/zta/internal/policy"
)

// Options configures an init run.
type Options struct {
	Dir    string // target repo (default ".")
	Agent  string // agent to wire (default "claude-code")
	Policy bool   // also scaffold zta.json
	Force  bool   // overwrite existing zta wiring / scaffolds
}

// Change describes one planned file modification.
type Change struct {
	Path   string // file path, repo-relative for display
	Action string // "create", "update", or "skip"
	Detail string
}

// Plan is the set of changes an init run would make, plus any guidance notes.
type Plan struct {
	Changes []Change
	Notes   []string

	writes map[string][]byte // absolute path -> content to write on Apply
}

// nonHookable agents have no enforceable pre-tool-call hook; they are guided to
// the sandbox tier instead.
var nonHookable = map[string]string{
	"cursor":   "Cursor",
	"windsurf": "Windsurf",
	"copilot":  "GitHub Copilot",
	"codex":    "Codex CLI",
}

// BuildPlan computes the changes for an init run without writing anything.
func BuildPlan(opts Options) (*Plan, error) {
	if opts.Dir == "" {
		opts.Dir = "."
	}
	if opts.Agent == "" {
		opts.Agent = "claude-code"
	}
	p := &Plan{writes: map[string][]byte{}}

	switch opts.Agent {
	case "claude-code":
		if err := p.wireClaude(opts); err != nil {
			return nil, err
		}
	default:
		if label, ok := nonHookable[opts.Agent]; ok {
			p.Notes = append(p.Notes, fmt.Sprintf(
				"%s has no enforceable pre-tool-call hook. Run it under the sandbox tier:\n    zta run -- %s",
				label, opts.Agent))
		} else {
			return nil, fmt.Errorf("unknown agent %q (known: claude-code, %s)",
				opts.Agent, strings.Join(sortedKeys(nonHookable), ", "))
		}
	}

	if err := p.scaffoldClaudeMD(opts); err != nil {
		return nil, err
	}
	if opts.Policy {
		if err := p.scaffoldPolicy(opts); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// Apply writes the planned changes to disk.
func (p *Plan) Apply() error {
	paths := make([]string, 0, len(p.writes))
	for path := range p.writes {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, p.writes[path], 0o644); err != nil {
			return err
		}
	}
	return nil
}

// wireClaude merges a `zta guard` PreToolUse hook into .claude/settings.json,
// preserving any existing configuration.
func (p *Plan) wireClaude(opts Options) error {
	path := filepath.Join(opts.Dir, ".claude", "settings.json")
	cfg := map[string]any{}
	existed := false
	if b, err := os.ReadFile(path); err == nil {
		existed = true
		if err := json.Unmarshal(b, &cfg); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
	}

	hooks, _ := cfg["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
	}
	pre, _ := hooks["PreToolUse"].([]any)

	if hasZtaGuard(pre) && !opts.Force {
		p.Changes = append(p.Changes, Change{path, "skip", "zta guard hook already present"})
		return nil
	}
	if opts.Force {
		pre = withoutZtaGuard(pre)
	}

	pre = append(pre, map[string]any{
		"matcher": "Bash|Read|Edit|Write|NotebookEdit",
		"hooks": []any{map[string]any{
			"type":    "command",
			"command": "zta guard --agent claude-code",
		}},
	})
	hooks["PreToolUse"] = pre
	cfg["hooks"] = hooks

	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')

	action := "create"
	if existed {
		action = "update"
	}
	p.writes[path] = out
	p.Changes = append(p.Changes, Change{path, action, "wire zta guard PreToolUse hook"})
	return nil
}

// scaffoldClaudeMD writes a starter acceptable-use policy if none exists.
func (p *Plan) scaffoldClaudeMD(opts Options) error {
	path := filepath.Join(opts.Dir, "CLAUDE.md")
	if _, err := os.Stat(path); err == nil {
		p.Changes = append(p.Changes, Change{path, "skip", "CLAUDE.md already exists"})
		return nil
	}
	p.writes[path] = []byte(claudeMDTemplate)
	p.Changes = append(p.Changes, Change{path, "create", "acceptable-use policy (GV-01)"})
	return nil
}

// scaffoldPolicy writes a zta.json mirroring the built-in defaults so users can
// see and edit exactly what is enforced.
func (p *Plan) scaffoldPolicy(opts Options) error {
	path := filepath.Join(opts.Dir, "zta.json")
	if _, err := os.Stat(path); err == nil && !opts.Force {
		p.Changes = append(p.Changes, Change{path, "skip", "zta.json already exists (use --force)"})
		return nil
	}
	b, err := json.MarshalIndent(policy.Default(), "", "  ")
	if err != nil {
		return err
	}
	p.writes[path] = append(b, '\n')
	action := "create"
	if _, err := os.Stat(path); err == nil {
		action = "update"
	}
	p.Changes = append(p.Changes, Change{path, action, "starter policy mirroring built-in defaults"})
	return nil
}

func hasZtaGuard(pre []any) bool {
	for _, g := range pre {
		if groupHasZtaGuard(g) {
			return true
		}
	}
	return false
}

func withoutZtaGuard(pre []any) []any {
	out := pre[:0:0]
	for _, g := range pre {
		if !groupHasZtaGuard(g) {
			out = append(out, g)
		}
	}
	return out
}

func groupHasZtaGuard(group any) bool {
	gm, _ := group.(map[string]any)
	hs, _ := gm["hooks"].([]any)
	for _, h := range hs {
		hm, _ := h.(map[string]any)
		if cmd, _ := hm["command"].(string); strings.Contains(cmd, "zta guard") {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
