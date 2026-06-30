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

// sandboxOnly agents have no enforceable pre-tool-call hook; they are guided to
// the sandbox tier instead. (Cursor, Codex, and Copilot gained blocking hooks in
// 2025–2026 and are wired directly; Windsurf has no documented blocking hook.)
var sandboxOnly = map[string]string{
	"windsurf": "Windsurf",
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

	dir := opts.Dir
	switch opts.Agent {
	case "claude-code":
		// Claude Code: PreToolUse hooks in .claude/settings.json.
		if err := p.wireClaudeStyle(filepath.Join(dir, ".claude", "settings.json"), "claude-code", "Bash|Read|Edit|Write|NotebookEdit", opts); err != nil {
			return nil, err
		}
	case "codex":
		// Codex: Claude-compatible PreToolUse hooks in .codex/hooks.json.
		if err := p.wireClaudeStyle(filepath.Join(dir, ".codex", "hooks.json"), "codex", "Bash|apply_patch", opts); err != nil {
			return nil, err
		}
		p.Notes = append(p.Notes, verifyNote("Codex"))
	case "cursor":
		// Cursor: per-event hooks in .cursor/hooks.json.
		if err := p.wireEventHooks(filepath.Join(dir, ".cursor", "hooks.json"), "cursor", []string{"beforeShellExecution", "preToolUse", "beforeReadFile"}, opts); err != nil {
			return nil, err
		}
		p.Notes = append(p.Notes, verifyNote("Cursor"))
	case "copilot":
		// Copilot CLI: preToolUse hook in .github/hooks/zta.json.
		if err := p.wireEventHooks(filepath.Join(dir, ".github", "hooks", "zta.json"), "copilot", []string{"preToolUse"}, opts); err != nil {
			return nil, err
		}
		p.Notes = append(p.Notes, verifyNote("Copilot"))
	default:
		if label, ok := sandboxOnly[opts.Agent]; ok {
			p.Notes = append(p.Notes, fmt.Sprintf(
				"%s has no enforceable pre-tool-call hook. Run it under the sandbox tier:\n    zta run -- %s",
				label, opts.Agent))
		} else {
			return nil, fmt.Errorf("unknown agent %q (known: claude-code, codex, cursor, copilot, windsurf)", opts.Agent)
		}
	}

	if err := p.scaffoldClaudeMD(opts); err != nil {
		return nil, err
	}
	if err := p.scaffoldGitignore(opts); err != nil {
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

// wireClaudeStyle merges a `zta guard` PreToolUse hook into a Claude-Code-style
// config (Claude Code's settings.json or Codex's hooks.json), preserving any
// existing configuration. Groups have the shape {matcher, hooks:[{type,command}]}.
func (p *Plan) wireClaudeStyle(path, agent, matcher string, opts Options) error {
	cfg, existed, err := loadJSONObject(path)
	if err != nil {
		return err
	}
	if containsZtaGuard(cfg) && !opts.Force {
		p.Changes = append(p.Changes, Change{path, "skip", "zta guard hook already present"})
		return nil
	}

	hooks, _ := cfg["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
	}
	pre, _ := hooks["PreToolUse"].([]any)
	pre = withoutZtaGuard(pre)
	pre = append(pre, map[string]any{
		"matcher": matcher,
		"hooks":   []any{map[string]any{"type": "command", "command": guardCmd(agent)}},
	})
	hooks["PreToolUse"] = pre
	cfg["hooks"] = hooks

	return p.record(path, cfg, existed, "wire zta guard PreToolUse hook")
}

// wireEventHooks merges a `zta guard` command into per-event hook arrays for
// agents whose config shape is {version, hooks:{<event>:[{type,command}]}}
// (Cursor, Copilot).
func (p *Plan) wireEventHooks(path, agent string, events []string, opts Options) error {
	cfg, existed, err := loadJSONObject(path)
	if err != nil {
		return err
	}
	if containsZtaGuard(cfg) && !opts.Force {
		p.Changes = append(p.Changes, Change{path, "skip", "zta guard hook already present"})
		return nil
	}

	if _, ok := cfg["version"]; !ok {
		cfg["version"] = 1
	}
	hooks, _ := cfg["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
	}
	for _, ev := range events {
		arr, _ := hooks[ev].([]any)
		arr = withoutZtaEntries(arr)
		hooks[ev] = append(arr, guardHookEntry(agent))
	}
	cfg["hooks"] = hooks

	return p.record(path, cfg, existed, "wire zta guard hook for "+strings.Join(events, ", "))
}

// record marshals cfg and queues the write as a create/update change.
func (p *Plan) record(path string, cfg map[string]any, existed bool, detail string) error {
	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	action := "create"
	if existed {
		action = "update"
	}
	p.writes[path] = append(out, '\n')
	p.Changes = append(p.Changes, Change{path, action, detail})
	return nil
}

func guardCmd(agent string) string { return "zta guard --agent " + agent }

// guardHookEntry builds the per-event hook entry that invokes `zta guard`.
// Copilot's documented hook format keys the command by shell (bash/powershell);
// the bare cross-platform "command" field is only confirmed in Copilot's Linux
// cloud sandbox, so for the local CLI we set bash and powershell explicitly and
// keep "command" as the documented fallback. The invocation is shell-agnostic
// (no pipes, quotes, or env expansion), so the same string serves all three.
// Keeping "command" also preserves idempotency: containsZtaGuard keys off it.
func guardHookEntry(agent string) map[string]any {
	cmd := guardCmd(agent)
	if agent == "copilot" {
		return map[string]any{"type": "command", "bash": cmd, "powershell": cmd, "command": cmd}
	}
	return map[string]any{"type": "command", "command": cmd}
}

func verifyNote(label string) string {
	return fmt.Sprintf("%s hook wired. Verify it actually blocks: attempt a denied command (e.g. a force-push) and confirm zta denies it — hook schemas vary by version.", label)
}

// loadJSONObject reads a JSON object file into a map, returning whether it
// existed. A missing file yields an empty map.
func loadJSONObject(path string) (map[string]any, bool, error) {
	cfg := map[string]any{}
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, false, nil
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, true, fmt.Errorf("parse %s: %w", path, err)
	}
	return cfg, true, nil
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

// scaffoldGitignore ensures the machine-local audit log is git-ignored.
func (p *Plan) scaffoldGitignore(opts Options) error {
	path := filepath.Join(opts.Dir, ".gitignore")
	const entry = ".zta/logs/"
	block := "# zta runtime audit log (machine-local)\n" + entry + "\n"

	b, err := os.ReadFile(path)
	if err != nil {
		p.writes[path] = []byte(block)
		p.Changes = append(p.Changes, Change{path, "create", "ignore zta audit log"})
		return nil
	}
	if strings.Contains(string(b), entry) {
		return nil // already ignored; leave the file untouched
	}
	content := string(b)
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	p.writes[path] = []byte(content + "\n" + block)
	p.Changes = append(p.Changes, Change{path, "update", "ignore zta audit log"})
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

// containsZtaGuard reports whether any "command" value anywhere in the config
// already invokes `zta guard`, making init idempotent across config shapes.
func containsZtaGuard(v any) bool {
	switch t := v.(type) {
	case map[string]any:
		if cmd, _ := t["command"].(string); strings.Contains(cmd, "zta guard") {
			return true
		}
		for _, x := range t {
			if containsZtaGuard(x) {
				return true
			}
		}
	case []any:
		for _, x := range t {
			if containsZtaGuard(x) {
				return true
			}
		}
	}
	return false
}

// withoutZtaGuard drops Claude-style PreToolUse groups that contain a zta guard.
func withoutZtaGuard(pre []any) []any {
	out := pre[:0:0]
	for _, g := range pre {
		if !containsZtaGuard(g) {
			out = append(out, g)
		}
	}
	return out
}

// withoutZtaEntries drops flat per-event hook entries that invoke zta guard.
func withoutZtaEntries(arr []any) []any {
	out := arr[:0:0]
	for _, e := range arr {
		if !containsZtaGuard(e) {
			out = append(out, e)
		}
	}
	return out
}
