package setup

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/networkdefendersecurity/zta/internal/policy"
)

func TestInit_FreshRepo(t *testing.T) {
	dir := t.TempDir()
	plan, err := BuildPlan(Options{Dir: dir, Agent: "claude-code"})
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Apply(); err != nil {
		t.Fatal(err)
	}

	// settings.json wired with a zta guard PreToolUse hook
	cfg := readJSON(t, filepath.Join(dir, ".claude", "settings.json"))
	if !wiredHasGuard(cfg) {
		t.Fatalf("settings.json not wired with zta guard: %v", cfg)
	}
	// CLAUDE.md scaffolded
	if _, err := os.Stat(filepath.Join(dir, "CLAUDE.md")); err != nil {
		t.Fatalf("CLAUDE.md not created: %v", err)
	}
}

func TestInit_Idempotent(t *testing.T) {
	dir := t.TempDir()
	first, _ := BuildPlan(Options{Dir: dir, Agent: "claude-code"})
	if err := first.Apply(); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(dir, ".claude", "settings.json"))

	// second run should skip and write nothing new
	second, err := BuildPlan(Options{Dir: dir, Agent: "claude-code"})
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Apply(); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, ".claude", "settings.json"))
	if string(before) != string(after) {
		t.Fatal("settings.json changed on a second init (not idempotent)")
	}
	if !hasSkip(second.Changes, ".claude/settings.json") {
		t.Errorf("second run did not skip the settings.json wiring: %+v", second.Changes)
	}
}

func TestInit_PreservesExistingConfig(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, ".claude", "settings.json"), `{
		"permissions": {"deny": ["Read(**/.env)"]},
		"hooks": {"PreToolUse": [
			{"matcher": "*", "hooks": [{"type": "command", "command": "bash .claude/hooks/zt-log.sh"}]}
		]}
	}`)

	plan, err := BuildPlan(Options{Dir: dir, Agent: "claude-code"})
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Apply(); err != nil {
		t.Fatal(err)
	}

	cfg := readJSON(t, filepath.Join(dir, ".claude", "settings.json"))
	// existing permissions preserved
	perms, _ := cfg["permissions"].(map[string]any)
	if perms == nil || perms["deny"] == nil {
		t.Errorf("existing permissions.deny was dropped: %v", cfg)
	}
	// existing logging hook preserved AND zta guard added
	hooks, _ := cfg["hooks"].(map[string]any)
	pre, _ := hooks["PreToolUse"].([]any)
	if len(pre) != 2 {
		t.Fatalf("expected 2 PreToolUse groups (existing + zta), got %d", len(pre))
	}
	if !wiredHasGuard(cfg) {
		t.Error("zta guard hook not added alongside existing hook")
	}
}

func TestInit_PolicyScaffoldIsValid(t *testing.T) {
	dir := t.TempDir()
	plan, err := BuildPlan(Options{Dir: dir, Agent: "claude-code", Policy: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Apply(); err != nil {
		t.Fatal(err)
	}
	// the scaffolded policy must load cleanly through the real loader
	if _, err := policy.Load(filepath.Join(dir, "zta.json"), false); err != nil {
		t.Fatalf("scaffolded zta.json does not load: %v", err)
	}
}

func TestInit_SandboxOnlyAgentGuidance(t *testing.T) {
	dir := t.TempDir()
	plan, err := BuildPlan(Options{Dir: dir, Agent: "windsurf"})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Notes) == 0 {
		t.Fatal("expected sandbox-tier guidance for a non-hookable agent")
	}
	for _, f := range []string{".claude/settings.json", ".cursor/hooks.json", ".codex/hooks.json"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
			t.Errorf("windsurf init should not write %s", f)
		}
	}
}

func TestInit_HookableAgents(t *testing.T) {
	cases := []struct{ agent, cfg string }{
		{"codex", ".codex/hooks.json"},
		{"cursor", ".cursor/hooks.json"},
		{"copilot", ".github/hooks/zta.json"},
	}
	for _, tc := range cases {
		t.Run(tc.agent, func(t *testing.T) {
			dir := t.TempDir()
			plan, err := BuildPlan(Options{Dir: dir, Agent: tc.agent})
			if err != nil {
				t.Fatal(err)
			}
			if err := plan.Apply(); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, tc.cfg)
			if !containsZtaGuard(readJSON(t, path)) {
				t.Fatalf("%s: %s missing a zta guard command", tc.agent, tc.cfg)
			}
			before, _ := os.ReadFile(path)
			if !strings.Contains(string(before), "--agent "+tc.agent) {
				t.Errorf("%s: command does not target the agent: %s", tc.agent, before)
			}
			// idempotent
			second, _ := BuildPlan(Options{Dir: dir, Agent: tc.agent})
			if err := second.Apply(); err != nil {
				t.Fatal(err)
			}
			after, _ := os.ReadFile(path)
			if string(before) != string(after) {
				t.Errorf("%s: init not idempotent", tc.agent)
			}
		})
	}
}

func TestInit_CopilotCrossShell(t *testing.T) {
	dir := t.TempDir()
	plan, err := BuildPlan(Options{Dir: dir, Agent: "copilot"})
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Apply(); err != nil {
		t.Fatal(err)
	}

	cfg := readJSON(t, filepath.Join(dir, ".github", "hooks", "zta.json"))
	hooks, _ := cfg["hooks"].(map[string]any)
	pre, _ := hooks["preToolUse"].([]any)
	if len(pre) != 1 {
		t.Fatalf("expected 1 preToolUse entry, got %d: %v", len(pre), pre)
	}
	entry, _ := pre[0].(map[string]any)
	// Copilot's local CLI is keyed by shell; "command" is only a confirmed
	// fallback in the Linux cloud sandbox. Set all three to the guard command.
	const want = "zta guard --agent copilot"
	for _, k := range []string{"bash", "powershell", "command"} {
		if got, _ := entry[k].(string); got != want {
			t.Errorf("copilot hook %q = %q, want %q", k, got, want)
		}
	}

	// the extra keys must not break idempotency (detection keys off "command")
	before, _ := os.ReadFile(filepath.Join(dir, ".github", "hooks", "zta.json"))
	second, _ := BuildPlan(Options{Dir: dir, Agent: "copilot"})
	if err := second.Apply(); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, ".github", "hooks", "zta.json"))
	if string(before) != string(after) {
		t.Error("copilot init not idempotent with cross-shell keys")
	}
}

// helpers

func readJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("invalid JSON at %s: %v", path, err)
	}
	return m
}

func wiredHasGuard(cfg map[string]any) bool {
	return containsZtaGuard(cfg)
}

func hasSkip(changes []Change, suffix string) bool {
	for _, c := range changes {
		if c.Action == "skip" && filepath.Base(c.Path) == filepath.Base(suffix) {
			return true
		}
	}
	return false
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
