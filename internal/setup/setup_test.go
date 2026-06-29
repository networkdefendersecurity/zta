package setup

import (
	"encoding/json"
	"os"
	"path/filepath"
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

func TestInit_NonHookableAgentGuidance(t *testing.T) {
	dir := t.TempDir()
	plan, err := BuildPlan(Options{Dir: dir, Agent: "cursor"})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Notes) == 0 {
		t.Fatal("expected sandbox-tier guidance for a non-hookable agent")
	}
	// must not have wired a settings.json
	if _, err := os.Stat(filepath.Join(dir, ".claude", "settings.json")); err == nil {
		t.Error("cursor init should not write .claude/settings.json")
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
	hooks, _ := cfg["hooks"].(map[string]any)
	pre, _ := hooks["PreToolUse"].([]any)
	return hasZtaGuard(pre)
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
