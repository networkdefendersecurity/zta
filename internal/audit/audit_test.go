package audit

import (
	"os"
	"path/filepath"
	"testing"
)

// writeRepo materializes a minimal repo layout under a temp dir.
func writeRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestEvaluate_ZtaWired(t *testing.T) {
	// A repo wired to enforce via `zta guard` (no legacy bash hooks) plus a
	// scoped subagent and an acceptable-use policy.
	root := writeRepo(t, map[string]string{
		".claude/settings.json": `{
			"permissions": {"deny": ["Read(**/.env)"], "ask": ["WebFetch"]},
			"hooks": {"PreToolUse": [
				{"matcher": "Bash|Read|Edit|Write", "hooks": [{"command": "zta guard --agent claude-code"}]}
			]}
		}`,
		".claude/agents/researcher.md": "---\ntools: Read, WebSearch\n---\nresearch agent",
		"CLAUDE.md":                    "# Acceptable use policy for agents",
	})

	res := Evaluate(root)
	wantPass := []string{"IA-02", "AC-01", "AC-02", "IO-01", "IO-02", "IR-01", "GV-01", "GV-03"}
	for _, id := range wantPass {
		if got := res[id].Status; got != Pass {
			t.Errorf("%s = %s, want PASS (%s)", id, got, res[id].Detail)
		}
	}
	// zta has no logging tier yet, so logging controls should not pass.
	if res["OA-01"].Status != Fail {
		t.Errorf("OA-01 = %s, want FAIL (no logging hook)", res["OA-01"].Status)
	}
	if res["AC-03"].Status != Manual {
		t.Errorf("AC-03 = %s, want MANUAL", res["AC-03"].Status)
	}
	if res["IA-01"].Status != NA {
		t.Errorf("IA-01 = %s, want N/A", res["IA-01"].Status)
	}
}

func TestEvaluate_BareRepo(t *testing.T) {
	// No config at all: every repo-scope control should fail.
	root := writeRepo(t, map[string]string{"README.md": "hi"})
	res := Evaluate(root)
	for _, c := range controls {
		if c.Scope != ScopeRepo {
			continue
		}
		if res[c.ID].Status == Pass {
			t.Errorf("%s = PASS on a bare repo, expected a non-pass status", c.ID)
		}
	}
}

func TestEvaluate_UnscopedSubagentFails(t *testing.T) {
	root := writeRepo(t, map[string]string{
		".claude/settings.json":   `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"command":"zta guard"}]}]}}`,
		".claude/agents/loose.md": "---\nname: loose\n---\nno tools allowlist here",
	})
	if got := Evaluate(root)["AC-02"].Status; got != Fail {
		t.Errorf("AC-02 = %s, want FAIL for a subagent without a tools allowlist", got)
	}
}
