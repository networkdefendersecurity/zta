package auditlog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/networkdefendersecurity/zta/internal/policy"
)

func TestLog_WritesJSONL(t *testing.T) {
	root := t.TempDir()
	t.Setenv("ZTA_LOG", "") // use the default destination under root

	Log(root, &policy.Event{Agent: "claude-code", Session: "s1", Action: policy.ActionExec, Command: "rm -rf /"},
		policy.Decision{Allow: false, Control: "AC-01", Rule: "destructive-delete"})
	Log(root, &policy.Event{Agent: "claude-code", Action: policy.ActionExec, Command: "npm test"},
		policy.Decision{Allow: true})

	b, err := os.ReadFile(filepath.Join(root, ".zta", "logs", "audit.jsonl"))
	if err != nil {
		t.Fatalf("log not written: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 records, got %d", len(lines))
	}
	var first Record
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("record is not valid JSON: %v", err)
	}
	if first.Decision != "block" || first.Control != "AC-01" || first.Session != "s1" || first.Agent != "claude-code" {
		t.Errorf("unexpected record: %+v", first)
	}
	var second Record
	json.Unmarshal([]byte(lines[1]), &second)
	if second.Decision != "allow" {
		t.Errorf("second record decision = %q, want allow", second.Decision)
	}
}

func TestLog_NeverRecordsContent(t *testing.T) {
	root := t.TempDir()
	t.Setenv("ZTA_LOG", "")
	secret := "AKIAIOSFODNN7EXAMPLE"
	Log(root, &policy.Event{Agent: "codex", Action: policy.ActionFileWrite, Path: "cfg.go", Content: secret},
		policy.Decision{Allow: false, Control: "IO-02", Rule: "aws-access-key"})

	b, _ := os.ReadFile(filepath.Join(root, ".zta", "logs", "audit.jsonl"))
	if strings.Contains(string(b), secret) {
		t.Fatalf("audit log leaked secret content: %s", b)
	}
	if !strings.Contains(string(b), "cfg.go") {
		t.Errorf("expected the path to be logged: %s", b)
	}
}

func TestLog_Disabled(t *testing.T) {
	root := t.TempDir()
	t.Setenv("ZTA_LOG", "off")
	Log(root, &policy.Event{Agent: "x", Action: policy.ActionExec, Command: "ls"}, policy.Decision{Allow: true})
	if _, err := os.Stat(filepath.Join(root, ".zta", "logs", "audit.jsonl")); !os.IsNotExist(err) {
		t.Errorf("ZTA_LOG=off should write nothing, but a log exists")
	}
}

func TestLog_CustomPath(t *testing.T) {
	root := t.TempDir()
	custom := filepath.Join(root, "custom", "trail.jsonl")
	t.Setenv("ZTA_LOG", custom)
	Log(root, &policy.Event{Agent: "x", Action: policy.ActionExec, Command: "ls"}, policy.Decision{Allow: true})
	if _, err := os.Stat(custom); err != nil {
		t.Errorf("ZTA_LOG path not honored: %v", err)
	}
}
