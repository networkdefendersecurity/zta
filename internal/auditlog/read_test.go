package auditlog

import (
	"bytes"
	"strings"
	"testing"

	"github.com/networkdefendersecurity/zta/internal/policy"
)

// seed writes a known set of decisions (2 allow, 1 block) under root's default log.
func seed(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	t.Setenv("ZTA_LOG", "")
	Log(root, &policy.Event{Agent: "claude-code", Action: policy.ActionExec, Command: "npm test"}, policy.Decision{Allow: true})
	Log(root, &policy.Event{Agent: "claude-code", Action: policy.ActionExec, Command: "rm -rf /"},
		policy.Decision{Allow: false, Control: "AC-01", Rule: "destructive-delete"})
	Log(root, &policy.Event{Agent: "claude-code", Action: policy.ActionFileRead, Path: "~/.ssh/id_rsa"}, policy.Decision{Allow: true})
	return root
}

func TestView_HumanShowsAll(t *testing.T) {
	root := seed(t)
	var out bytes.Buffer
	if err := View(&out, ViewOptions{Root: root}); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d: %q", len(lines), out.String())
	}
	// blocks carry the control/rule tag; allows do not
	if !strings.Contains(out.String(), "[AC-01/destructive-delete]") {
		t.Errorf("block line missing control/rule tag: %s", out.String())
	}
	if strings.Contains(out.String(), "npm test") && strings.Contains(out.String(), "ALLOW") {
		// sanity: allow line present and uppercased
	} else {
		t.Errorf("expected an ALLOW line for npm test: %s", out.String())
	}
}

func TestView_BlockedFilter(t *testing.T) {
	root := seed(t)
	var out bytes.Buffer
	if err := View(&out, ViewOptions{Root: root, OnlyBlocked: true}); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 1 || !strings.Contains(lines[0], "BLOCK") {
		t.Fatalf("expected 1 BLOCK line, got %q", out.String())
	}
}

func TestView_LastN(t *testing.T) {
	root := seed(t)
	var out bytes.Buffer
	if err := View(&out, ViewOptions{Root: root, Lines: 1}); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 line with -n 1, got %d: %q", len(lines), out.String())
	}
	// the last seeded record is the id_rsa read
	if !strings.Contains(lines[0], "id_rsa") {
		t.Errorf("expected the most recent record, got %q", lines[0])
	}
}

func TestView_JSONPassthrough(t *testing.T) {
	root := seed(t)
	var out bytes.Buffer
	if err := View(&out, ViewOptions{Root: root, JSON: true, OnlyBlocked: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"decision":"block"`) || strings.Contains(out.String(), "BLOCK  ") {
		t.Errorf("expected raw JSONL, got %q", out.String())
	}
}

func TestView_NoLogYet(t *testing.T) {
	root := t.TempDir()
	t.Setenv("ZTA_LOG", "")
	var out bytes.Buffer
	if err := View(&out, ViewOptions{Root: root}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "no audit log yet") {
		t.Errorf("expected a friendly 'no log yet' message, got %q", out.String())
	}
}

func TestView_DisabledIsError(t *testing.T) {
	t.Setenv("ZTA_LOG", "off")
	var out bytes.Buffer
	if err := View(&out, ViewOptions{Root: t.TempDir()}); err == nil {
		t.Error("expected an error when logging is disabled")
	}
}

func TestView_ConflictingFilters(t *testing.T) {
	var out bytes.Buffer
	if err := View(&out, ViewOptions{Root: t.TempDir(), OnlyBlocked: true, OnlyAllowed: true}); err == nil {
		t.Error("expected an error when both --blocked and --allowed are set")
	}
}
