// Package auditlog appends an attribution record for every gated decision to a
// machine-local JSONL log (controls OA-01 / OA-02). It is best-effort: a logging
// failure never blocks or alters enforcement. It never records file content,
// which may itself be the secret a write rule is blocking.
package auditlog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/networkdefendersecurity/zta/internal/policy"
)

const maxCommand = 512 // cap logged command length to keep lines small and append atomic

// Record is one line of the audit log.
type Record struct {
	Time     string `json:"time"`
	Agent    string `json:"agent,omitempty"`
	Session  string `json:"session,omitempty"`
	Action   string `json:"action"`
	Command  string `json:"command,omitempty"`
	Path     string `json:"path,omitempty"`
	URL      string `json:"url,omitempty"`
	Tool     string `json:"tool,omitempty"`
	Decision string `json:"decision"` // "allow" or "block"
	Control  string `json:"control,omitempty"`
	Rule     string `json:"rule,omitempty"`
	PID      int    `json:"pid"`
}

// Log appends a record for ev/d under the project root. Set ZTA_LOG to a file
// path to redirect the log, or to "off"/"none"/"0" to disable it.
func Log(root string, ev *policy.Event, d policy.Decision) {
	dest := destination(root)
	if dest == "" {
		return
	}
	rec := Record{
		Time:     time.Now().UTC().Format(time.RFC3339),
		Agent:    ev.Agent,
		Session:  ev.Session,
		Action:   string(ev.Action),
		Command:  truncate(ev.Command),
		Path:     ev.Path, // path only — never ev.Content
		URL:      truncate(ev.URL),
		Tool:     ev.Tool,
		Decision: decision(d),
		Control:  d.Control,
		Rule:     d.Rule,
		PID:      os.Getpid(),
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return
	}
	f, err := os.OpenFile(dest, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	f.Write(append(line, '\n'))
}

// Path returns the resolved audit-log file path for root, or "" when logging is
// disabled (ZTA_LOG=off). It mirrors the destination Log writes to, so readers
// (e.g. `zta log`) and the writer agree on a single location.
func Path(root string) string { return destination(root) }

// destination resolves the log file path, or "" when logging is disabled. The
// default lives under the integrity-protected .zta/ directory so the agent
// cannot tamper with it.
func destination(root string) string {
	if v := os.Getenv("ZTA_LOG"); v != "" {
		switch strings.ToLower(v) {
		case "off", "none", "0", "false":
			return ""
		default:
			return v
		}
	}
	if root == "" {
		root = "."
	}
	return filepath.Join(root, ".zta", "logs", "audit.jsonl")
}

func decision(d policy.Decision) string {
	if d.Allow {
		return "allow"
	}
	return "block"
}

func truncate(s string) string {
	if len(s) > maxCommand {
		return s[:maxCommand] + "…"
	}
	return s
}
