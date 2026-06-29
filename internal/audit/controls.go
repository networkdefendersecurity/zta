// Package audit scores a repository's AI-agent configuration against the
// Foundation control catalog and renders a posture scorecard. It is the Go port
// of the original zt-audit Python tool, generalized to recognize zta wiring
// (`zta guard` / `zta run`) alongside the legacy .claude/ bash hooks.
package audit

// Scope classifies how a control is assessed.
type Scope string

const (
	ScopeRepo   Scope = "repo"   // deterministically checkable from repo config
	ScopeManual Scope = "manual" // requires out-of-band verification (reported as MANUAL)
	ScopeNA     Scope = "na"     // assessed in the full deployment assessment, not here
)

// Control is one Foundation-tier control from the Agent Security Posture
// Assessment workbook.
type Control struct {
	ID     string
	Domain string
	Name   string
	Scope  Scope
	Why    string
}

// Status is the outcome of evaluating a control.
type Status string

const (
	Pass    Status = "PASS"
	Partial Status = "PARTIAL"
	Fail    Status = "FAIL"
	Manual  Status = "MANUAL"
	NA      Status = "N/A"
)

// Result pairs a status with a short explanation.
type Result struct {
	Status Status
	Detail string
}

// controls is the catalog, in display order.
var controls = []Control{
	{"IA-01", "Identity & Auth", "Unique cryptographic agent identity", ScopeNA,
		"Ephemeral coding-agent sessions; agent identity assessed at deployment scope."},
	{"IA-02", "Identity & Auth", "No static keys / credentials out of reach", ScopeRepo,
		"Secret-scan + file-guard keep credentials out of code and out of agent reach."},
	{"AC-01", "Access Control", "RBAC with deny-by-default", ScopeRepo,
		"settings.json deny list + a registered PreToolUse command guard."},
	{"AC-02", "Access Control", "Least-privilege scoping per subagent", ScopeRepo,
		"Every subagent definition carries a bounded `tools:` allowlist."},
	{"AC-03", "Access Control", "Identity-based isolation / sandbox", ScopeManual,
		"Hooks are not a sandbox; verify OS-level isolation (container, egress policy)."},
	{"OA-01", "Observability", "Comprehensive action logging", ScopeRepo,
		"A logging hook fires on every tool call (PreToolUse * matcher)."},
	{"OA-02", "Observability", "Traceability (session/agent ids)", ScopeRepo,
		"Log records carry session_id and subagent attribution."},
	{"BM-01", "Behavioral Monitoring", "Documented expected-behavior baseline", ScopeNA,
		"Runtime behavioral baseline assessed in the monitoring platform, not the repo."},
	{"BM-02", "Behavioral Monitoring", "Threshold alerts + first-pass triage", ScopeNA,
		"Runtime telemetry concern; assessed in the monitoring platform."},
	{"BM-03", "Behavioral Monitoring", "Alert routing & response procedures", ScopeNA,
		"Operational concern; assessed in the monitoring platform."},
	{"IO-01", "Input/Output Controls", "Untrusted-input handling", ScopeRepo,
		"File-guard limits untrusted reads; WebFetch is gated; researcher agent flags untrusted content."},
	{"IO-02", "Input/Output Controls", "Output filtering for secrets", ScopeRepo,
		"A secret-scan guard blocks writes that contain credential material."},
	{"IR-01", "Integrity & Recovery", "Version-controlled, integrity-protected config", ScopeRepo,
		"Policy lives in git and is write-protected from the agent."},
	{"IR-02", "Integrity & Recovery", "Documented, tested rollback", ScopeNA,
		"Provided by git history; rollback procedure documented at deployment scope."},
	{"MP-01", "Memory Protection", "Memory & session isolation", ScopeNA,
		"Coding agent is largely stateless; memory controls assessed where memory persists."},
	{"MP-02", "Memory Protection", "Context integrity validation", ScopeNA,
		"Assessed where persisted context/RAG exists."},
	{"MP-03", "Memory Protection", "Context retention / TTL", ScopeNA,
		"Assessed where persisted context exists."},
	{"GV-01", "Governance", "Documented acceptable use", ScopeRepo,
		"CLAUDE.md states the acceptable-use policy for agents in this repo."},
	{"GV-02", "Governance", "Agent-compromise incident response", ScopeNA,
		"Org-level IR procedure; assessed at deployment scope."},
	{"GV-03", "Governance", "Pack installed / deployment gate", ScopeRepo,
		"Enforcement is wired up and this audit gates the build."},
}
