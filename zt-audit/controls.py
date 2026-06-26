"""Foundation control definitions for the repo-scope agent posture audit.

Each control mirrors an ID from the Agent Security Posture Assessment workbook.
`scope` is one of:
  - "repo":   deterministically checkable from the repository's .claude/ config
  - "manual": requires out-of-band verification (e.g. sandbox), reported as INFO
  - "na":     assessed in the full deployment assessment, not at repo scope
"""

CONTROLS = [
    ("IA-01", "Identity & Auth",        "Unique cryptographic agent identity",          "na",
     "Ephemeral coding-agent sessions; agent identity assessed at deployment scope."),
    ("IA-02", "Identity & Auth",        "No static keys / credentials out of reach",    "repo",
     "Secret-scan + file-guard keep credentials out of code and out of agent reach."),
    ("AC-01", "Access Control",         "RBAC with deny-by-default",                    "repo",
     "settings.json deny list + a registered PreToolUse Bash guard."),
    ("AC-02", "Access Control",         "Least-privilege scoping per subagent",         "repo",
     "Every subagent definition carries a bounded `tools:` allowlist."),
    ("AC-03", "Access Control",         "Identity-based isolation / sandbox",           "manual",
     "Hooks are not a sandbox; verify OS-level isolation (container, egress policy)."),
    ("OA-01", "Observability",          "Comprehensive action logging",                 "repo",
     "A logging hook fires on every tool call (PreToolUse * matcher)."),
    ("OA-02", "Observability",          "Traceability (session/agent ids)",             "repo",
     "Log records carry session_id and subagent attribution."),
    ("BM-01", "Behavioral Monitoring",  "Documented expected-behavior baseline",        "na",
     "Runtime behavioral baseline assessed in the monitoring platform, not the repo."),
    ("BM-02", "Behavioral Monitoring",  "Threshold alerts + first-pass triage",         "na",
     "Runtime telemetry concern; assessed in the monitoring platform."),
    ("BM-03", "Behavioral Monitoring",  "Alert routing & response procedures",          "na",
     "Operational concern; assessed in the monitoring platform."),
    ("IO-01", "Input/Output Controls",  "Untrusted-input handling",                     "repo",
     "File-guard limits untrusted reads; WebFetch is gated; researcher agent flags untrusted content."),
    ("IO-02", "Input/Output Controls",  "Output filtering for secrets",                 "repo",
     "A secret-scan hook blocks writes that contain credential material."),
    ("IR-01", "Integrity & Recovery",   "Version-controlled, integrity-protected config","repo",
     "Policy lives in git and is write-protected from the agent."),
    ("IR-02", "Integrity & Recovery",   "Documented, tested rollback",                  "na",
     "Provided by git history; rollback procedure documented at deployment scope."),
    ("MP-01", "Memory Protection",      "Memory & session isolation",                   "na",
     "Coding agent is largely stateless; memory controls assessed where memory persists."),
    ("MP-02", "Memory Protection",      "Context integrity validation",                 "na",
     "Assessed where persisted context/RAG exists."),
    ("MP-03", "Memory Protection",      "Context retention / TTL",                      "na",
     "Assessed where persisted context exists."),
    ("GV-01", "Governance",             "Documented acceptable use",                    "repo",
     "CLAUDE.md states the acceptable-use policy for agents in this repo."),
    ("GV-02", "Governance",             "Agent-compromise incident response",           "na",
     "Org-level IR procedure; assessed at deployment scope."),
    ("GV-03", "Governance",             "Pack installed / deployment gate",             "repo",
     "The policy pack is present and this audit gates the build."),
]
