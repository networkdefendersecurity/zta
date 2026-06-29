package policy

// Default returns the secure-by-default policy compiled into the binary. These
// rules are the agent-agnostic port of the original zero-trust guard set. They
// are deliberately conservative; an optional JSON policy file can extend or
// replace any set (see Load).
func Default() *Policy {
	return &Policy{
		DenyExec: []*Rule{
			{
				Name:    "destructive-delete",
				Control: "AC-01",
				Reason:  "destructive recursive delete (rm -rf of a broad path)",
				Pattern: `(?i)(^|[;&|[:space:]])rm[[:space:]]+(-[a-z]*[rf][a-z]*[[:space:]]+)+(-[a-z]+[[:space:]]+)*(/|~|\$HOME|\*|/\*|\.\.?)([[:space:]]|/|$)`,
			},
			{
				Name:    "pipe-to-shell",
				Control: "AC-01",
				Reason:  "pipe-to-shell (curl|wget … | sh) executes untrusted remote code",
				Pattern: `\|[[:space:]]*(ba|z)?sh([[:space:]]|$)`,
			},
			{
				Name:    "force-push",
				Control: "IA-02",
				Reason:  "force-push overwrites remote history",
				Pattern: `(?i)(git[[:space:]].*push.*(--force([[:space:]]|=|$)|--force-with-lease|[[:space:]]-f([[:space:]]|$))|push[[:space:]].*[[:space:]]\+[^[:space:]:]+:)`,
			},
			{
				Name:    "shell-credential-read",
				Control: "IA-02",
				Reason:  "reads credential material from the shell",
				Pattern: `(?i)(\.env([[:space:]'";|&)]|$)|id_rsa|id_ed25519|\.aws/credentials|\.git-credentials|(^|/)\.ssh/|\.pem([[:space:]'";|&)]|$)|/etc/shadow|\.npmrc)`,
			},
			{
				Name:    "policy-tamper",
				Control: "IR-01",
				Reason:  "tampering with the integrity-protected policy directory",
				Pattern: `(?i)((rm|mv|cp|chmod|chown|truncate|tee|dd|ln|install|sed[[:space:]]+-i)[^|;&]*\.(claude|zta)/|>>?[[:space:]]*[^|;&]*\.(claude|zta)/)`,
			},
		},
		DenyPath: []*Rule{
			{
				Name:    "credential-file",
				Control: "IA-02",
				Reason:  "access to credential material",
				Pattern: `(?i)(id_rsa|id_ed25519|(^|/)\.ssh/|\.aws/credentials|\.git-credentials|(^|/)\.npmrc$|\.pem$|\.key$|(^|/)secrets?(\.|/)|credentials\.json$)`,
			},
		},
		ProtectWrite: []*Rule{
			{
				Name:    "policy-integrity",
				Control: "IR-01",
				Reason:  "the policy directory is integrity-protected; changes go through human review",
				Pattern: `(^|/)\.(claude|zta)/`,
			},
			{
				Name:    "git-internals",
				Control: "IR-01",
				Reason:  "writing to .git/ internals is not allowed",
				Pattern: `(^|/)\.git/`,
			},
		},
		SecretContent: []*Rule{
			{Name: "aws-access-key", Control: "IO-02", Reason: "AWS access key id", Pattern: `AKIA[0-9A-Z]{16}`},
			{Name: "anthropic-key", Control: "IO-02", Reason: "Anthropic API key", Pattern: `sk-ant-[A-Za-z0-9_-]{20,}`},
			{Name: "openai-key", Control: "IO-02", Reason: "OpenAI-style secret key", Pattern: `sk-[A-Za-z0-9]{20,}`},
			{Name: "github-token", Control: "IO-02", Reason: "GitHub token", Pattern: `gh[pousr]_[A-Za-z0-9]{36,}`},
			{Name: "slack-token", Control: "IO-02", Reason: "Slack token", Pattern: `xox[baprs]-[A-Za-z0-9-]{10,}`},
			{Name: "jwt", Control: "IO-02", Reason: "JSON Web Token", Pattern: `eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`},
			{Name: "private-key", Control: "IO-02", Reason: "private key material", Pattern: `-----BEGIN [A-Z ]*PRIVATE KEY-----`},
			{Name: "generic-secret", Control: "IO-02", Reason: "hardcoded secret assignment", Pattern: `(?i)(api[_-]?key|secret|passwd|password|access[_-]?token|auth[_-]?token)[[:space:]]*[=:][[:space:]]*['"][^'"]{8,}['"]`},
		},
	}
}
