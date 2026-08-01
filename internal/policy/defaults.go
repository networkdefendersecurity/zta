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
				// Matches `rm` as a command word — tolerating a path prefix
				// (/bin/rm) or a shell escape (\rm) so those do not slip the
				// anchor — followed by at least one recursive/force flag in
				// either short (-rf, -r) or long (--recursive, --force) form,
				// then a broad/system target path.
				Pattern: `(?i)(^|[;&|[:space:]])(\\|[^[:space:];&|]*/)?rm[[:space:]]+(--?[a-z][a-z-]*[[:space:]]+)*(-[a-z]*[rf][a-z]*|--recursive|--force)[[:space:]]+(--?[a-z][a-z-]*[[:space:]]+)*(/|~|\$HOME|\*|/\*|\.\.?)([[:space:]]|/|$)`,
			},
			{
				Name:    "pipe-to-shell",
				Control: "AC-01",
				Reason:  "pipe-to-shell (curl|wget … | sh) executes untrusted remote code",
				// Any pipe into a shell interpreter, optionally by path
				// (| /bin/bash). Covers sh, bash, zsh, dash, ash, ksh, fish.
				Pattern: `\|[[:space:]]*(/[^[:space:]|;&]*/)?((ba|z|da|a|k)?sh|fish)([[:space:]]|$)`,
			},
			{
				Name:    "fetch-to-interpreter",
				Control: "AC-01",
				Reason:  "executing fetched remote code (curl|wget|fetch piped or substituted into an interpreter/eval)",
				// Targets remote-code execution specifically — a fetch tool must
				// be present — so ordinary local pipes (cat x | python) and output
				// capture (x=$(curl …)) are not flagged. Covers `curl … | python`,
				// `eval "$(curl …)"`, and `bash <(curl …)` and friends.
				Pattern: `(?i)(\b(curl|wget|fetch)\b[^|;&]*\|[[:space:]]*(/[^[:space:]|;&]*/)?(python[0-9.]*|perl|ruby|node|php|tclsh)([[:space:]]|$)|eval[[:space:]]+['"]?\$\([[:space:]]*\b(curl|wget|fetch)\b|((ba|z|da|a|k)?sh|fish|source|\.)[[:space:]]+<\([[:space:]]*\b(curl|wget|fetch)\b)`,
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
		DenyNetwork: []*Rule{
			{
				Name:    "cloud-metadata",
				Control: "SC-07",
				Reason:  "SSRF to a cloud instance-metadata endpoint (credential theft)",
				// The well-known link-local metadata IPs/hostnames across AWS, GCP,
				// Azure, Alibaba, plus AWS's IMDS IPv6 address.
				Pattern: `(?i)(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|fd00:ec2::254)`,
			},
			{
				Name:    "internal-address",
				Control: "SC-07",
				Reason:  "fetch of an internal/loopback address (SSRF to a private service)",
				// Anchored to the host position (scheme://[user@]HOST) so a private
				// address in the host is blocked while the same digits in a path or
				// query are not. Covers loopback, RFC1918, and link-local ranges.
				Pattern: `(?i)^[a-z][a-z0-9+.-]*://([^@/]*@)?(localhost|127\.[0-9]+\.[0-9]+\.[0-9]+|0\.0\.0\.0|10\.[0-9]+\.[0-9]+\.[0-9]+|192\.168\.[0-9]+\.[0-9]+|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]+\.[0-9]+|169\.254\.[0-9]+\.[0-9]+|\[?::1\]?)([:/]|$)`,
			},
			{
				Name:    "non-web-scheme",
				Control: "SC-07",
				Reason:  "non-web URL scheme in a fetch (local-file/SSRF vector, e.g. file://)",
				// WebFetch tools speak http(s); these schemes reach the local
				// filesystem or internal services and bypass the file-read guard.
				Pattern: `(?i)^(file|gopher|dict|ldap|ldaps|jar|netdoc|tftp):`,
			},
		},
		// DenyMCP is empty by default: MCP tool semantics vary per server, so there
		// is no safe universal block. Populating it via a policy file lets a repo
		// deny specific servers/tools by name; the arm always logs MCP calls.
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
