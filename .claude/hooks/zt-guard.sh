#!/usr/bin/env bash
# PreToolUse guard for Bash. Blocks destructive deletes, pipe-to-shell,
# force-pushes, shell credential reads, and tampering with the policy itself.
# Controls: AC-01, IA-02, IR-01. Fail-closed.
set -u
ZT_HOOK="zt-guard"
source "$(dirname "${BASH_SOURCE[0]}")/zt-lib.sh"
zt_init

[ "$(zt_get tool_name)" = "Bash" ] || zt_allow
cmd="$(zt_get tool_input.command)"
[ -n "$cmd" ] || zt_allow

# deny <regex> <reason> : block if the command matches (extended, case-insensitive).
deny() { printf '%s' "$cmd" | grep -Eiq "$1" && zt_block "$2"; }

# Destructive recursive delete of a broad/system path.
deny '(^|[;&|[:space:]])rm[[:space:]]+(-[a-z]*[rf][a-z]*[[:space:]]+)+(-[a-z]+[[:space:]]+)*(/|~|\$HOME|\*|/\*|\.\.?)([[:space:]]|/|$)' \
  "destructive recursive delete (rm -rf of a broad path)"

# Pipe a download straight into a shell interpreter.
deny '\|[[:space:]]*(ba|z)?sh([[:space:]]|$)' \
  "pipe-to-shell (curl|wget … | sh) executes untrusted remote code"

# Force-push (overwrites remote history).
deny '(git[[:space:]].*push.*(--force([[:space:]]|=|$)|--force-with-lease|[[:space:]]-f([[:space:]]|$))|push[[:space:]].*[[:space:]]\+[^[:space:]:]+:)' \
  "force-push overwrites remote history"

# Shell read/exfil of credential material.
deny '(\.env([[:space:]'"'"'";|&)]|$)|id_rsa|id_ed25519|\.aws/credentials|\.git-credentials|(^|/)\.ssh/|\.pem([[:space:]'"'"'";|&)]|$)|/etc/shadow|\.npmrc)' \
  "reads credential material from the shell"

# Tampering with the integrity-protected policy under .claude/.
deny '((rm|mv|cp|chmod|chown|truncate|tee|dd|ln|install|sed[[:space:]]+-i)[^|;&]*\.claude|>>?[[:space:]]*[^|;&]*\.claude/)' \
  "tampering with the integrity-protected .claude/ policy"

zt_allow
