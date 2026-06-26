#!/usr/bin/env bash
# PreToolUse guard for Read/Edit/Write/NotebookEdit. Blocks reads or writes of
# secret files, and write-protects the .claude/ policy and .git/ internals.
# Controls: IA-02, IR-01, IO-01. Fail-closed.
set -u
ZT_HOOK="zt-file-guard"
source "$(dirname "${BASH_SOURCE[0]}")/zt-lib.sh"
zt_init

tool="$(zt_get tool_name)"
fp="$(zt_get tool_input.file_path)"
[ -n "$fp" ] || zt_allow
base="${fp##*/}"

# Secret files are off-limits to any tool (read or write).
case "$base" in
  .env.example|.env.sample|.env.template) : ;;          # templates are fine
  .env|.env.*) zt_block "access to secret file: $base" ;;
esac
printf '%s' "$fp" | grep -Eq \
  '(id_rsa|id_ed25519|(^|/)\.ssh/|\.aws/credentials|\.git-credentials|(^|/)\.npmrc$|\.pem$|\.key$|(^|/)secrets?(\.|/)|credentials\.json$)' \
  && zt_block "access to credential file: $fp"

# Write-protect the policy and git internals (reads are allowed).
case "$tool" in
  Write|Edit|NotebookEdit)
    printf '%s' "$fp" | grep -Eq '(^|/)\.claude/' \
      && zt_block "the .claude/ policy is integrity-protected; changes go through human review (IR-01)"
    printf '%s' "$fp" | grep -Eq '(^|/)\.git/' \
      && zt_block "writing to .git/ internals is not allowed"
    ;;
esac

zt_allow
