#!/usr/bin/env bash
# PreToolUse scan for Write/Edit. Inspects the content being written and blocks
# it before a credential can land on disk. Control: IO-02. Fail-closed.
#
# Note: registered on PreToolUse so the write is prevented (the key never hits
# disk). It can also be run on PostToolUse to scan committed diffs after the fact.
set -u
ZT_HOOK="zt-secret-scan"
source "$(dirname "${BASH_SOURCE[0]}")/zt-lib.sh"
zt_init

# Write sends `content`; Edit sends `new_string`. Scan whichever is present.
blob="$(zt_get tool_input.content)
$(zt_get tool_input.new_string)"
[ -n "${blob// /}" ] || zt_allow

# hit <regex> <label>
hit() { printf '%s' "$blob" | grep -Eq -- "$1" && zt_block "secret in write: $2"; }

hit 'AKIA[0-9A-Z]{16}'                               "AWS access key id"
hit 'ASIA[0-9A-Z]{16}'                               "AWS temporary access key id"
hit 'sk-ant-[A-Za-z0-9_-]{16,}'                      "Anthropic API key"
hit 'sk-[A-Za-z0-9]{20,}'                            "OpenAI-style API key"
hit 'gh[posru]_[A-Za-z0-9]{20,}'                     "GitHub token"
hit 'github_pat_[A-Za-z0-9_]{20,}'                   "GitHub fine-grained PAT"
hit 'xox[baprs]-[A-Za-z0-9-]{10,}'                   "Slack token"
hit 'AIza[0-9A-Za-z_-]{30,}'                         "Google API key"
hit '-----BEGIN[A-Z ]*PRIVATE KEY-----'              "private key block"
hit 'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.' "JWT"
hit '(password|passwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|token)["'"'"'[:space:]]*[:=][[:space:]]*["'"'"'][^"'"'"']{8,}["'"'"']' \
                                                     "hardcoded credential assignment"

zt_allow
