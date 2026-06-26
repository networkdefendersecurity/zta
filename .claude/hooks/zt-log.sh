#!/usr/bin/env bash
# Logging hook (registered on the * matcher for PreToolUse and PostToolUse).
# Appends one JSON object per tool call to .claude/logs/zt-actions.jsonl with
# session and subagent attribution. Controls: OA-01, OA-02.
# Logging must never block a call, so this hook always exits 0 (fail-open).
set -u
RAW="$(cat)"

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOGDIR="$(dirname "$DIR")/logs"
mkdir -p "$LOGDIR" 2>/dev/null || exit 0
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)"

emit() {  # build one JSON record carrying session_id + agent attribution
  if command -v python3 >/dev/null 2>&1; then
    RAW="$RAW" TS="$TS" python3 -c '
import json, os
try:
    d = json.loads(os.environ["RAW"])
    if not isinstance(d, dict): d = {}
except Exception:
    d = {}
ti = d.get("tool_input") or {}
cmd = ti.get("command")
target = ti.get("file_path") or (cmd[:200] if isinstance(cmd, str) else None)
print(json.dumps({
    "ts": os.environ["TS"],
    "event": d.get("hook_event_name"),
    "session_id": d.get("session_id"),
    "agent_id": d.get("agent_id"),
    "agent_type": d.get("agent_type"),
    "tool_name": d.get("tool_name"),
    "target": target,
}))'
  elif command -v jq >/dev/null 2>&1; then
    printf '%s' "$RAW" | jq -c --arg ts "$TS" '{
      ts:$ts, event:.hook_event_name, session_id:.session_id,
      agent_id:.agent_id, agent_type:.agent_type, tool_name:.tool_name,
      target:(.tool_input.file_path // (.tool_input.command // null))
    }' 2>/dev/null
  else
    printf '{"ts":"%s","raw_unparsed":true}' "$TS"
  fi
}

line="$(emit)"
[ -n "$line" ] && printf '%s\n' "$line" >> "$LOGDIR/zt-actions.jsonl"
exit 0
