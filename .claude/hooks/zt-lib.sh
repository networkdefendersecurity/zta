# shellcheck shell=bash
# Shared helpers for the zero-trust PreToolUse guards.
# JSON is parsed with jq when present, else python3; if neither exists the
# blocking guards fail CLOSED (deny). Sourced, never executed directly.

# Read all of stdin and pick a JSON parser. Sets ZT_RAW and ZT_PARSER.
# Blocking hooks call zt_init (which denies on unparseable input); the
# logging hook does its own best-effort parse and never blocks.
zt_init() {
  ZT_RAW="$(cat)"
  if command -v jq >/dev/null 2>&1; then
    ZT_PARSER="jq"
    printf '%s' "$ZT_RAW" | jq -e . >/dev/null 2>&1 || zt_block "unparseable hook input"
  elif command -v python3 >/dev/null 2>&1; then
    ZT_PARSER="py"
    printf '%s' "$ZT_RAW" | python3 -c 'import json,sys; json.load(sys.stdin)' 2>/dev/null \
      || zt_block "unparseable hook input"
  else
    # No parser available: cannot inspect the call, so deny it.
    ZT_PARSER="none"
    zt_block "no jq or python3 available to evaluate policy (fail-closed)"
  fi
}

# zt_get <dot.path>  ->  prints the scalar leaf value, or empty string if absent.
zt_get() {
  case "${ZT_PARSER:-}" in
    jq) printf '%s' "$ZT_RAW" | jq -r ".$1 // empty" 2>/dev/null ;;
    py) printf '%s' "$ZT_RAW" | ZT_PATH="$1" python3 -c '
import json,os,sys
try:
    cur = json.load(sys.stdin)
except Exception:
    print(""); sys.exit(0)
for k in os.environ["ZT_PATH"].split("."):
    cur = cur.get(k) if isinstance(cur, dict) else None
    if cur is None:
        print(""); sys.exit(0)
print(cur if isinstance(cur, str) else json.dumps(cur))' 2>/dev/null ;;
    *) printf '' ;;
  esac
}

# Deny the tool call. Message goes to stderr (shown to the model as the reason);
# exit 2 blocks the call and holds even under --dangerously-skip-permissions.
zt_block() {
  printf 'ZT-DENY [%s] %s\n' "${ZT_HOOK:-guard}" "$1" >&2
  exit 2
}

# Allow the tool call.
zt_allow() { exit 0; }
