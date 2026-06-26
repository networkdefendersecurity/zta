#!/usr/bin/env python3
"""Zero-trust agent posture audit (repo scope).

Reads a repository's .claude/ configuration and scores it against the Foundation
control catalog. Prints a scorecard and exits non-zero if any repo-scope control FAILs,
so it can gate CI on AI-generated changes.

Usage:  python3 zt-audit/zt_audit.py [repo_root]   (defaults to current directory)
        --strict   also fail the build on PARTIAL results
"""
import json
import os
import re
import sys
import glob

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from controls import CONTROLS  # noqa: E402

PASS, PARTIAL, FAIL, MANUAL, NA = "PASS", "PARTIAL", "FAIL", "MANUAL", "N/A"


def load_settings(root):
    path = os.path.join(root, ".claude", "settings.json")
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}


def hook_commands(settings, event):
    out = []
    for group in (settings.get("hooks", {}) or {}).get(event, []) or []:
        matcher = group.get("matcher", "")
        for h in group.get("hooks", []) or []:
            out.append((matcher, h.get("command", "")))
    return out


def all_hook_commands(settings):
    cmds = []
    for ev in (settings.get("hooks", {}) or {}):
        cmds += [c for _, c in hook_commands(settings, ev)]
    return cmds


def read(root, *parts):
    path = os.path.join(root, *parts)
    try:
        with open(path) as f:
            return f.read()
    except Exception:
        return ""


def subagents(root):
    agents = {}
    for p in glob.glob(os.path.join(root, ".claude", "agents", "*.md")):
        text = read(p)
        m = re.search(r"^---\s*$(.*?)^---\s*$", text, re.S | re.M)
        fm = m.group(1) if m else ""
        tools = re.search(r"^\s*tools\s*:\s*(.+)$", fm, re.M)
        agents[os.path.basename(p)] = (tools.group(1).strip() if tools else None)
    return agents


def evaluate(root):
    s = load_settings(root)
    results = {}

    def deny_list():
        return (s.get("permissions", {}) or {}).get("deny", []) if s else []

    def ask_list():
        return (s.get("permissions", {}) or {}).get("ask", []) if s else []

    if s is None:
        # no config at all -> every repo-scope control fails
        for cid, *_rest, scope, _why in CONTROLS:
            results[cid] = (FAIL, "no .claude/settings.json found") if scope == "repo" else (
                MANUAL if scope == "manual" else NA, "")
        return results, s

    pre = [c for _, c in hook_commands(s, "PreToolUse")]
    allc = all_hook_commands(s)
    agents = subagents(root)

    def has(cmds, needle):
        return any(needle in c for c in cmds)

    # IA-02 — credentials out of reach
    if has(allc, "zt-secret-scan") and has(pre, "zt-file-guard"):
        results["IA-02"] = (PASS, "secret-scan + file-guard registered")
    elif has(allc, "zt-secret-scan") or has(pre, "zt-file-guard"):
        results["IA-02"] = (PARTIAL, "only one of secret-scan / file-guard present")
    else:
        results["IA-02"] = (FAIL, "no secret-scan or file-guard hook")

    # AC-01 — deny-by-default
    if deny_list() and has(pre, "zt-guard"):
        results["AC-01"] = (PASS, f"{len(deny_list())} deny rules + Bash guard")
    elif deny_list() or has(pre, "zt-guard"):
        results["AC-01"] = (PARTIAL, "deny list or Bash guard present, not both")
    else:
        results["AC-01"] = (FAIL, "no deny rules and no Bash guard")

    # AC-02 — least-privilege scoping per subagent
    if not agents:
        results["AC-02"] = (PARTIAL, "no subagents defined to scope")
    elif all(v for v in agents.values()):
        results["AC-02"] = (PASS, f"all {len(agents)} subagents have a tools allowlist")
    else:
        unscoped = [k for k, v in agents.items() if not v]
        results["AC-02"] = (FAIL, "subagents missing tools allowlist: " + ", ".join(unscoped))

    # AC-03 — isolation/sandbox (manual)
    note = os.path.exists(os.path.join(root, ".claude", "ISOLATION.md"))
    results["AC-03"] = (MANUAL, "documented isolation note found" if note
                        else "verify OS-level sandbox/egress out-of-band")

    # OA-01 — comprehensive logging
    star_log = any(m == "*" and "zt-log" in c for m, c in hook_commands(s, "PreToolUse")) \
        or any(m == "*" and "zt-log" in c for m, c in hook_commands(s, "PostToolUse"))
    results["OA-01"] = (PASS, "logging hook on * matcher") if star_log else (
        FAIL, "no wildcard logging hook")

    # OA-02 — traceability
    logsrc = read(root, ".claude", "hooks", "zt-log.sh")
    if star_log and "session" in logsrc and "agent" in logsrc:
        results["OA-02"] = (PASS, "log records carry session + agent attribution")
    elif star_log:
        results["OA-02"] = (PARTIAL, "logging present but session/agent fields unconfirmed")
    else:
        results["OA-02"] = (FAIL, "no logging to trace")

    # IO-01 — untrusted input handling
    web_gated = any("WebFetch" in x for x in (ask_list() + deny_list()))
    if has(pre, "zt-file-guard") and (web_gated or "researcher.md" in agents):
        results["IO-01"] = (PASS, "file-guard + WebFetch gating/researcher scoping")
    elif has(pre, "zt-file-guard"):
        results["IO-01"] = (PARTIAL, "file-guard present; WebFetch not gated")
    else:
        results["IO-01"] = (FAIL, "no untrusted-input controls")

    # IO-02 — output filtering
    results["IO-02"] = (PASS, "secret-scan hook on Write/Edit") if has(allc, "zt-secret-scan") else (
        FAIL, "no secret-scan hook")

    # IR-01 — config integrity
    fg = read(root, ".claude", "hooks", "zt-file-guard.sh")
    protected = ".claude" in fg or any(".claude" in d for d in deny_list())
    if os.path.exists(os.path.join(root, ".claude", "settings.json")) and protected:
        results["IR-01"] = (PASS, "policy present and write-protected from the agent")
    else:
        results["IR-01"] = (PARTIAL, "policy present but not write-protected")

    # GV-01 — acceptable use
    claude_md = read(root, "CLAUDE.md").lower()
    if claude_md and ("acceptable use" in claude_md or "policy" in claude_md):
        results["GV-01"] = (PASS, "CLAUDE.md documents acceptable use")
    else:
        results["GV-01"] = (FAIL, "no acceptable-use policy in CLAUDE.md")

    # GV-03 — pack installed / gate present
    installed = (os.path.exists(os.path.join(root, ".claude", "settings.json"))
                 and glob.glob(os.path.join(root, ".claude", "hooks", "*.sh"))
                 and agents)
    results["GV-03"] = (PASS, "policy pack present; audit gating the build") if installed else (
        FAIL, "policy pack incomplete")

    # fill any NA controls
    for cid, _dom, _name, scope, _why in CONTROLS:
        if cid not in results:
            results[cid] = (NA, "")
    return results, s


COLOR = {PASS: "\033[32m", FAIL: "\033[31m", PARTIAL: "\033[33m",
         MANUAL: "\033[36m", NA: "\033[90m"}
RESET = "\033[0m"


def main():
    strict = "--strict" in sys.argv
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    root = args[0] if args else "."
    use_color = sys.stdout.isatty()

    results, settings = evaluate(root)

    print()
    print("  Zero-Trust Agent Posture Audit  —  repo scope")
    print("  root: " + os.path.abspath(root))
    print("  " + "-" * 72)
    print(f"  {'ID':6} {'STATUS':8} {'DOMAIN':22} CONTROL")
    print("  " + "-" * 72)

    counts = {PASS: 0, FAIL: 0, PARTIAL: 0, MANUAL: 0, NA: 0}
    for cid, dom, name, scope, _why in CONTROLS:
        status, detail = results[cid]
        counts[status] += 1
        tag = f"{COLOR.get(status,'')}{status:8}{RESET}" if use_color else f"{status:8}"
        print(f"  {cid:6} {tag} {dom[:22]:22} {name}")
        if detail and status in (FAIL, PARTIAL, MANUAL):
            print(f"  {'':6} {'':8} {'':22}   -> {detail}")

    print("  " + "-" * 72)
    summary = (f"  {counts[PASS]} pass · {counts[FAIL]} fail · {counts[PARTIAL]} partial · "
               f"{counts[MANUAL]} manual · {counts[NA]} n/a")
    print(summary)

    failed = counts[FAIL] > 0 or (strict and counts[PARTIAL] > 0)
    verdict = "FOUNDATION NOT MET" if failed else (
        "FOUNDATION MET (repo scope)" if counts[PARTIAL] == 0 else "FOUNDATION PARTIAL (repo scope)")
    print(f"  verdict: {verdict}")
    print()
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
