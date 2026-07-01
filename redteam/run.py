#!/usr/bin/env python3
"""Tier 1 of the zta testing kit: feed every case in cases.json straight into
`zta guard` on stdin and check the exit code matches what the case expects.

This never executes a real command or touches a real file — it only exercises
the policy engine + adapter parsing through the same CLI entrypoint the
PreToolUse hook invokes. Safe to run anywhere, including this repo, and safe
to wire into CI.

Usage:
  redteam/run.py                  run every case, human-readable report
  redteam/run.py --json           machine-readable report on stdout
  redteam/run.py --strict         also fail (non-zero exit) if any known gap
                                   is present, so you can track "gaps closed"
  redteam/run.py --only dd-01,dd-02   run a subset by id (comma-separated)
"""
import argparse
import copy
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
CASES_FILE = HERE / "cases.json"

RESET = "\033[0m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
DIM = "\033[2m"


def color(s, c, enabled):
    return f"{c}{s}{RESET}" if enabled else s


def build_payload(case):
    payload = copy.deepcopy(case["payload"])
    inject = case.get("inject")
    if inject:
        secret = "".join(inject["secret_parts"])
        value = inject["template"].replace("{S}", secret)
        node = payload
        for key in inject["path"][:-1]:
            node = node[key]
        node[inject["path"][-1]] = value
    return payload


def run_case(zta_bin, root, case):
    payload = build_payload(case)
    agent = case.get("agent", "claude-code")
    try:
        proc = subprocess.run(
            [zta_bin, "guard", "--agent", agent, "--root", root],
            input=json.dumps(payload).encode(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        return {"case": case, "returncode": None, "stderr": "TIMEOUT", "outcome": "FAIL"}

    expected_code = 2 if case["want"] == "block" else 0
    actual_blocked = proc.returncode not in (0,)
    matched = proc.returncode == expected_code

    if matched and case.get("gap"):
        outcome = "GAP"
    elif matched:
        outcome = "PASS"
    else:
        outcome = "FAIL"

    return {
        "case": case,
        "returncode": proc.returncode,
        "stderr": proc.stderr.decode(errors="replace").strip(),
        "outcome": outcome,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON report")
    ap.add_argument("--strict", action="store_true", help="also fail if any known gap is present")
    ap.add_argument("--only", help="comma-separated list of case ids to run")
    ap.add_argument("--zta", default=None, help="path to the zta binary (default: find on PATH)")
    args = ap.parse_args()

    zta_bin = args.zta or shutil.which("zta")
    if not zta_bin:
        print(color("zta: not found on PATH. Install it or pass --zta /path/to/zta.", RED, True), file=sys.stderr)
        sys.exit(2)

    cases = json.loads(CASES_FILE.read_text())
    if args.only:
        wanted = set(args.only.split(","))
        cases = [c for c in cases if c["id"] in wanted]
        if not cases:
            print(f"no cases matched --only {args.only}", file=sys.stderr)
            sys.exit(2)

    color_ok = sys.stdout.isatty() and not args.json

    with tempfile.TemporaryDirectory(prefix="zta-redteam-") as root:
        results = [run_case(zta_bin, root, c) for c in cases]

    if args.json:
        out = [
            {
                "id": r["case"]["id"],
                "category": r["case"]["category"],
                "control": r["case"]["control"],
                "agent": r["case"].get("agent", "claude-code"),
                "desc": r["case"]["desc"],
                "want": r["case"]["want"],
                "gap": r["case"].get("gap", False),
                "audit_ref": r["case"].get("audit_ref"),
                "returncode": r["returncode"],
                "outcome": r["outcome"],
            }
            for r in results
        ]
        print(json.dumps(out, indent=2))
    else:
        by_category = {}
        for r in results:
            by_category.setdefault(r["case"]["category"], []).append(r)

        for cat, rs in by_category.items():
            print(f"\n{color(cat, DIM, color_ok)}")
            for r in rs:
                c = r["case"]
                mark = {"PASS": ("PASS", GREEN), "GAP": ("GAP ", YELLOW), "FAIL": ("FAIL", RED)}[r["outcome"]]
                label = color(mark[0], mark[1], color_ok)
                extra = f"  [known gap: {c['audit_ref']}]" if c.get("gap") else ""
                agent = c.get("agent", "claude-code")
                print(f"  {label}  {c['id']:<12} ({agent:<11}) {c['desc']}{extra}")
                if r["outcome"] == "FAIL":
                    print(f"         {color('expected', DIM, color_ok)}={c['want']} "
                          f"{color('got exit', DIM, color_ok)}={r['returncode']} "
                          f"{color(r['stderr'] or '(no stderr)', DIM, color_ok)}")

    n_pass = sum(1 for r in results if r["outcome"] == "PASS")
    n_gap = sum(1 for r in results if r["outcome"] == "GAP")
    n_fail = sum(1 for r in results if r["outcome"] == "FAIL")
    total = len(results)

    if not args.json:
        print()
        summary = f"{total} cases: {n_pass} pass, {n_gap} known gap, {n_fail} FAIL"
        print(color(summary, GREEN if n_fail == 0 else RED, color_ok))
        if n_fail:
            print(color("\nA FAIL means either a command that should be blocked got through,", RED, color_ok))
            print(color("or a safe command got wrongly blocked. Treat this as a real bypass", RED, color_ok))
            print(color("or regression until proven otherwise.", RED, color_ok))

    if n_fail:
        sys.exit(1)
    if args.strict and n_gap:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
