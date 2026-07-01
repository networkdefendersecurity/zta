# zta redteam kit

A testing kit to answer one question with confidence: **is everything `zta` is
supposed to block actually blocked?** It has two tiers.

| Tier | What it proves | Execution risk | Run it |
|------|-----------------|-----------------|--------|
| 1 — `run.py` | The policy engine + every agent adapter return the right verdict for a given payload | None — never executes a real command, only feeds JSON to `zta guard` on stdin | Anywhere, including this repo, including CI |
| 2 — canary workspace + `AGENT_PROMPT.md` | A real coding-agent session, with `zta` wired the normal way, actually gets blocked in practice | None for the checklist as written (every fixture is safe-by-construction); real for the optional Docker section | In a disposable scratch workspace |

Tier 1 catches a broken rule or a broken adapter. Tier 2 catches a broken
*wiring* — the hook not firing, the agent ignoring its hook, `zta` missing
from `PATH`, or a payload shape the adapter doesn't recognize. Both matter;
neither substitutes for the other.

## Tier 1 — deterministic policy/adapter check

```bash
redteam/run.py                 # human-readable report
redteam/run.py --json          # machine-readable
redteam/run.py --strict        # also fail if any known gap is present
redteam/run.py --only dd-01,sec-01   # run a subset
```

`cases.json` holds the matrix: every `DenyExec`/`DenyPath`/`ProtectWrite`/
`SecretContent` rule in `internal/policy/defaults.go`, the evasion shapes
from `security-audit/AUDIT-REPORT.md` that were fixed (must stay blocked —
these are regression guards, including the Copilot F1 nested/array payload
fix), negative controls (safe commands that must stay allowed, to catch
over-blocking), and adapter-parity checks across `claude-code`, `codex`,
`cursor`, and `copilot`.

A few cases are marked `"gap": true` with an `audit_ref` — these are
documented, currently-accepted bypasses (F5-followup `find -delete`, F8
interpreter writes to `.claude/`, F10 unquoted/split secrets). The runner
reports them as `GAP`, not `PASS` or `FAIL`, so they never masquerade as
either "this is fine" or "this just broke." `--strict` turns them into
failures if you want to track closing them over time.

Exit code is 0 unless a case's actual result didn't match what it expected
(a `FAIL`) — safe to wire into CI as a gate, alongside the existing
`Guard smoke test` step in `.github/workflows/ci.yml`, which this
complements rather than replaces (that step is a minimal PATH-wiring smoke
test; this is the full rule/adapter matrix).

Requires `zta` on `PATH` (or `--zta /path/to/zta`) and Python 3. No `go`
toolchain, no `jq`, no network.

## Tier 2 — live agent, real hook wiring

```bash
redteam/setup_canary.sh                 # creates a disposable scratch workspace, prints its path
cd <the printed path>
zta init --agent claude-code            # or codex / cursor / copilot — wire it for real
# start your coding agent in this directory, hand it redteam/AGENT_PROMPT.md
redteam/teardown_canary.sh <the printed path>   # clean up when done
```

`setup_canary.sh` builds a throwaway workspace that is safe to run every
checklist item in even if a block fails:

- decoy `.env`, `.ssh/id_rsa`, `.aws/credentials`, `.git-credentials`,
  `.npmrc`, `server.pem` — all fake content
- a symlink to `.env`, for demonstrating the F9 symlink-path known gap live
- a disposable local bare git repo as `canary-remote`, never a real remote
- a harmless local HTTP-served "payload" (`canary_payload.sh`) that only
  echoes a marker string, for the pipe-to-shell / fetch-to-interpreter checks
- everything lives under one throwaway directory, so `.`/`..`-relative
  deletes only ever destroy scratch data

`AGENT_PROMPT.md` is the literal checklist to hand the live agent: exact tool
calls, expected result, and what a `FAIL` means. Read its "Before you start"
and safety notes before running it — in particular, **`rm -rf /`, `rm -rf ~`,
`rm -rf /*`, and a force-push to a real remote are deliberately excluded**
from live execution because no amount of scratch-directory tooling makes
them safe to actually run if the guard has a bypass. Those shapes are
covered by Tier 1 only, unless you explicitly want full live-fire proof in a
disposable Docker container — see the last section of `AGENT_PROMPT.md`.

## Extending the kit

Adding a new rule to `internal/policy/defaults.go`? Add a matching case (or
two: one baseline, one negative control) to `cases.json` and, if it's a shape
worth proving live, a line to `AGENT_PROMPT.md`. Keep secret-shaped test
values split into fragments (see the `inject` field in `cases.json`, or the
"concatenate these fragments" pattern in `AGENT_PROMPT.md`) — writing a
literal matching secret into this kit's own files will get blocked by `zta`'s
own guard when you save them (which is, itself, a nice sanity check that it
works).
