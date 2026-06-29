# Architecture

`zta` separates *what is dangerous* (the policy and engine — written once, shared
by every agent) from *how an agent expresses an operation* (the adapters — small,
per-agent). This document explains the pieces and how to extend them.

## Design principles

1. **Agent-agnostic core.** All policy logic operates on a normalized event. No
   agent-specific knowledge leaks into the engine.
2. **Zero dependencies.** The binary uses only the Go standard library. Secure
   defaults are compiled in, so the tool is correct with no config file and the
   build is trivially reproducible — fitting for a supply-chain-conscious tool.
3. **Fail closed.** Anything the guard cannot parse or evaluate is *blocked*, not
   allowed.
4. **Honest assurance tiers.** Where an agent has no enforceable hook, that is
   stated, not papered over. See [Enforcement tiers](#enforcement-tiers).

## Package layout

```
cmd/zta                 CLI entrypoint and command dispatch
internal/policy         Event/Decision model, Rule, Policy, embedded defaults, loader
internal/engine         Evaluate(policy, event) -> decision  (the heart)
internal/adapter        Adapter interface + registry
internal/adapter/...    one package per supported agent (e.g. claudecode)
```

## The normalized event

Every agent operation an adapter cares about collapses into one shape
(`policy.Event`):

| Field | Meaning |
|-------|---------|
| `Action` | `exec`, `file_read`, or `file_write` |
| `Command` | shell command, for `exec` |
| `Path` | target file, for file actions |
| `Content` | content being written, for `file_write` (used by secret scanning) |
| `Agent` | originating agent id |
| `Raw` | original tool input, for logging/debugging |

If a future agent introduces an operation class that doesn't fit (e.g. a network
request), that becomes a new `Action` plus the rules that evaluate it — added in
one place, inherited by all adapters.

## The engine

`engine.Evaluate(p *policy.Policy, e *policy.Event) policy.Decision` is pure and
side-effect-free. Decision order:

1. **`exec`** → match `Command` against `DenyExec`.
2. **`file_read` / `file_write`** → dotenv basename check, then `DenyPath`.
3. **`file_write`** also → `ProtectWrite` (scoped to the project root), then
   `SecretContent` against `Content`.

Default verdict is **allow**; the first matching rule blocks and names the
control and rule that fired.

### Project-root scoping

`ProtectWrite` rules (the policy directory and `.git/`) only fire when the target
path resolves *inside* the project root (`Policy.ProjectRoot`). This prevents the
guard from protecting unrelated `.claude/` or `.git/` directories elsewhere on
disk — e.g. an agent legitimately editing `~/.claude/` for a *different* project.
Relative paths are treated as in-tree; an empty root disables scoping.

### Why some checks are code, not regex

Go's regexp engine is RE2, which has no lookahead. The dotenv rule ("block
`.env*` except `.env.example|.sample|.template`") is therefore a basename check
in code rather than a negative-lookahead pattern. Everything else is RE2.

## Policy

`policy.Policy` holds four rule sets — `DenyExec`, `DenyPath`, `ProtectWrite`,
`SecretContent` — each a list of `Rule{Name, Pattern, Control, Reason}`.

- `policy.Default()` returns the compiled-in secure baseline.
- `policy.Load(path, optional)` starts from the defaults and overlays a JSON
  file: any rule set present in the file *replaces* that default set; omitted
  sets are kept. The result is compiled (regexes validated) before use.

This "override by set" model keeps the common case (extend one category)
ergonomic while letting power users replace a category wholesale.

## Adapters

```go
type Adapter interface {
    Name() string
    Parse(r io.Reader) (*policy.Event, error)            // normalize one payload
    Respond(stdout, stderr io.Writer, d policy.Decision) int // emit verdict, return exit code
}
```

Adapters self-register in `init()`. `Parse` returns `adapter.ErrPassthrough` for
operations the guard does not gate (e.g. a tool type with no policy implications),
which the CLI treats as allow. `Respond` receives both streams because agents
disagree on where the verdict goes — some read a message from stderr plus the
exit code, others read a JSON object from stdout.

Four hook adapters ship, each speaking its agent's exact protocol (verified
against 2026 docs):

| Adapter | Input schema | Deny signal |
|---------|--------------|-------------|
| `claude-code` | `tool_name` + `tool_input` | exit 2 + reason on stderr |
| `codex` | same as Claude (plus `apply_patch`) | exit 2 + reason on stderr |
| `cursor` | `command` / `tool_name` / `file_path` per event | `{"permission":"deny"}` on stdout (+ exit 2) |
| `copilot` | camelCase `toolName` + `toolArgs` | `{"permissionDecision":"deny"}` on stdout (+ exit 2) |

Claude Code and Codex share `adapter.ClaudeStyleEvent`. Copilot's `toolArgs` key
names vary by version, so it tries common keys and falls back to scanning all
string values — a mis-guessed key must never let a dangerous command through.

### Adding an agent

1. Create `internal/adapter/<agent>/<agent>.go`.
2. Implement `Parse` (map the agent's interception JSON/format to an `Event`) and
   `Respond` (write the verdict in the agent's expected form, return its block
   exit code).
3. `adapter.Register(Adapter{})` in `init()`.
4. Blank-import the package in `cmd/zta/main.go` so it registers.

No engine or policy changes are required.

## Enforcement tiers

| Tier | How it intercepts | Assurance |
|------|-------------------|-----------|
| **Hook** | the agent invokes `zta guard` before each tool call | High where the agent has real, blocking hooks (Claude Code) |
| **Sandbox / shim** | `zta run` launches the agent with a shim `PATH` that routes command execution through the engine | Catches commands the agent runs, regardless of cooperation |
| **Sandbox / container** | `zta run --backend=docker` isolates the agent in a hardened container with the shim running inside | Kernel-enforced host/network isolation plus command policy |

All tiers funnel through the same engine. The sandbox tiers are the answer for
agents (Cursor, Copilot) whose only native controls are advisory.

### Sandbox tier (`zta run`)

`zta run -- <command…>` (see `internal/sandbox`):

1. Create a temp **shim directory** with an executable wrapper per target
   binary — the shells plus high-risk tools (`rm`, `git`, `curl`, …). Each
   wrapper is `exec zta __shim --name <tool> -- "$@"`.
2. Launch the command with `PATH` = shim dir first, passing the original `PATH`
   as `ZTA_REAL_PATH` so shims can find the real binaries without recursion.
   `argv[0]` is resolved against the shim `PATH` explicitly, so the *top-level*
   command is shimmed too (Go's `exec.Command` otherwise resolves it against the
   parent `PATH`).
3. On each intercepted call, `zta __shim` reconstructs the command and evaluates
   it as an `exec` event:
   - **Shell with `-c`** → the inner command string, so full pipelines like
     `curl … | bash` are visible (this is why shells are the primary target).
   - **Direct exec** → the tool name plus its arguments.
4. **Blocked** → exit `126` with a reason on stderr (reads as a failed command).
   **Allowed** → `syscall.Exec` replaces the shim with the real binary and its
   original, unmodified argv, so execution is faithful.

Fail-closed: a shim that cannot load the policy blocks the command.

**Boundary.** The shim backend intercepts *command execution*, not the agent's
own syscalls. File reads/writes the agent process performs directly (not via a
shimmed command) are out of scope for it — that is what the container backend
addresses.

### Container backend (`zta run --backend=docker`)

`internal/sandbox/docker.go` runs the agent inside a hardened Docker container.
`dockerArgs` is a pure function (unit-tested without a daemon) that builds the
`docker run` invocation; `RunDocker` resolves the host context and execs it:

- **Only the project root is mounted** at `/workspace` — the host home,
  `~/.ssh`, `~/.aws`, and the rest of the host filesystem are simply not present.
  This is what closes the raw-syscall read gap.
- **Runs as the host uid:gid** (`--user`), so the agent is non-root in the
  container and the bind mount keeps correct ownership (which is why dropping
  `CAP_DAC_OVERRIDE` is fine).
- **Hardened**: `--network none` by default, `--cap-drop ALL`,
  `--security-opt no-new-privileges`.
- **Repo secrets are masked**: a bounded walk finds files that look like
  credentials (`.env`, `*.key`, `*.pem`, …) and mounts an empty file over each,
  so even a direct read returns nothing.
- **The shim tier runs inside**: the static `zta` binary is mounted read-only and
  set as the entrypoint (`zta run` wraps the agent), so command policy still
  applies — important because `/workspace` is writable.

Layered result: Docker provides kernel-enforced host/network isolation; the
nested shim keeps command-level policy. The backend needs a daemon and a
user-supplied image carrying the agent's toolchain.

## The `guard` command

`zta guard` is the hook-tier entrypoint:

1. Resolve the adapter (`--agent`), load policy (`--policy`, defaults if absent),
   set `ProjectRoot` (`--root`).
2. `adapter.Parse(stdin)`:
   - `ErrPassthrough` → exit 0 (not gated).
   - other error → exit 2 (**fail closed** — unparseable gated payload).
3. `engine.Evaluate` → `adapter.Respond` → exit with its code.

## Setup (`zta init`)

`internal/setup` wires enforcement into a repo for a given agent. `BuildPlan`
computes the changes (so `--dry-run` can preview them) and `Apply` writes them:

- **Claude Code** → merges a `zta guard` `PreToolUse` hook into
  `.claude/settings.json`. The file is parsed as a generic `map[string]any` and
  re-serialized, so existing keys (permissions, other hooks) are preserved rather
  than dropped. Idempotent: a run that finds an existing `zta guard` command
  skips it.
- **CLAUDE.md** is scaffolded from a template when absent (satisfies GV-01).
- **`--policy`** writes `zta.json` by marshaling `policy.Default()`, so users see
  and can edit exactly what is enforced.
- **Non-hookable agents** (Cursor, Codex, …) get sandbox-tier guidance
  (`zta run -- <agent>`) instead of a hook that wouldn't fire.

`init` deliberately does not fake full compliance — it wires enforcement and
points the user to `zta audit` for the remaining gaps (logging, subagent scoping,
WebFetch gating) that need human decisions.

## Audit log

`internal/auditlog` appends one JSON line per gated decision (controls OA-01/
OA-02). Both the hook path (`zta guard`) and the sandbox path (`zta __shim`) call
`auditlog.Log(root, event, decision)` after evaluating.

- **Best-effort:** a logging failure never blocks or changes enforcement.
- **Content is never logged.** Records carry the command (truncated) or the
  file path, the decision, the control/rule, agent, session id, and pid — but not
  `Event.Content`, which may be the very secret a write rule is blocking.
- **Destination:** `<root>/.zta/logs/audit.jsonl` by default — under the
  integrity-protected `.zta/` directory so the agent can't tamper with it.
  `ZTA_LOG` overrides the path or disables logging (`off`).
- **Attribution:** adapters capture the agent's session id from the hook payload
  into `Event.Session`; the sandbox tags records with a per-run `ZTA_SESSION`.

Because a zta-wired repo logs by default, the auditor treats OA-01/OA-02 as
satisfied when zta is wired.

## Control catalog

Rules carry a control id from the *Zero Trust for AI Agents* Foundation tier:

| Control | Theme |
|---------|-------|
| AC-01 | least-privilege / dangerous-action prevention |
| IA-02 | credential protection |
| IR-01 | policy integrity |
| IO-02 | secret hygiene (no secrets in code) |

## Auditor (`zta audit`)

`internal/audit` is the *verify* half: it scores a repository's agent
configuration against the full Foundation catalog (`controls.go`) and renders a
scorecard, exiting non-zero on any repo-scope `FAIL` so CI can gate AI-generated
changes. It is a dependency-free Go port of the original `zt-audit/` Python tool,
verified to produce the same scorecard.

`Evaluate(root)` inspects `.claude/settings.json`, the subagent definitions, and
`CLAUDE.md`. Each repo-scope check recognizes enforcement wired either as
`zta guard` / `zta run` **or** as the legacy bash hooks, so it works during and
after migration. Controls requiring out-of-band verification are reported
`MANUAL` (e.g. AC-03 isolation); those out of repo scope (behavioral monitoring,
agent identity, org incident response) are `N/A`. Logging controls (OA-01/02)
currently rely on the legacy logging hook — they will be satisfied by zta's own
logging once that lands.
