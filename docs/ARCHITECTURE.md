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
    Parse(r io.Reader) (*policy.Event, error)   // normalize one payload
    Respond(w io.Writer, d policy.Decision) int // emit verdict, return exit code
}
```

Adapters self-register in `init()`. `Parse` returns `adapter.ErrPassthrough` for
operations the guard does not gate (e.g. a tool type with no policy implications),
which the CLI treats as allow.

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
| **Sandbox** | `zta run` launches the agent with a shim `PATH` that routes command execution through the engine | Catches commands the agent runs, regardless of cooperation |

Both tiers funnel through the same engine. The sandbox tier is the answer for
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

**Boundary.** The sandbox tier intercepts *command execution*, not the agent's
own syscalls. File reads/writes the agent process performs directly (not via a
shimmed command) are out of scope here — they belong to the hook tier or the
planned container backend, which would run the agent under kernel-enforced
filesystem/network restrictions.

## The `guard` command

`zta guard` is the hook-tier entrypoint:

1. Resolve the adapter (`--agent`), load policy (`--policy`, defaults if absent),
   set `ProjectRoot` (`--root`).
2. `adapter.Parse(stdin)`:
   - `ErrPassthrough` → exit 0 (not gated).
   - other error → exit 2 (**fail closed** — unparseable gated payload).
3. `engine.Evaluate` → `adapter.Respond` → exit with its code.

## Control catalog

Rules carry a control id from the *Zero Trust for AI Agents* Foundation tier:

| Control | Theme |
|---------|-------|
| AC-01 | least-privilege / dangerous-action prevention |
| IA-02 | credential protection |
| IR-01 | policy integrity |
| IO-02 | secret hygiene (no secrets in code) |

Controls assessed by the (planned) `zta audit` rather than enforced at runtime —
and those out of scope for a repo-local tool (behavioral monitoring, agent
identity, org incident response) — will be documented with the auditor.
