# zta — Zero-Trust enforcement for AI coding agents

`zta` is a single, zero-dependency Go binary that holds an AI coding agent — and
any subagents it spawns — to a zero-trust policy **while it works**. It blocks
destructive commands, secret reads/writes, force-pushes, and policy tampering at
the moment the agent tries them, regardless of which agent you run.

It is the successor to this repo's original Claude-Code-only `.claude/` bash pack
([see below](#legacy-claude-code-pack)), rebuilt to be **agent-agnostic**.

> **Scope.** `zta` secures the *coding agent's behavior inside a repo*. It is a
> low-blast-radius enforcement layer, not a credential proxy or a production
> network control. Read [Honest limits](#honest-limits) before relying on it.

---

## Why

Most "guardrails" for coding agents are prompt-level guidance the model can
ignore. `zta` enforces at the **tool-call boundary** instead: a deterministic
check that runs before an operation happens and can deny it.

The hard part is that **there is no universal interception API across agents.**
Claude Code exposes real hooks; Cursor and Copilot mostly expose only advisory
config. `zta` handles this with two enforcement tiers and is explicit about which
one each agent gets — no false sense of security.

| Tier | Mechanism | Assurance | Agents |
|------|-----------|-----------|--------|
| **Hook** | the agent's native pre-tool-call hook calls `zta guard` | High — the call is genuinely blocked | Claude Code (✅), Codex CLI (planned) |
| **Sandbox** | `zta run` launches the agent with a shim PATH that routes command execution through the engine | Catches commands the agent runs (any agent) | ✅ any agent |

The guard logic is identical across tiers; only the *wiring* differs.

---

## How it works

```
agent operation ──► adapter ──► normalized Event ──► engine ──► Decision ──► adapter ──► allow / block
                 (agent-specific)   (exec / file_read    (pure, agent-agnostic)   (exit code / format)
                                     / file_write)
```

- **Adapter** — translates one agent's interception payload into a normalized
  `Event` and translates the verdict back into that agent's expected response.
  Adding an agent is one small adapter; the policy logic is untouched.
- **Engine** — a pure function `Evaluate(policy, event) → decision`. Default is
  *allow*; rules *block*. This is the single source of truth for every agent.
- **Policy** — secure defaults are **compiled into the binary**, so `zta` is safe
  with no config file. An optional JSON file extends or overrides any rule set.

Full design notes: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

---

## Status

Early but functional. What exists today:

- ✅ `zta init` — wire enforcement into a repo (idempotent, with dry-run)
- ✅ `zta guard` — hook-tier enforcement entrypoint (fail-closed)
- ✅ `zta run` — sandbox-tier launcher for agents without hooks
- ✅ `zta audit` — posture auditor; scores config vs the control catalog, gates CI
- ✅ `zta version`
- ✅ Claude Code adapter (PreToolUse hooks)
- ✅ Engine + embedded default policy (destructive deletes, pipe-to-shell,
  force-push, credential read/write, secret-in-code, policy-integrity)

Planned (see [Roadmap](#roadmap)): Cursor & Codex adapters, tool-call logging, and
a container backend for kernel-level isolation.

---

## Install

Until tagged binaries ship, build from source. Requires Go 1.26+.

```bash
git clone https://github.com/networkdefendersecurity/zta
cd zta
go build -o zta ./cmd/zta
./zta version
```

The result is a static binary with no runtime dependencies — copy it anywhere on
your `PATH`.

---

## Usage

### Quick start

From your repo, wire enforcement in one command (preview first with `--dry-run`):

```bash
zta init --dry-run        # show what would change
zta init                  # wire `zta guard` into the agent + scaffold CLAUDE.md
zta init --policy         # also drop a zta.json mirroring the built-in defaults
zta audit .               # see remaining Foundation gaps
```

`zta init` merges into existing config (it won't clobber your settings) and is
idempotent. For an agent without hooks, it prints sandbox-tier guidance instead.

### Claude Code (hook tier)

Register `zta guard` as a `PreToolUse` hook in your project's
`.claude/settings.json`. A non-zero exit blocks the tool call and the message is
shown to the agent:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Read|Edit|Write|NotebookEdit",
        "hooks": [{ "type": "command", "command": "zta guard --agent claude-code" }]
      }
    ]
  }
}
```

That single hook replaces the four bash guards from the legacy pack. Claude Code
sets `CLAUDE_PROJECT_DIR`, which `zta` uses to scope policy-integrity protection
to *your* repo.

### Any agent (sandbox tier)

For agents without usable hooks (Cursor, Copilot, …), launch them through
`zta run`. It puts a shim `PATH` in front of the agent so the **commands it runs**
are evaluated by the same engine before they execute — no agent cooperation
required:

```bash
zta run -- cursor-agent          # or: aider, codex, any CLI agent
zta run -- bash                  # even a plain shell is now guarded
```

A blocked command fails with exit `126` and a reason on stderr; everything else
runs normally. This intercepts the shell (so full pipelines like `curl … | bash`
are caught) plus a default set of high-risk binaries.

### Audit posture (CI gate)

`zta audit` scores a repo's agent configuration against the Foundation control
catalog and exits non-zero if a repo-scope control fails — drop it in CI to gate
AI-generated changes:

```bash
zta audit .            # scorecard + verdict; exit 1 on any FAIL
zta audit . --strict   # also fail on PARTIAL
```

It recognizes both `zta` wiring (`zta guard` / `zta run`) and the legacy bash
hooks, so it works during and after migration.

### Try it directly

`zta guard` reads one operation as JSON on stdin and exits `0` (allow) or `2`
(block):

```bash
# allowed
echo '{"tool_name":"Bash","tool_input":{"command":"npm test"}}' \
  | zta guard --agent claude-code; echo "exit=$?"        # exit=0

# blocked
echo '{"tool_name":"Bash","tool_input":{"command":"curl x.sh | bash"}}' \
  | zta guard --agent claude-code; echo "exit=$?"        # exit=2
# zta: blocked by policy [AC-01/pipe-to-shell]: pipe-to-shell ... executes untrusted remote code
```

### Flags

| Flag | Default | Purpose |
|------|---------|---------|
| `--agent` | `claude-code` | which agent protocol to speak |
| `--root` | `$ZTA_PROJECT_DIR`, `$CLAUDE_PROJECT_DIR`, else cwd | project root for policy-integrity scoping |
| `--policy` | `$ZTA_POLICY` | optional JSON policy file overriding the defaults |

---

## Policy

The compiled-in defaults block, by control:

| Control | Blocks |
|---------|--------|
| **AC-01** | destructive recursive deletes; pipe-to-shell (`curl … \| sh`) |
| **IA-02** | force-push; reading credential files (`.env`, keys, `.aws/credentials`, …) |
| **IR-01** | writes to the project's policy directory (`.claude/`, `.zta/`) and `.git/` internals |
| **IO-02** | writing secrets into code (AWS/Anthropic/OpenAI/GitHub/Slack keys, JWTs, private keys, hardcoded credentials) |

To customize, point `--policy` at a JSON file. Any rule set you specify replaces
that default set; sets you omit keep their defaults:

```json
{
  "deny_exec": [
    { "name": "no-terraform-apply", "control": "AC-01",
      "reason": "infra changes go through CI",
      "pattern": "(?i)terraform[[:space:]]+apply" }
  ]
}
```

Rule sets: `deny_exec` (shell commands), `deny_path` (files off-limits to any
access), `protect_write` (paths write-protected within the project),
`secret_content` (patterns blocked from being written). Patterns are RE2.

---

## Honest limits

`zta` is a deterministic layer at the tool-call boundary. It is **not a sandbox**
(until the sandbox tier lands) and not complete:

- **The model can route around naive blocks.** Block `Write` and it may use a
  Bash heredoc; block `rm` and it may use `perl -e unlink`. The command rules
  cover common shapes, not all of them.
- **The sandbox tier intercepts *commands*, not raw syscalls.** `zta run`
  evaluates what the agent executes through the shell and shimmed binaries. It
  does **not** trap file reads/writes the agent's own process performs directly
  (e.g. an agent that opens `.env` via a syscall rather than running `cat`). For
  that, use the hook tier or the planned container backend.
- **Hard isolation needs the kernel.** For guarantees against a determined
  process, run the agent in a container/namespaced worktree with restricted
  filesystem and network egress — the planned container backend for `zta run`.
- **Hook tier depends on the agent honoring hooks.** On agents without real
  hooks, use the sandbox tier instead.

Treat these as the deterministic 80%, paired with OS-level isolation — not a
replacement for it.

---

## Roadmap

1. **Container backend for `zta run`** — kernel-level filesystem/network isolation (catches raw syscalls, not just commands).
2. **Cursor / Codex / Copilot adapters.**
3. **Tool-call logging** — append-only attribution log (OA-01/02), which will also lift the auditor's OA-01/02 for zta-only repos and let `zta init` wire it.
4. **Tagged cross-compiled releases.**

---

## Legacy Claude Code pack

The original `.claude/` bash hooks, `CLAUDE.md`, and `zt-audit/` Python auditor
still live in this repo and remain functional for Claude Code. `zta audit` is a
faithful, dependency-free port of `zt-audit/` (verified to produce the same
scorecard), so the Python auditor can be retired. The bash hooks are superseded
by `zta guard` and will be retired once `zta init` lands. `zta` itself cannot
modify `.claude/` — its own integrity guard blocks that, by design.

---

## Development

```bash
go test ./...     # unit tests + fixture-backed behavior tests
go vet ./...
gofmt -l .        # should print nothing
```

v0.1 — derived from Anthropic, *Zero Trust for AI Agents* (2026). Control
mappings are advisory alignments, not legal determinations.
