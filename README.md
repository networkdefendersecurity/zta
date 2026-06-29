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

The hard part is that **there is no universal interception API across agents** —
hook payload shapes and deny signals differ, and some agents have no hook at all.
`zta` handles this with two enforcement tiers and is explicit about which one
each agent gets — no false sense of security. (As of 2026, Claude Code, Codex,
Cursor, and Copilot all expose a real *blocking* pre-tool hook; each adapter
speaks that agent's exact protocol.)

| Tier | Mechanism | Assurance | Agents |
|------|-----------|-----------|--------|
| **Hook** | the agent's native pre-tool-call hook calls `zta guard` | High — the call is genuinely blocked | Claude Code, Codex, Cursor, Copilot (✅) |
| **Sandbox (shim)** | `zta run` launches the agent with a shim PATH that routes command execution through the engine | Catches commands the agent runs (any agent) | ✅ any agent |
| **Sandbox (container)** | `zta run --backend=docker` isolates the agent in a hardened container; the shim runs inside | Kernel-enforced: host FS/creds absent, network restricted, secrets masked, command policy still applied | ✅ any agent (needs Docker) |

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
- ✅ `zta run` — sandbox-tier launcher (shim or hardened-container backend)
- ✅ `zta audit` — posture auditor; scores config vs the control catalog, gates CI
- ✅ `zta version`
- ✅ Hook adapters: Claude Code, Codex, Cursor, Copilot (each speaks its native
  hook protocol and deny format)
- ✅ Engine + embedded default policy (destructive deletes, pipe-to-shell,
  force-push, credential read/write, secret-in-code, policy-integrity)

Planned (see [Roadmap](#roadmap)): tool-call logging, and tagged releases.

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

### Codex, Cursor, Copilot (hook tier)

`zta init --agent <name>` writes each agent's native hook config — Codex's
`.codex/hooks.json`, Cursor's `.cursor/hooks.json`, or Copilot's
`.github/hooks/zta.json` — pointing at `zta guard --agent <name>`. Each adapter
emits that agent's exact deny signal (Codex: exit 2 + stderr; Cursor:
`{"permission":"deny"}`; Copilot: `{"permissionDecision":"deny"}`).

```bash
zta init --agent codex     # or cursor, copilot
```

> Hook coverage and schemas vary by version (e.g. Codex's PreToolUse sees only
> some shell paths). After wiring, **verify enforcement** by attempting a denied
> command and confirming `zta` blocks it; pair with the sandbox tier for defense
> in depth.

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

For stronger, kernel-enforced isolation, add `--backend=docker` (requires Docker):

```bash
zta run --backend=docker --image=my-dev-image -- aider
```

The agent runs in a container as your user with **only the project mounted** —
the host home, `~/.ssh`, `~/.aws`, and the rest of the host filesystem are absent.
`--network none` (default; override with `--network`) blocks exfil and remote
code download, repo-local secret files (`.env`, `*.key`, …) are masked so even a
raw read returns nothing, and the shim still applies command policy inside. This
closes the shim tier's gap: file reads the agent performs via its own syscalls,
not just commands. Use `--tty` for interactive agents and `--mount` for extra
volumes.

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

### Common flags (`guard` / `run`)

| Flag | Default | Purpose |
|------|---------|---------|
| `--agent` | `claude-code` | which agent protocol to speak |
| `--root` | `$ZTA_PROJECT_DIR`, `$CLAUDE_PROJECT_DIR`, else cwd | project root for policy-integrity scoping |
| `--policy` | `$ZTA_POLICY` | optional JSON policy file overriding the defaults |

(`init` and `audit` have their own flags — `init [--dir] [--policy] [--dry-run] [--force]`, `audit [DIR] [--strict]`.)

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

`zta` is a deterministic layer at the tool-call boundary. The `docker` backend
adds real OS isolation, but the default (hook / shim) path is **not a sandbox**,
and nothing here is complete:

- **The model can route around naive blocks.** Block `Write` and it may use a
  Bash heredoc; block `rm` and it may use `perl -e unlink`. The command rules
  cover common shapes, not all of them.
- **The shim backend intercepts *commands*, not raw syscalls.** It evaluates what
  the agent executes through the shell and shimmed binaries, but does **not** trap
  file reads/writes the agent's own process performs directly (e.g. opening `.env`
  via a syscall rather than running `cat`). For that, use the hook tier or the
  `docker` backend, which removes host credentials from the filesystem entirely.
- **The container backend depends on Docker** and on you supplying an image with
  your agent's toolchain. It hardens the host boundary (FS/creds/network); within
  the mounted `/workspace`, destructive deletes of specific subpaths are still
  possible (recoverable via git) since the delete rule targets broad/system paths.
- **Hook tier depends on the agent honoring hooks.** On agents without real
  hooks, use the sandbox tier instead.

Treat these as the deterministic 80%, paired with OS-level isolation — not a
replacement for it.

---

## Roadmap

1. **Tool-call logging** — append-only attribution log (OA-01/02), which will also lift the auditor's OA-01/02 for zta-only repos and let `zta init` wire it.
2. **Tagged cross-compiled releases.**

---

## Legacy Claude Code pack

The original `.claude/` bash hooks, `CLAUDE.md`, and `zt-audit/` Python auditor
still live in this repo and remain functional for Claude Code. They are now fully
superseded:

- `zta audit` is a faithful, dependency-free port of `zt-audit/` (verified to
  produce the same scorecard), so the Python auditor can be retired.
- `zta init` generates the equivalent `zta guard` wiring, so the bash hooks can
  be retired in favor of the binary.

Retirement is left as a reviewed human change — `zta` itself cannot modify
`.claude/`, since its own integrity guard blocks that by design.

---

## Development

```bash
go test ./...     # unit tests + fixture-backed behavior tests
go vet ./...
gofmt -l .        # should print nothing
```

v0.1 — derived from Anthropic, *Zero Trust for AI Agents* (2026). Control
mappings are advisory alignments, not legal determinations.
