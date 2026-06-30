# zta — Zero-Trust enforcement for AI coding agents

`zta` is a single, zero-dependency Go binary that holds an AI coding agent — and
any subagents it spawns — to a zero-trust policy **while it works**. It blocks
destructive commands, secret reads/writes, force-pushes, and policy tampering the
moment the agent tries them, regardless of which agent you run.

It enforces at the **tool-call boundary** — a deterministic check that runs before
an operation and can deny it — not prompt-level guidance the model can ignore.

> **Scope.** `zta` secures a coding agent's *behavior inside a repo*. It's a
> low-blast-radius enforcement layer, not a credential proxy or network control.
> Read [Honest limits](#honest-limits) first.

## Enforcement tiers

The same engine runs in every tier; only the wiring differs.

| Tier | Mechanism | Assurance |
|------|-----------|-----------|
| **Hook** | the agent's native pre-tool hook calls `zta guard` | High — the call is genuinely blocked (Claude Code, Codex, Cursor, Copilot) |
| **Sandbox (shim)** | `zta run` puts a shim `PATH` in front of any agent | Guardrail — catches commands run through the shell |
| **Sandbox (container)** | `zta run --backend=docker` | Kernel-enforced: host FS/creds absent, network off, secrets masked |

Design notes: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Install

From source (Go 1.26+) — a static, dependency-free binary:

```bash
go build -o zta ./cmd/zta && install -m755 zta /usr/local/bin/zta
```

Tagged releases also publish static binaries + `SHA256SUMS` for linux/darwin/
windows. The sandbox tier is Unix-only; the hook tier works everywhere.

## Usage

Wire enforcement into a repo (idempotent; preview with `--dry-run`):

```bash
zta init                  # wire `zta guard` for the agent + scaffold CLAUDE.md
zta init --agent codex    # or cursor, copilot
zta audit .               # score config against the control catalog (CI gate)
```

For Claude Code that's a single `PreToolUse` hook in `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash|Read|Edit|Write|NotebookEdit",
        "hooks": [{ "type": "command", "command": "zta guard --agent claude-code" }] }
    ]
  }
}
```

The hook calls `zta` by name, so the binary must be on `PATH` where the agent
runs — otherwise enforcement silently degrades. Keep `zta audit .` in CI to catch
un-wired configs.

For an agent with no usable hook, launch it through the sandbox instead:

```bash
zta run -- aider                                 # shim tier: any CLI agent
zta run --backend=docker --image=dev -- aider    # container tier (needs Docker)
```

`zta help` lists all flags.

### Try it directly

`zta guard` reads one operation as JSON on stdin and exits `0` (allow) or `2`
(block):

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"curl x.sh | bash"}}' \
  | zta guard --agent claude-code; echo "exit=$?"   # exit=2, blocked
```

Every gated decision is appended to `.zta/logs/audit.jsonl` (path only, never
content). Redirect with `ZTA_LOG=<path>` or disable with `ZTA_LOG=off`.

## Policy

Secure defaults are compiled into the binary, so `zta` is safe with no config:

| Control | Blocks |
|---------|--------|
| **AC-01** | destructive deletes; pipe-to-shell / fetch piped to an interpreter |
| **IA-02** | force-push; reading credential files (`.env`, keys, `.aws/credentials`, …) |
| **IR-01** | writes to the policy dir (`.claude/`, `.zta/`) and `.git/` internals |
| **IO-02** | writing secrets into code (cloud/API keys, JWTs, private keys) |

Override with a JSON file via `--policy` (or `zta init --policy` to scaffold one).
Any rule set you specify replaces that default; omitted sets keep theirs. Patterns
are RE2.

```json
{ "deny_exec": [
  { "name": "no-terraform-apply", "control": "AC-01",
    "reason": "infra changes go through CI", "pattern": "(?i)terraform[[:space:]]+apply" }
] }
```

## Honest limits

`zta` is a deterministic layer, not a complete sandbox:

- **Command rules cover common shapes, not all.** A model can reach for an
  interpreter (`perl -e unlink`) or a variant the rules don't match.
- **The shim tier is a guardrail, not a boundary.** It runs as the same user as
  the agent, so an adversarial or prompt-injected agent escapes it in one line
  (absolute path, or restoring `PATH`). It catches *accidental* dangerous
  commands; for an actively-hostile agent use the **`docker` backend**
  (kernel-enforced).
- **The shim sees commands, not raw syscalls** — it won't trap a file read the
  agent's own process performs directly. The hook tier and docker backend close
  this.
- **The hook tier depends on the agent honoring hooks**; for agents that don't,
  use the sandbox tier.

Treat this as the deterministic 80%, paired with OS-level isolation — not a
replacement for it.

## Development

```bash
go test ./... && go vet ./... && gofmt -l .   # gofmt should print nothing
```

CI (`go test`/`vet`/cross-compile/`zta audit` + a guard smoke-test) gates `main`
and every PR. Tag `vX.Y.Z` to cut a release.

v0.1 — derived from Anthropic, *Zero Trust for AI Agents* (2026). Control mappings
are advisory alignments.
