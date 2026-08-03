# zta — guardrails for AI coding agents

`zta` is a tiny, single-file tool that stops an AI coding agent from doing
dangerous things in your project **before** they happen. It works with Claude
Code, Codex, Cursor, and GitHub Copilot, and needs no cloud account, API key, or
configuration to get started.

It blocks things like:

- 🗑️ **Destructive commands** — `rm -rf /`, wiping your repo, force-pushing over history
- 🔑 **Secret leaks** — reading `.env` / SSH keys, or writing API keys into your code
- 🌐 **Remote code execution** — `curl … | bash` and similar
- 🛡️ **Tampering** — the agent editing its own guardrails

Unlike "be careful" notes in a prompt (which a model can ignore), `zta` enforces at
the **tool-call boundary**: a real check that runs the instant the agent tries an
action and can say no.

> Think of it as a seatbelt, not an armored car — it catches the common, costly
> mistakes. For a fully untrusted agent, pair it with Docker mode (below).
> See [Honest limits](#honest-limits).

---

## Quick start (about 2 minutes)

**1. Install it.** Easiest is to download a prebuilt binary from the
[Releases](../../releases) page:

```bash
chmod +x zta_linux_amd64
sudo install -m755 zta_linux_amd64 /usr/local/bin/zta
zta version                                   # confirm it's installed
```

Or build from source (needs [Go](https://go.dev/dl/) 1.26+):

```bash
git clone https://github.com/networkdefendersecurity/zta.git
cd zta
go build -o zta ./cmd/zta
sudo install -m755 zta /usr/local/bin/zta    # put it on your PATH
zta version                                   # confirm it's installed
```

**2. Turn it on in your project.** From your repo, run one command:

```bash
cd ~/my-project
zta init               # wires the guard into your agent + adds a CLAUDE.md
```

That's it — your agent is now guarded. `zta init` defaults to Claude Code; for the
others use `zta init --agent codex` (or `cursor`, `copilot`). It's safe to re-run
and won't overwrite your existing settings.

**3. Confirm it's working.** Send `zta` a dangerous command and watch it refuse:

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' \
  | zta guard --agent claude-code; echo "exit=$?"
```

You should see a `blocked by policy` message and `exit=2` (2 = blocked). A safe
command like `npm test` would print `exit=0`.

> **Heads up:** the agent runs `zta` by name, so the binary must stay on your
> `PATH`. If it's missing, the guard silently does nothing — run `zta version` to
> check, and keep `zta audit .` in your CI.

---

## Upgrading

`zta` is a single binary, so upgrading is a drop-in swap — releases are additive,
with no breaking changes or config migration. Your existing wiring keeps working
because the hook it installs (`zta guard --agent <name>`) is stable across
versions, so **you don't need to re-run `zta init`**.

**Prebuilt binary:** download the new version for your platform from
[Releases](../../releases), replace the old one on your `PATH`, and confirm:

```bash
zta version                     # should print the new version
sha256sum -c SHA256SUMS         # optional: verify the download
```

**From source:**

```bash
git pull && go build -o zta ./cmd/zta
sudo install -m755 zta /usr/local/bin/zta
```

> **Copilot only:** if you wired Copilot before v0.2.1, force a rewrite to pick up
> the shell-keyed (`bash`/`powershell`) hook — a plain `zta init` skips an
> already-wired repo:
> ```bash
> zta init --agent copilot --force
> ```

---

## How it works (30 seconds)

`zta init` adds a small hook to your agent's config (for Claude Code, a
`PreToolUse` hook in `.claude/settings.json`). Every time the agent wants to run a
command or touch a file, the hook asks `zta`, which checks it against a built-in
security policy and allows or blocks it. The policy is **baked into the binary**,
so it's safe out of the box with zero setup.

There are three ways to wire it up, depending on your agent:

| Mode | Command | When to use |
|------|---------|-------------|
| **Hook** *(recommended)* | `zta init` | Claude Code, Codex, Cursor, Copilot — the agent calls `zta` on every action |
| **Sandbox** | `zta run -- <agent>` | Any CLI agent, even ones with no hooks |
| **Container** | `zta run --backend=docker --image=<img> -- <agent>` | Strongest isolation (needs Docker), e.g. `zta run --backend=docker --image=node:20 -- claude` |

---

## Everyday use

After `zta init`, **just use your agent normally** — `zta` runs invisibly and only
speaks up to block something, showing the agent a clear reason so it can adjust.

**Run any agent through the sandbox** (no hook setup needed):

```bash
zta run -- aider           # or codex, cursor-agent … even: zta run -- bash
```

**See what's allowed vs blocked.** Every decision is logged as one line to
`.zta/logs/audit.jsonl` in your project (it records the command/path, **never**
secret contents). Watch them stream in with `zta log`, which tails the log live
by default:

```bash
zta log                # follow decisions live (tail -f style)
zta log --blocked      # only what was blocked (or --allowed)
zta log --no-follow    # print recent decisions and exit
zta log -n 50          # show the last 50 first;  --json for raw JSONL
```

Each line reads `time · DECISION · action · command/path`, with the
`[control/rule]` that fired shown on blocks.

**Check your setup is solid** (great as a CI step):

```bash
zta audit .                # scores your config and fails if it isn't guarded
```

---

## Customizing what's blocked

The defaults already cover the common dangers — no config needed:

| Blocks | Examples |
|--------|----------|
| Destructive deletes & remote code | `rm -rf /`, `curl … \| bash` |
| Credential access | reading `.env`, SSH keys, `.aws/credentials` |
| Secrets in code | committing API keys, tokens, private keys |
| Tampering | writing to `.claude/`, `.zta/`, `.git/` |
| Web-fetch SSRF | fetching `169.254.169.254` (cloud metadata), `localhost`/private IPs, `file://` URLs |

Beyond shell commands and file access, the guard also gates the agent's
**`WebFetch`** (blocking the SSRF shapes above) and logs every **MCP** tool call
(`mcp__*`). MCP has no default blocks — its tool semantics vary per server — but
you can deny specific servers/tools by name with a `deny_mcp` rule.

To add your own rules, create a `zta.json` (start one with `zta init --policy`) and
pass it with `--policy`. Each rule is just a name + a regex. For example, to block
`terraform apply`:

```json
{ "deny_exec": [
  { "name": "no-terraform-apply", "control": "AC-01",
    "reason": "infra changes go through CI",
    "pattern": "(?i)terraform[[:space:]]+apply" }
] }
```

---

## Honest limits

`zta` is a strong, deterministic guardrail — not a bulletproof sandbox. Be
clear-eyed about what it does and doesn't do:

- It matches **common command shapes**, not every possible trick. A determined
  model can reach for an interpreter (`perl -e unlink`) or an obscure variant.
- The **sandbox (shim) mode is a guardrail, not a cage.** It runs as you, so an
  actively-malicious or prompt-injected agent can step around it. For that threat,
  use **`--backend=docker`**, which the operating system enforces.
- The **hook mode relies on the agent honoring its hooks** (Claude Code, Codex,
  Cursor, and Copilot do today).
- **Web-fetch gating covers SSRF shapes** (metadata endpoints, internal
  addresses, non-web schemes), **not** exfiltration to an arbitrary public host —
  there's no reliable deterministic signal for that, so it's left to the sandbox
  tier's `--network none`. Likewise, only the agent's *declared* `WebFetch`/MCP
  tool calls are seen; a raw socket opened inside a `Bash` command is the shell
  guard's job, and true network containment belongs to Docker mode.

Bottom line: `zta` stops the expensive accidents and most bad behavior. Pair it
with Docker mode and good repo hygiene for anything you don't fully trust.

---

## Requirements & notes

- **To build:** Go 1.26+. **To run:** the binary is static and dependency-free.
- Hook mode works on Linux, macOS, and Windows; **sandbox mode is Unix-only**.
- Full design notes: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

### bash vs. PowerShell (Windows)

The `zta` binary is cross-platform and the hook enforcement fires the same way in
both shells. The difference is in **what gets caught**:

| | bash / zsh (Linux, macOS, WSL) | PowerShell (native Windows) |
|---|---|---|
| `zta init` / `zta guard` (hook tier) | ✅ | ✅ |
| `zta run` (sandbox / Docker tier) | ✅ | ❌ Unix-only |
| Secret scanning & `force-push` rules | ✅ | ✅ (shell-agnostic) |
| Destructive / remote-code rules | ✅ | ⚠️ tuned for POSIX syntax — `Remove-Item -Recurse -Force`, `iwr … \| iex` and other PowerShell-native forms are **not** matched yet |

**Recommendation:** on Windows, run your agent under **WSL or Git Bash** for full
coverage. A native PowerShell session still gets hook enforcement, secret
scanning, and the git/tamper guards, but the default destructive-command rules
assume bash syntax, so it's the weaker setup.

## Development

```bash
go test ./... && go vet ./... && gofmt -l .    # gofmt should print nothing
```

CI runs tests, vet, cross-compile, `zta audit`, and a guard smoke-test on every PR.

To check that everything the policy is supposed to block is actually
blocked — every rule, every evasion shape from the security audit, every
adapter, plus a live-agent checklist against a real hook — see
[`redteam/README.md`](redteam/README.md).

Tag `vX.Y.Z` to publish binaries.

v0.1 — derived from Anthropic, *Zero Trust for AI Agents* (2026). Control mappings
are advisory.
