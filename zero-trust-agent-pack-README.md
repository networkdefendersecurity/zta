# Zero-Trust Agent Pack

A drop-in `.claude/` policy bundle plus a CI auditor that holds an agentic coding tool
(and the subagents it spawns) to the Anthropic *Zero Trust for AI Agents* Foundation tier.

It has two layers:

- **Enforce** — runtime guards (`PreToolUse` hooks), deny-by-default permissions, and
  least-privilege subagents that constrain the agent *while it works*.
- **Verify** — a CI auditor (`zt-audit/`) that scores the repo's agent configuration against
  the Foundation control catalog and **fails the build** if the agent is misconfigured.

> Scope: this secures the *coding agent's* behavior inside a repo. It is the low-blast-radius
> starting point — not a credential proxy or a production enforcement layer.

---

## Install

Copy `.claude/`, `CLAUDE.md`, `zt-audit/`, and `.github/workflows/zt-audit.yml` into your repo,
then commit them. Hooks fire automatically the next time Claude Code runs in the project.

Requirements: `bash`, and either `jq` **or** `python3` for the hooks (they prefer `jq`, fall back
to `python3`, and fail-closed only if neither exists). The auditor needs `python3` (stdlib only).

Verify locally:

```bash
bash tests/test_hooks.sh        # hook self-tests (no dangerous commands are ever run)
python3 zt-audit/zt_audit.py .  # posture audit; exits non-zero on any FAIL
```

---

## What each piece enforces

| File | Mechanism | Controls |
|------|-----------|----------|
| `.claude/settings.json` | deny-by-default permissions + hook registration | AC-01 |
| `.claude/hooks/zt-guard.sh` | blocks destructive / pipe-to-shell / force-push / secret-read / policy-tamper Bash | AC-01, IA-02, IR-01 |
| `.claude/hooks/zt-file-guard.sh` | blocks reads/writes of `.env`, keys, secrets, and `.git/`; write-protects the policy | IA-02, IR-01 |
| `.claude/hooks/zt-secret-scan.sh` | blocks writing secrets (AWS/OpenAI/Anthropic/GitHub/Slack keys, JWTs, creds) into code | IO-02 |
| `.claude/hooks/zt-log.sh` | append-only JSONL log of every tool call with session + subagent attribution | OA-01, OA-02 |
| `.claude/agents/*.md` | least-privilege subagents (`reviewer` read-only, `test-runner` shell-scoped, `researcher` web-only) | AC-02, IO-01 |
| `CLAUDE.md` | acceptable-use policy for agents in the repo | GV-01 |
| `zt-audit/` + CI workflow | scores config vs catalog, gates the build | GV-03 |

The enforcement contract: a `PreToolUse` hook that exits `2` blocks the tool call, and that block
holds **even under `--dangerously-skip-permissions`** — bypass mode skips interactive prompts and
the auto-mode classifier, not hooks. All guards are **fail-closed** (deny on unparseable input).

---

## Honest limits (read this)

Hooks are a deterministic layer at the *tool-call boundary*. They are not a sandbox, and they are
not complete:

- **The model routes around naive blocks.** Block `Write` and it may use a Bash heredoc; block `rm`
  and it may use `perl -e unlink`. The Bash guard covers common shapes, not all of them.
- **Real isolation needs OS-level controls.** For hard guarantees, run the agent in a sandboxed /
  containerized worktree with restricted filesystem and network egress. That is control AC-03, and
  the auditor reports it as `MANUAL` — the pack cannot verify it for you.
- **Subagent / MCP / pipe-mode edges.** Hooks can fail to fire in some subagent, MCP, and
  `claude -p` paths. Subagent safety leans more on each agent's `tools:` allowlist (reliable) than
  on a hook firing inside it.
- **Permission matching is imperfect.** Use hooks for enforcement and permissions for convenience;
  the auditor checks both.

Treat this pack as the deterministic 80% plus a verifiable posture baseline — paired with OS-level
isolation, not a replacement for it.

---

## Controls assessed elsewhere

The repo cannot meaningfully assess runtime behavioral monitoring (BM-*), persisted memory (MP-*),
cryptographic agent identity (IA-01), tested rollback (IR-02), or org-level incident response
(GV-02). The auditor marks these `N/A` at repo scope; they belong to the full deployment
assessment (the Agent Security Posture Assessment workbook).

v0.1 — derived from Anthropic, *Zero Trust for AI Agents* (2026). Compliance mappings in the
catalog are advisory alignments, not legal determinations.
