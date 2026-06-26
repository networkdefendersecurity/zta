# Isolation note (AC-03 — assessed out of band)

The hooks in this pack are a **deterministic guard at the tool-call boundary, not a
sandbox.** A capable model can route around naive pattern blocks (a blocked `Write`
becomes a Bash heredoc; a blocked `rm` becomes `perl -e 'unlink'`), and hooks can fail to
fire in some subagent, MCP, and `claude -p` paths.

For hard guarantees, run the coding agent inside an OS-level isolation boundary that sits
**below** the tool layer:

- **Filesystem:** a dedicated worktree / container with no access to credential stores
  (`~/.aws`, `~/.ssh`, `~/.config/gh`), the host home directory, or other repos.
- **Network egress:** default-deny outbound, allowlisting only the registries and APIs the
  task needs. This is the real defense against exfiltration, which a hook cannot guarantee.
- **Privilege:** run as a non-root user with no `sudo`; mount the repo read-only where the
  task allows it.

The auditor reports **AC-03 as MANUAL** because the repository cannot verify this for you.
Record here how isolation is actually provided in your environment (e.g. "runs in a
gVisor-sandboxed devcontainer with egress restricted to npm + the GitHub API") so a
reviewer can confirm it.
