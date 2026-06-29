// Command zta is an agent-agnostic zero-trust enforcement tool for AI coding
// agents. It evaluates each agent operation against a security policy and blocks
// dangerous ones, using each agent's native interception where available and an
// OS-level sandbox where it is not.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/networkdefendersecurity/zta/internal/adapter"
	_ "github.com/networkdefendersecurity/zta/internal/adapter/claudecode"
	"github.com/networkdefendersecurity/zta/internal/audit"
	"github.com/networkdefendersecurity/zta/internal/engine"
	"github.com/networkdefendersecurity/zta/internal/policy"
	"github.com/networkdefendersecurity/zta/internal/sandbox"
	"github.com/networkdefendersecurity/zta/internal/setup"
)

var version = "0.1.0-dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "init":
		cmdInit(os.Args[2:])
	case "guard":
		cmdGuard(os.Args[2:])
	case "run":
		cmdRun(os.Args[2:])
	case "audit":
		cmdAudit(os.Args[2:])
	case "__shim": // internal: invoked by sandbox shim wrappers, not by users
		cmdShim(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Printf("zta %s\n", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "zta: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `zta %s — zero-trust enforcement for AI coding agents

Usage:
  zta init [--agent NAME] [--dir DIR] [--policy] [--dry-run]   wire enforcement into a repo
  zta guard --agent <name> [--root DIR] [--policy FILE]   evaluate one operation from stdin (hook tier)
  zta run [--root DIR] [--policy FILE] -- <command...>    launch a command in the sandbox tier
  zta audit [DIR] [--strict]                              score agent config against the control catalog
  zta version                                             print version
  zta help                                                show this help

Adapters: %s
`, version, strings.Join(adapter.Names(), ", "))
}

// cmdInit wires zta enforcement into a repo for a coding agent and scaffolds the
// supporting policy docs. It is idempotent; --dry-run previews changes.
func cmdInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	agent := fs.String("agent", "claude-code", "coding agent to wire")
	dir := fs.String("dir", ".", "target repository directory")
	pol := fs.Bool("policy", false, "also scaffold a zta.json starter policy")
	dry := fs.Bool("dry-run", false, "show planned changes without writing")
	force := fs.Bool("force", false, "overwrite existing zta wiring / scaffolds")
	fs.Parse(args)

	plan, err := setup.BuildPlan(setup.Options{Dir: *dir, Agent: *agent, Policy: *pol, Force: *force})
	if err != nil {
		fmt.Fprintf(os.Stderr, "zta init: %v\n", err)
		os.Exit(1)
	}

	if len(plan.Changes) == 0 && len(plan.Notes) == 0 {
		fmt.Println("zta init: nothing to do")
		return
	}
	for _, c := range plan.Changes {
		fmt.Printf("  %-7s %s  (%s)\n", c.Action, c.Path, c.Detail)
	}
	for _, n := range plan.Notes {
		fmt.Printf("\n  note: %s\n", n)
	}

	if *dry {
		fmt.Println("\n(dry run — nothing written)")
		return
	}
	if err := plan.Apply(); err != nil {
		fmt.Fprintf(os.Stderr, "zta init: write failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("\nDone. Ensure the `zta` binary is on PATH, then run `zta audit %s` to see remaining gaps.\n", *dir)
}

// cmdGuard is the enforcement entrypoint invoked by an agent's native hook. It
// reads one interception payload on stdin, evaluates it, and exits with the
// code the agent expects (0 allow, non-zero block). It is fail-closed: payloads
// it cannot parse are blocked.
func cmdGuard(args []string) {
	fs := flag.NewFlagSet("guard", flag.ExitOnError)
	agentName := fs.String("agent", "claude-code", "coding agent whose protocol to speak")
	root := fs.String("root", defaultRoot(), "project root used to scope policy-integrity protection")
	policyFile := fs.String("policy", os.Getenv("ZTA_POLICY"), "optional JSON policy file overriding defaults")
	fs.Parse(args)

	a, ok := adapter.Get(*agentName)
	if !ok {
		fmt.Fprintf(os.Stderr, "zta: no adapter for agent %q (have: %s)\n", *agentName, strings.Join(adapter.Names(), ", "))
		os.Exit(2)
	}

	pol, err := policy.Load(*policyFile, true)
	if err != nil {
		// Cannot load policy → fail closed.
		fmt.Fprintf(os.Stderr, "zta: policy load failed, blocking: %v\n", err)
		os.Exit(2)
	}
	pol.ProjectRoot = *root

	ev, err := a.Parse(os.Stdin)
	if err == adapter.ErrPassthrough {
		os.Exit(0) // not a gated operation
	}
	if err != nil {
		// Unparseable gated payload → fail closed.
		fmt.Fprintf(os.Stderr, "zta: could not parse operation, blocking: %v\n", err)
		os.Exit(2)
	}

	d := engine.Evaluate(pol, ev)
	os.Exit(a.Respond(os.Stderr, d))
}

// cmdRun launches a command in the sandbox tier: a shim PATH that routes
// execution of risky binaries back through the policy engine. Use for agents
// that expose no native hook. Everything after `--` is the command to run.
func cmdRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	root := fs.String("root", defaultRoot(), "project root used to scope policy-integrity protection")
	policyFile := fs.String("policy", os.Getenv("ZTA_POLICY"), "optional JSON policy file overriding defaults")
	fs.Parse(args)

	cmd := fs.Args()
	if len(cmd) == 0 {
		fmt.Fprintln(os.Stderr, "zta run: nothing to run\nusage: zta run [--root DIR] [--policy FILE] -- <command...>")
		os.Exit(2)
	}

	code, err := sandbox.Run(cmd, sandbox.Options{PolicyFile: *policyFile, Root: *root})
	if err != nil {
		fmt.Fprintf(os.Stderr, "zta run: %v\n", err)
		os.Exit(2)
	}
	os.Exit(code)
}

// cmdAudit scores a repository's agent configuration against the Foundation
// control catalog and exits non-zero if a repo-scope control fails, so CI can
// gate AI-generated changes.
func cmdAudit(args []string) {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	strict := fs.Bool("strict", false, "also fail the build on PARTIAL results")
	fs.Parse(args)

	root := "."
	if rest := fs.Args(); len(rest) > 0 {
		root = rest[0]
	}
	os.Exit(audit.Run(os.Stdout, root, *strict, isTTY(os.Stdout)))
}

// cmdShim is the internal entrypoint each sandbox shim wrapper invokes. It
// evaluates the intercepted command and, if allowed, execs the real binary.
func cmdShim(args []string) {
	fs := flag.NewFlagSet("__shim", flag.ExitOnError)
	name := fs.String("name", "", "intercepted tool name")
	fs.Parse(args)
	os.Exit(sandbox.Shim(*name, fs.Args()))
}

// isTTY reports whether f is a terminal, used to decide on ANSI color.
func isTTY(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// defaultRoot prefers an agent-provided project dir, falling back to cwd.
func defaultRoot() string {
	for _, k := range []string{"ZTA_PROJECT_DIR", "CLAUDE_PROJECT_DIR"} {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	if wd, err := os.Getwd(); err == nil {
		return wd
	}
	return ""
}
