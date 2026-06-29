// Package sandbox implements the OS-level enforcement tier. Where an agent has
// no native hook, `zta run` launches it with a shim PATH that routes command
// execution back through the policy engine before the real binary runs. This
// file holds the pure, platform-independent evaluation logic; process launch and
// exec live in run.go.
package sandbox

import (
	"path/filepath"
	"strings"

	"github.com/networkdefendersecurity/zta/internal/engine"
	"github.com/networkdefendersecurity/zta/internal/policy"
)

// shells are the interpreters whose -c argument carries a full command string.
// Intercepting these captures pipelines and shell syntax (e.g. curl … | bash)
// that argv-level interception of individual binaries cannot see.
var shells = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ash": true, "ksh": true,
}

func isShell(name string) bool { return shells[filepath.Base(name)] }

// shellCommand returns the command string passed to a shell's command flag
// (-c, or a short cluster ending in c such as -lc / -ic), if the shell is
// invoked in command mode.
//
// It mirrors shell option parsing: scanning stops at the first non-flag
// argument (the script path) or at "--". A real shell only treats -c as the
// command flag when it appears among the options, before any script; a -c that
// follows a script name is a positional argument, not a command. Honoring only
// a pre-script command flag prevents a decoy trailing "-c <benign>" from
// steering evaluation away from the real invocation.
//
// Returning false is always safe: the caller then evaluates the full
// "name args..." string, which still contains any command text and the script
// path. Long options are skipped; their value arguments (if any) are handled
// conservatively by stopping, which only ever over-includes.
func shellCommand(args []string) (string, bool) {
	for i, a := range args {
		switch {
		case a == "--":
			return "", false // end of options; the rest is script + args
		case strings.HasPrefix(a, "--"):
			continue // long option; keep scanning for the command flag
		case len(a) >= 2 && a[0] == '-':
			if strings.HasSuffix(a, "c") && i+1 < len(args) {
				return args[i+1], true
			}
			// non-command short flag/cluster; keep scanning
		default:
			return "", false // first non-flag argument is the script path
		}
	}
	return "", false
}

// commandString reconstructs the command to evaluate from an invocation. For a
// shell with -c it is the inner command (the real intent); otherwise it is the
// tool name plus its arguments. Reconstruction is only used for matching — the
// real process is later exec'd with its original, unmodified argv.
func commandString(name string, args []string) string {
	if isShell(name) {
		if c, ok := shellCommand(args); ok {
			return c
		}
	}
	if len(args) == 0 {
		return filepath.Base(name)
	}
	return filepath.Base(name) + " " + strings.Join(args, " ")
}

// invocationEvent builds the normalized exec event for an intercepted command.
func invocationEvent(name string, args []string) *policy.Event {
	return &policy.Event{
		Action:  policy.ActionExec,
		Command: commandString(name, args),
		Agent:   "sandbox",
	}
}

// EvalInvocation evaluates an intercepted command against the policy.
func EvalInvocation(p *policy.Policy, name string, args []string) policy.Decision {
	return engine.Evaluate(p, invocationEvent(name, args))
}
