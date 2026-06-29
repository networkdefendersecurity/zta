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

// shellCommand returns the argument to a shell's -c flag (including bundled
// forms like -lc / -ic), if present.
func shellCommand(args []string) (string, bool) {
	for i, a := range args {
		if len(a) >= 2 && a[0] == '-' && a[1] != '-' && strings.HasSuffix(a, "c") {
			if i+1 < len(args) {
				return args[i+1], true
			}
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

// EvalInvocation evaluates an intercepted command against the policy.
func EvalInvocation(p *policy.Policy, name string, args []string) policy.Decision {
	return engine.Evaluate(p, &policy.Event{
		Action:  policy.ActionExec,
		Command: commandString(name, args),
		Agent:   "sandbox",
	})
}
