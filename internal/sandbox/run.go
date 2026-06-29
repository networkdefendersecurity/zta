//go:build !windows

package sandbox

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/networkdefendersecurity/zta/internal/auditlog"
	"github.com/networkdefendersecurity/zta/internal/engine"
	"github.com/networkdefendersecurity/zta/internal/policy"
)

// blockCode is the exit status a shimmed command returns when the policy denies
// it. 126 is the shell convention for "found but not executable", which reads
// naturally to the agent as a failed command.
const blockCode = 126

// defaultTargets are the binaries shimmed by default: the shells (which carry
// full command strings via -c) plus a few high-risk tools that agents sometimes
// exec directly without a shell.
var defaultTargets = []string{
	"sh", "bash", "zsh", "dash", "ash", "ksh",
	"rm", "git", "curl", "wget", "chmod", "dd",
}

// Options configures a sandboxed run.
type Options struct {
	PolicyFile   string   // optional JSON policy override
	Root         string   // project root for policy-integrity scoping
	ExtraTargets []string // additional binaries to shim
}

// Run launches argv with a shim PATH that routes execution of the target
// binaries back through `zta __shim`. It returns the child's exit code. The
// shim directory is removed when the child exits.
func Run(argv []string, opts Options) (int, error) {
	if len(argv) == 0 {
		return 2, errors.New("no command to run")
	}
	bin, err := os.Executable()
	if err != nil {
		return 2, fmt.Errorf("locate zta binary: %w", err)
	}

	shimDir, err := os.MkdirTemp("", "zta-shim-")
	if err != nil {
		return 2, fmt.Errorf("create shim dir: %w", err)
	}
	defer os.RemoveAll(shimDir)

	for _, t := range append(append([]string{}, defaultTargets...), opts.ExtraTargets...) {
		if err := writeShim(shimDir, t, bin); err != nil {
			return 2, err
		}
	}

	origPath := os.Getenv("PATH")
	env := append(os.Environ(),
		"PATH="+shimDir+string(os.PathListSeparator)+origPath,
		"ZTA_REAL_PATH="+origPath, // PATH without the shim dir, so shims find real binaries
		"ZTA_BIN="+bin,
		"ZTA_SESSION=sandbox-"+strconv.Itoa(os.Getpid()),
	)
	if opts.PolicyFile != "" {
		env = append(env, "ZTA_POLICY="+opts.PolicyFile)
	}
	if opts.Root != "" {
		env = append(env, "ZTA_PROJECT_DIR="+opts.Root)
	}

	// exec.Command resolves argv[0] against the *parent* PATH, which would run
	// the real binary and intercept only its children. Resolve against the
	// shim-first PATH ourselves so the top-level command is shimmed too.
	cmd := exec.Command(argv[0], argv[1:]...)
	resolved, err := lookInPath(argv[0], shimDir+string(os.PathListSeparator)+origPath)
	if err != nil {
		return 2, fmt.Errorf("locate %q: %w", argv[0], err)
	}
	cmd.Path = resolved
	cmd.Env = env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr

	runErr := cmd.Run()
	if cmd.ProcessState != nil {
		return cmd.ProcessState.ExitCode(), nil
	}
	if runErr != nil {
		return 2, fmt.Errorf("start %q: %w", argv[0], runErr)
	}
	return 0, nil
}

// Shim is the entrypoint each shim wrapper calls. It evaluates the intercepted
// invocation and, if allowed, replaces itself with the real binary. It is
// fail-closed: a policy it cannot load blocks the command.
func Shim(name string, args []string) int {
	pol, err := policy.Load(os.Getenv("ZTA_POLICY"), true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "zta: sandbox policy load failed, blocking: %v\n", err)
		return blockCode
	}
	pol.ProjectRoot = os.Getenv("ZTA_PROJECT_DIR")

	ev := invocationEvent(name, args)
	ev.Session = os.Getenv("ZTA_SESSION")
	d := engine.Evaluate(pol, ev)
	auditlog.Log(pol.ProjectRoot, ev, d)
	if !d.Allow {
		fmt.Fprintf(os.Stderr, "zta: blocked in sandbox [%s/%s]: %s\n", d.Control, d.Rule, d.Reason)
		return blockCode
	}

	real, err := lookReal(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "zta: %v\n", err)
		return 127
	}
	if err := syscall.Exec(real, append([]string{real}, args...), os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "zta: exec %s: %v\n", real, err)
		return 126
	}
	return 0 // unreachable: Exec replaces the process on success
}

// writeShim creates an executable wrapper named after a tool that re-invokes the
// zta binary's __shim subcommand.
func writeShim(dir, name, bin string) error {
	script := fmt.Sprintf("#!/bin/sh\nexec %s __shim --name %s -- \"$@\"\n", shQuote(bin), name)
	if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
		return fmt.Errorf("write shim %s: %w", name, err)
	}
	return nil
}

// lookReal finds the real binary for name on ZTA_REAL_PATH (the original PATH,
// which excludes the shim dir, so there is no recursion).
func lookReal(name string) (string, error) {
	return lookInPath(name, os.Getenv("ZTA_REAL_PATH"))
}

// lookInPath resolves an executable by name against a PATH-style string. An
// explicit path (containing a separator) is used as-is if executable.
func lookInPath(name, pathEnv string) (string, error) {
	if strings.ContainsRune(name, os.PathSeparator) {
		if isExec(name) {
			return name, nil
		}
		return "", fmt.Errorf("%s is not an executable file", name)
	}
	for _, dir := range filepath.SplitList(pathEnv) {
		if dir == "" {
			continue
		}
		if cand := filepath.Join(dir, name); isExec(cand) {
			return cand, nil
		}
	}
	return "", fmt.Errorf("%q not found on PATH", name)
}

func isExec(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir() && info.Mode()&0o111 != 0
}

// shQuote single-quotes a string for safe embedding in a /bin/sh script.
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
