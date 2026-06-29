// Package engine evaluates a normalized policy.Event against a policy.Policy and
// returns a verdict. It is pure and agent-agnostic: all agent-specific parsing
// happens in adapters before this point. Default verdict is allow; rules block.
package engine

import (
	"path/filepath"
	"strings"

	"github.com/networkdefendersecurity/zta/internal/policy"
)

// Evaluate returns the policy decision for an event. The order mirrors the
// original guard set: command rules for exec, then file rules for read/write.
func Evaluate(p *policy.Policy, e *policy.Event) policy.Decision {
	switch e.Action {
	case policy.ActionExec:
		if d, blocked := matchSet(p.DenyExec, e.Command); blocked {
			return d
		}

	case policy.ActionFileRead, policy.ActionFileWrite:
		if d, blocked := secretFile(e.Path); blocked {
			return d
		}
		if d, blocked := matchSet(p.DenyPath, e.Path); blocked {
			return d
		}
		if e.Action == policy.ActionFileWrite {
			if d, blocked := protectedWrite(p, e.Path); blocked {
				return d
			}
			if d, blocked := matchSet(p.SecretContent, e.Content); blocked {
				return d
			}
		}
	}
	return policy.Decision{Allow: true}
}

// matchSet returns a blocking decision for the first rule that matches s.
func matchSet(rules []*policy.Rule, s string) (policy.Decision, bool) {
	if s == "" {
		return policy.Decision{}, false
	}
	for _, r := range rules {
		if r.Match(s) {
			return block(r), true
		}
	}
	return policy.Decision{}, false
}

// secretFile blocks dotenv files by basename, allowing the conventional
// template suffixes. Lookahead isn't available in RE2, so this is done in code.
func secretFile(path string) (policy.Decision, bool) {
	if path == "" {
		return policy.Decision{}, false
	}
	base := filepath.Base(path)
	switch base {
	case ".env.example", ".env.sample", ".env.template":
		return policy.Decision{}, false
	}
	if base == ".env" || strings.HasPrefix(base, ".env.") {
		return policy.Decision{
			Allow:   false,
			Rule:    "secret-file",
			Control: "IA-02",
			Reason:  "access to secret file: " + base,
		}, true
	}
	return policy.Decision{}, false
}

// protectedWrite blocks writes to integrity-protected paths, but only when the
// path resolves inside the project root. This keeps the guard from protecting
// unrelated .claude/ or .git/ directories elsewhere on disk.
func protectedWrite(p *policy.Policy, path string) (policy.Decision, bool) {
	for _, r := range p.ProtectWrite {
		if r.Match(path) && withinProject(path, p.ProjectRoot) {
			return block(r), true
		}
	}
	return policy.Decision{}, false
}

// withinProject reports whether path is inside root. Relative paths are assumed
// to be within the working tree. An empty root disables scoping (match anywhere).
func withinProject(path, root string) bool {
	if !filepath.IsAbs(path) || root == "" {
		return true
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func block(r *policy.Rule) policy.Decision {
	return policy.Decision{Allow: false, Rule: r.Name, Control: r.Control, Reason: r.Reason}
}
