package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// settings is the subset of .claude/settings.json the audit inspects.
type settings struct {
	Permissions struct {
		Deny []string `json:"deny"`
		Ask  []string `json:"ask"`
	} `json:"permissions"`
	Hooks map[string][]hookGroup `json:"hooks"`
}

type hookGroup struct {
	Matcher string    `json:"matcher"`
	Hooks   []hookCmd `json:"hooks"`
}

type hookCmd struct {
	Command string `json:"command"`
}

// hookEntry is a flattened (matcher, command) pair.
type hookEntry struct{ matcher, command string }

func (s *settings) entries(event string) []hookEntry {
	var out []hookEntry
	for _, g := range s.Hooks[event] {
		for _, h := range g.Hooks {
			out = append(out, hookEntry{g.Matcher, h.Command})
		}
	}
	return out
}

func (s *settings) commands(event string) []string {
	e := s.entries(event)
	out := make([]string, len(e))
	for i, x := range e {
		out[i] = x.command
	}
	return out
}

func (s *settings) allCommands() []string {
	var out []string
	for ev := range s.Hooks {
		out = append(out, s.commands(ev)...)
	}
	return out
}

// Evaluate scores every control for the repository at root.
func Evaluate(root string) map[string]Result {
	s := loadSettings(root)
	deny := s.Permissions.Deny
	ask := s.Permissions.Ask
	pre := s.commands("PreToolUse")
	all := s.allCommands()
	agents := subagents(root)

	res := map[string]Result{}

	// A command counts as a guard / file-guard / secret-scan if it invokes the
	// legacy bash hook OR routes through zta (whose single engine covers all of
	// them). Logging has no zta equivalent yet.
	guard := anyHas(pre, "zt-guard", "zta guard", "zta run")
	fileGuard := anyHas(pre, "zt-file-guard", "zta guard", "zta run")
	secretScan := anyHas(all, "zt-secret-scan", "zta guard", "zta run")
	ztaWired := anyHas(all, "zta guard", "zta run")

	// IA-02 — credentials out of reach
	switch {
	case secretScan && fileGuard:
		res["IA-02"] = Result{Pass, "secret-scan + file-guard enforcement registered"}
	case secretScan || fileGuard:
		res["IA-02"] = Result{Partial, "only one of secret-scan / file-guard present"}
	default:
		res["IA-02"] = Result{Fail, "no secret-scan or file-guard enforcement"}
	}

	// AC-01 — deny-by-default
	switch {
	case len(deny) > 0 && guard:
		res["AC-01"] = Result{Pass, fmt.Sprintf("%d deny rules + command guard", len(deny))}
	case len(deny) > 0 || guard:
		res["AC-01"] = Result{Partial, "deny list or command guard present, not both"}
	default:
		res["AC-01"] = Result{Fail, "no deny rules and no command guard"}
	}

	// AC-02 — least-privilege scoping per subagent
	switch {
	case len(agents) == 0:
		res["AC-02"] = Result{Partial, "no subagents defined to scope"}
	default:
		var unscoped []string
		for name, scoped := range agents {
			if !scoped {
				unscoped = append(unscoped, name)
			}
		}
		if len(unscoped) == 0 {
			res["AC-02"] = Result{Pass, fmt.Sprintf("all %d subagents have a tools allowlist", len(agents))}
		} else {
			res["AC-02"] = Result{Fail, "subagents missing tools allowlist: " + strings.Join(unscoped, ", ")}
		}
	}

	// AC-03 — isolation/sandbox (manual)
	if fileExists(filepath.Join(root, ".claude", "ISOLATION.md")) {
		res["AC-03"] = Result{Manual, "documented isolation note found; verify OS-level sandbox/egress"}
	} else {
		res["AC-03"] = Result{Manual, "verify OS-level sandbox/egress out-of-band (e.g. zta run + container)"}
	}

	// OA-01 — comprehensive logging (wildcard logging hook)
	starLog := hasStarLog(s, "PreToolUse") || hasStarLog(s, "PostToolUse")
	if starLog {
		res["OA-01"] = Result{Pass, "logging hook on * matcher"}
	} else {
		res["OA-01"] = Result{Fail, "no wildcard logging hook"}
	}

	// OA-02 — traceability
	logSrc := readFile(root, ".claude", "hooks", "zt-log.sh")
	switch {
	case starLog && strings.Contains(logSrc, "session") && strings.Contains(logSrc, "agent"):
		res["OA-02"] = Result{Pass, "log records carry session + agent attribution"}
	case starLog:
		res["OA-02"] = Result{Partial, "logging present but session/agent fields unconfirmed"}
	default:
		res["OA-02"] = Result{Fail, "no logging to trace"}
	}

	// IO-01 — untrusted input handling
	webGated := anyContains(append(append([]string{}, ask...), deny...), "WebFetch")
	_, hasResearcher := agents["researcher.md"]
	switch {
	case fileGuard && (webGated || hasResearcher):
		res["IO-01"] = Result{Pass, "file-guard + WebFetch gating / researcher scoping"}
	case fileGuard:
		res["IO-01"] = Result{Partial, "file-guard present; WebFetch not gated"}
	default:
		res["IO-01"] = Result{Fail, "no untrusted-input controls"}
	}

	// IO-02 — output filtering
	if secretScan {
		res["IO-02"] = Result{Pass, "secret-scan enforcement on writes"}
	} else {
		res["IO-02"] = Result{Fail, "no secret-scan enforcement"}
	}

	// IR-01 — config integrity
	fg := readFile(root, ".claude", "hooks", "zt-file-guard.sh")
	protected := strings.Contains(fg, ".claude") || anyContains(deny, ".claude") || ztaWired
	if fileExists(filepath.Join(root, ".claude", "settings.json")) && protected {
		res["IR-01"] = Result{Pass, "policy present and write-protected from the agent"}
	} else {
		res["IR-01"] = Result{Partial, "policy present but not write-protected"}
	}

	// GV-01 — acceptable use
	claudeMD := strings.ToLower(readFile(root, "CLAUDE.md"))
	if claudeMD != "" && (strings.Contains(claudeMD, "acceptable use") || strings.Contains(claudeMD, "policy")) {
		res["GV-01"] = Result{Pass, "CLAUDE.md documents acceptable use"}
	} else {
		res["GV-01"] = Result{Fail, "no acceptable-use policy in CLAUDE.md"}
	}

	// GV-03 — enforcement installed / gate present
	hooksOnDisk, _ := filepath.Glob(filepath.Join(root, ".claude", "hooks", "*.sh"))
	enforcement := ztaWired || len(hooksOnDisk) > 0
	if fileExists(filepath.Join(root, ".claude", "settings.json")) && enforcement {
		res["GV-03"] = Result{Pass, "enforcement present; audit gating the build"}
	} else {
		res["GV-03"] = Result{Fail, "no enforcement wired up"}
	}

	// Remaining controls are not assessed at repo scope.
	for _, c := range controls {
		if _, ok := res[c.ID]; !ok {
			res[c.ID] = Result{NA, ""}
		}
	}
	return res
}

func hasStarLog(s *settings, event string) bool {
	for _, e := range s.entries(event) {
		if e.matcher == "*" && strings.Contains(e.command, "zt-log") {
			return true
		}
	}
	return false
}

func loadSettings(root string) *settings {
	s := &settings{}
	b, err := os.ReadFile(filepath.Join(root, ".claude", "settings.json"))
	if err != nil {
		return s // empty settings: repo-scope checks naturally fail
	}
	_ = json.Unmarshal(b, s) // tolerate malformed config; treat as empty
	return s
}

// subagents maps each .claude/agents/*.md filename to whether it declares a
// bounded tools: allowlist in its frontmatter.
func subagents(root string) map[string]bool {
	out := map[string]bool{}
	files, _ := filepath.Glob(filepath.Join(root, ".claude", "agents", "*.md"))
	fm := regexp.MustCompile(`(?sm)^---\s*$(.*?)^---\s*$`)
	tools := regexp.MustCompile(`(?m)^\s*tools\s*:\s*(.+)$`)
	for _, p := range files {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		scoped := false
		if m := fm.FindSubmatch(b); m != nil {
			if t := tools.FindSubmatch(m[1]); t != nil && strings.TrimSpace(string(t[1])) != "" {
				scoped = true
			}
		}
		out[filepath.Base(p)] = scoped
	}
	return out
}

func anyHas(cmds []string, needles ...string) bool {
	for _, c := range cmds {
		for _, n := range needles {
			if strings.Contains(c, n) {
				return true
			}
		}
	}
	return false
}

func anyContains(xs []string, needle string) bool {
	for _, x := range xs {
		if strings.Contains(x, needle) {
			return true
		}
	}
	return false
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func readFile(root string, parts ...string) string {
	b, err := os.ReadFile(filepath.Join(append([]string{root}, parts...)...))
	if err != nil {
		return ""
	}
	return string(b)
}

// Counts tallies results by status.
type Counts struct{ Pass, Fail, Partial, Manual, NA int }

func tally(res map[string]Result) Counts {
	var c Counts
	for _, r := range res {
		switch r.Status {
		case Pass:
			c.Pass++
		case Fail:
			c.Fail++
		case Partial:
			c.Partial++
		case Manual:
			c.Manual++
		case NA:
			c.NA++
		}
	}
	return c
}

var color = map[Status]string{
	Pass: "\033[32m", Fail: "\033[31m", Partial: "\033[33m",
	Manual: "\033[36m", NA: "\033[90m",
}

const reset = "\033[0m"

// Run evaluates root, renders the scorecard to w, and returns the process exit
// code (1 on any FAIL, or any PARTIAL when strict).
func Run(w io.Writer, root string, strict, useColor bool) int {
	res := Evaluate(root)
	abs, _ := filepath.Abs(root)

	fmt.Fprintln(w)
	fmt.Fprintln(w, "  Zero-Trust Agent Posture Audit  —  repo scope")
	fmt.Fprintln(w, "  root: "+abs)
	fmt.Fprintln(w, "  "+strings.Repeat("-", 72))
	fmt.Fprintf(w, "  %-6s %-8s %-22s %s\n", "ID", "STATUS", "DOMAIN", "CONTROL")
	fmt.Fprintln(w, "  "+strings.Repeat("-", 72))

	for _, c := range controls {
		r := res[c.ID]
		status := fmt.Sprintf("%-8s", r.Status)
		if useColor {
			status = color[r.Status] + status + reset
		}
		fmt.Fprintf(w, "  %-6s %s %-22.22s %s\n", c.ID, status, c.Domain, c.Name)
		if r.Detail != "" && (r.Status == Fail || r.Status == Partial || r.Status == Manual) {
			fmt.Fprintf(w, "  %-6s %-8s %-22s   -> %s\n", "", "", "", r.Detail)
		}
	}

	cnt := tally(res)
	fmt.Fprintln(w, "  "+strings.Repeat("-", 72))
	fmt.Fprintf(w, "  %d pass · %d fail · %d partial · %d manual · %d n/a\n",
		cnt.Pass, cnt.Fail, cnt.Partial, cnt.Manual, cnt.NA)

	failed := cnt.Fail > 0 || (strict && cnt.Partial > 0)
	verdict := "FOUNDATION MET (repo scope)"
	switch {
	case failed:
		verdict = "FOUNDATION NOT MET"
	case cnt.Partial > 0:
		verdict = "FOUNDATION PARTIAL (repo scope)"
	}
	fmt.Fprintf(w, "  verdict: %s\n\n", verdict)

	if failed {
		return 1
	}
	return 0
}
