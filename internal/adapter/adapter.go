// Package adapter translates between a specific coding agent's native
// interception format and the normalized policy.Event/Decision the engine uses.
// Each supported agent registers one Adapter; the sandbox tier handles agents
// that expose no usable interception point.
package adapter

import (
	"errors"
	"io"
	"sort"

	"github.com/networkdefendersecurity/zta/internal/policy"
)

// ErrPassthrough signals that an event is outside the policy's scope (e.g. a
// tool this guard doesn't gate) and should be allowed without evaluation.
var ErrPassthrough = errors.New("event not subject to policy")

// Adapter wires one agent's interception protocol to the engine.
type Adapter interface {
	// Name is the stable identifier used on the command line (e.g. "claude-code").
	Name() string
	// Parse reads one interception payload and normalizes it. It returns
	// ErrPassthrough for events the guard does not gate.
	Parse(r io.Reader) (*policy.Event, error)
	// Respond emits the decision in the agent's expected format and returns the
	// process exit code the agent interprets (0 allow, non-zero block).
	Respond(w io.Writer, d policy.Decision) int
}

var registry = map[string]Adapter{}

// Register makes an adapter available by name. Called from adapter init().
func Register(a Adapter) { registry[a.Name()] = a }

// Get returns the adapter registered under name, or false.
func Get(name string) (Adapter, bool) {
	a, ok := registry[name]
	return a, ok
}

// Names returns the registered adapter names, sorted.
func Names() []string {
	out := make([]string, 0, len(registry))
	for n := range registry {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
