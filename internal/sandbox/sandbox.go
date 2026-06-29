package sandbox

// This file holds the option types shared by all platforms. The shim and
// container implementations live in run.go / docker.go (Unix) with stubs in
// unsupported_windows.go, so the package — and the zta binary — build on every
// target even though the sandbox tier itself is Unix-only.

// Options configures a sandboxed run (shim backend).
type Options struct {
	PolicyFile   string   // optional JSON policy override
	Root         string   // project root for policy-integrity scoping
	ExtraTargets []string // additional binaries to shim
}

// DockerOptions configures the container backend of `zta run`.
type DockerOptions struct {
	Image       string   // container image (required)
	Root        string   // host project root, mounted at /workspace (absolute)
	Network     string   // container network mode; default "none"
	PolicyFile  string   // host JSON policy override, mounted read-only (absolute) or ""
	ExtraMounts []string // additional raw `-v` mount specs
	MaskSecrets bool     // mask repo secret files with an empty file
	TTY         bool     // allocate a pseudo-TTY (-t)
	User        string   // run as this uid:gid (set by RunDocker to the host user)
}
