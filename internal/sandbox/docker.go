//go:build !windows

package sandbox

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

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

// RunDocker launches argv inside a hardened container: only the project root is
// mounted, the host environment and credentials are absent, the network is
// restricted, and the zta binary is mounted so the shim tier still applies
// command policy inside. Returns the container's exit code.
func RunDocker(argv []string, opts DockerOptions) (int, error) {
	if opts.Image == "" {
		return 2, errors.New("the docker backend requires --image")
	}
	if len(argv) == 0 {
		return 2, errors.New("no command to run")
	}
	ztaBin, err := os.Executable()
	if err != nil {
		return 2, fmt.Errorf("locate zta binary: %w", err)
	}
	// Run as the host user so the agent is non-root in the container and the
	// bind-mounted workspace keeps correct ownership (also why CAP_DAC_OVERRIDE
	// being dropped is fine).
	if opts.User == "" {
		opts.User = fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid())
	}
	dockerBin, err := lookInPath("docker", os.Getenv("PATH"))
	if err != nil {
		return 2, fmt.Errorf("docker not found on PATH: %w", err)
	}

	var emptyFile string
	var masks []string
	if opts.MaskSecrets {
		if masks = secretFilesIn(opts.Root); len(masks) > 0 {
			f, err := os.CreateTemp("", "zta-empty-")
			if err != nil {
				return 2, fmt.Errorf("create mask file: %w", err)
			}
			emptyFile = f.Name()
			f.Close()
			defer os.Remove(emptyFile)
		}
	}

	cmd := exec.Command(dockerBin, dockerArgs(opts, argv, masks, ztaBin, emptyFile)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	runErr := cmd.Run()
	if cmd.ProcessState != nil {
		return cmd.ProcessState.ExitCode(), nil
	}
	if runErr != nil {
		return 2, fmt.Errorf("docker run: %w", runErr)
	}
	return 0, nil
}

// dockerArgs builds the full `docker` argument vector. It is pure so the
// invocation can be unit-tested without a daemon. masks are project-relative
// paths to neutralize; emptyFile is the host file mounted over each.
func dockerArgs(opts DockerOptions, argv, masks []string, ztaBin, emptyFile string) []string {
	network := opts.Network
	if network == "" {
		network = "none"
	}

	args := []string{"run", "--rm", "-i"}
	if opts.TTY {
		args = append(args, "-t")
	}
	args = append(args,
		"--network", network,
		"--security-opt", "no-new-privileges",
		"--cap-drop", "ALL",
	)
	if opts.User != "" {
		args = append(args, "--user", opts.User)
	}
	args = append(args,
		"-v", opts.Root+":/workspace",
		"-w", "/workspace",
		"-v", ztaBin+":/zta:ro", // static zta binary for the nested shim tier
		"-e", "ZTA_PROJECT_DIR=/workspace",
	)
	if opts.PolicyFile != "" {
		args = append(args, "-v", opts.PolicyFile+":/zta-policy.json:ro", "-e", "ZTA_POLICY=/zta-policy.json")
	}
	for _, m := range masks {
		args = append(args, "-v", emptyFile+":/workspace/"+filepath.ToSlash(m)+":ro")
	}
	for _, m := range opts.ExtraMounts {
		args = append(args, "-v", m)
	}

	// Entrypoint: the nested shim tier wraps the agent command, so command
	// policy still applies inside the isolated container.
	args = append(args, "--entrypoint", "/zta", opts.Image, "run", "--root", "/workspace", "--")
	return append(args, argv...)
}

// secretFilesIn returns project-relative paths of files that should be masked in
// the container. The walk skips common large/irrelevant directories and is
// bounded so a huge repo cannot blow up the docker command line.
func secretFilesIn(root string) []string {
	skip := map[string]bool{".git": true, "node_modules": true, "vendor": true}
	const limit = 200
	var out []string
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skip[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if looksSecret(d.Name()) {
			if rel, err := filepath.Rel(root, p); err == nil {
				out = append(out, rel)
			}
		}
		if len(out) >= limit {
			return filepath.SkipAll
		}
		return nil
	})
	return out
}

// looksSecret reports whether a basename names credential material. It mirrors
// the engine's file rules, restricted to what is meaningful to mask by name.
func looksSecret(base string) bool {
	switch base {
	case ".env.example", ".env.sample", ".env.template":
		return false
	case ".git-credentials", ".npmrc", "credentials.json", "id_rsa", "id_ed25519":
		return true
	}
	if base == ".env" || strings.HasPrefix(base, ".env.") {
		return true
	}
	return strings.HasSuffix(base, ".pem") || strings.HasSuffix(base, ".key")
}
