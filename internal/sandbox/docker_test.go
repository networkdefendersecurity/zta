//go:build !windows

package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDockerArgs(t *testing.T) {
	opts := DockerOptions{Image: "alpine:latest", Root: "/repo", Network: "none"}
	args := dockerArgs(opts, []string{"sh", "-c", "echo hi"}, nil, "/zta", "")
	joined := strings.Join(args, " ")

	for _, want := range []string{
		"run --rm -i",
		"--network none",
		"--security-opt no-new-privileges",
		"--cap-drop ALL",
		"-v /repo:/workspace",
		"-w /workspace",
		"-v /zta:/zta:ro",
		"-e ZTA_PROJECT_DIR=/workspace",
		"--entrypoint /zta alpine:latest run --root /workspace --",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("docker args missing %q\n  got: %s", want, joined)
		}
	}
	// agent command is appended verbatim at the end
	if args[len(args)-3] != "sh" || args[len(args)-1] != "echo hi" {
		t.Errorf("agent command not appended verbatim: %v", args[len(args)-3:])
	}
	// no TTY requested -> no -t
	if strings.Contains(joined, " -t ") {
		t.Errorf("unexpected -t without TTY: %s", joined)
	}
}

func TestDockerArgs_PolicyMasksTTY(t *testing.T) {
	opts := DockerOptions{Image: "img", Root: "/r", PolicyFile: "/host/zta.json", TTY: true, User: "1000:1000"}
	args := dockerArgs(opts, []string{"aider"}, []string{".env", "sub/secret.key"}, "/zta", "/tmp/empty")
	joined := strings.Join(args, " ")

	for _, want := range []string{
		"-t",
		"--user 1000:1000",
		"-v /host/zta.json:/zta-policy.json:ro",
		"-e ZTA_POLICY=/zta-policy.json",
		"-v /tmp/empty:/workspace/.env:ro",
		"-v /tmp/empty:/workspace/sub/secret.key:ro",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("docker args missing %q\n  got: %s", want, joined)
		}
	}
}

func TestSecretFilesIn(t *testing.T) {
	root := t.TempDir()
	write := func(rel string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(".env")
	write(".env.example") // template: not a secret
	write("config/app.key")
	write("certs/server.pem")
	write("src/main.go") // not a secret
	write(".git/config") // skipped dir

	got := map[string]bool{}
	for _, f := range secretFilesIn(root) {
		got[filepath.ToSlash(f)] = true
	}
	for _, want := range []string{".env", "config/app.key", "certs/server.pem"} {
		if !got[want] {
			t.Errorf("expected %q to be masked; got %v", want, got)
		}
	}
	for _, notWant := range []string{".env.example", "src/main.go", ".git/config"} {
		if got[notWant] {
			t.Errorf("did not expect %q to be masked", notWant)
		}
	}
}
