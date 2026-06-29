//go:build windows

package sandbox

import (
	"errors"
	"fmt"
	"os"
)

// The sandbox tier relies on Unix process semantics (a shim PATH of /bin/sh
// wrappers and syscall.Exec) and on Docker bind-mount conventions, so it is not
// available on Windows. The hook tier (zta init / zta guard) works everywhere.
var errWindowsSandbox = errors.New("the sandbox tier (zta run) is not supported on Windows; use the hook tier (zta init / zta guard)")

func Run(argv []string, opts Options) (int, error)             { return 2, errWindowsSandbox }
func RunDocker(argv []string, opts DockerOptions) (int, error) { return 2, errWindowsSandbox }

func Shim(name string, args []string) int {
	fmt.Fprintln(os.Stderr, "zta: __shim is not supported on Windows")
	return 2
}
