//go:build !windows

package netconfig

import "os/exec"

// hideCommandWindow is a no-op away from Windows, where there is no console
// window for a subprocess to raise.
func hideCommandWindow(*exec.Cmd) {}
