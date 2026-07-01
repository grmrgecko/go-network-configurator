package netconfig

import (
	"os/exec"
	"syscall"
)

// hideCommandWindow keeps a subprocess from flashing a console window on a
// desktop session. Every command this package runs on Windows (netsh, ipconfig)
// is a console program, and without this each one briefly steals focus.
func hideCommandWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
}
