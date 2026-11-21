//go:build windows

package sysexec

import (
	"os/exec"
	"syscall"
)

// prepare keeps netsh and friends from flashing a console window.
func prepare(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
}
