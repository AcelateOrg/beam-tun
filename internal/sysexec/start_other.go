//go:build !linux

package sysexec

import "os/exec"

func start(cmd *exec.Cmd) error {
	return cmd.Run()
}
