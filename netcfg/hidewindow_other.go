//go:build !windows

package netcfg

import "os/exec"

func hideWindow(cmd *exec.Cmd) {}
