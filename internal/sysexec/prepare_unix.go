//go:build !windows && !linux

package sysexec

import "os/exec"

func prepare(*exec.Cmd) {}
