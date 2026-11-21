//go:build linux

package sysexec

import (
	"os"
	"os/exec"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

// Capabilities handed to child processes: configuring links, routes, DNS and
// nftables needs CAP_NET_ADMIN, raw ICMP needs CAP_NET_RAW.
var passedCaps = []uintptr{unix.CAP_NET_ADMIN, unix.CAP_NET_RAW}

func prepare(*exec.Cmd) {}

// start runs cmd with Beam's network capabilities in the child's ambient set.
//
// A capability can be raised to ambient only if it is both permitted and
// inheritable. File capabilities make it permitted but leave the process
// inheritable set empty, so it is added here. Capabilities are per thread on
// Linux, and the child is forked from the calling thread: the goroutine is
// locked to a fresh thread, its inheritable set extended, the command run
// from it, and the thread discarded afterwards (the goroutine exits without
// unlocking), so no other goroutine ever runs with the modified set.
func start(cmd *exec.Cmd) error {
	if os.Geteuid() == 0 {
		return cmd.Run()
	}

	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		// No UnlockOSThread: the thread dies with this goroutine.
		if caps := raiseInheritable(); len(caps) > 0 {
			if cmd.SysProcAttr == nil {
				cmd.SysProcAttr = &syscall.SysProcAttr{}
			}
			cmd.SysProcAttr.AmbientCaps = caps
		}
		done <- cmd.Run()
	}()
	return <-done
}

// raiseInheritable adds the permitted network capabilities of the current
// thread to its inheritable set and returns them. Empty when the process has
// none (the child then runs unprivileged and reports its own error).
func raiseInheritable() []uintptr {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return nil
	}
	var caps []uintptr
	for _, c := range passedCaps {
		word, bit := c/32, uint32(1)<<(c%32)
		if data[word].Permitted&bit == 0 {
			continue
		}
		data[word].Inheritable |= bit
		caps = append(caps, c)
	}
	if len(caps) == 0 {
		return nil
	}
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return nil
	}
	return caps
}
