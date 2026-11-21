//go:build !windows

package stack

import "runtime"

// boostCurrentThread pins the read loop to its OS thread. Raising the thread
// priority needs privileges on Unix and is left to the platform integration.
func boostCurrentThread() func() {
	runtime.LockOSThread()
	return runtime.UnlockOSThread
}

// ensureFirewall is a no-op: Linux/macOS do not filter the tunnel listener by
// default.
func ensureFirewall() error { return nil }
