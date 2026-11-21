//go:build windows

package stack

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/windows"
)

var (
	kernel32              = windows.NewLazySystemDLL("kernel32.dll")
	procSetThreadPriority = kernel32.NewProc("SetThreadPriority")
)

const (
	threadPriorityNormal  = 0
	threadPriorityHighest = 2
)

// boostCurrentThread pins the read loop to its OS thread and raises that
// thread's priority: every packet of every flow passes through it, so it must
// not queue behind ordinary work (browser, game) under CPU load.
func boostCurrentThread() func() {
	runtime.LockOSThread()
	thread := windows.CurrentThread()
	ok, _, _ := procSetThreadPriority.Call(uintptr(thread), threadPriorityHighest)
	return func() {
		if ok != 0 {
			_, _, _ = procSetThreadPriority.Call(uintptr(thread), threadPriorityNormal)
		}
		runtime.UnlockOSThread()
	}
}

var (
	firewallOnce sync.Once
	firewallErr  error
)

// ensureFirewall allows inbound TCP for this executable once per process.
// The NAT listener receives connections on the tunnel interface, which
// Windows Defender Firewall filters like any other; without the rule SYNs are
// dropped silently and every TCP flow hangs. The rule name is derived from
// the executable path so dev and release builds do not clash.
func ensureFirewall() error {
	firewallOnce.Do(func() {
		exe, err := os.Executable()
		if err != nil {
			firewallErr = err
			return
		}
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		sum := sha256.Sum256([]byte(strings.ToLower(exe)))
		name := fmt.Sprintf("Beam TUN (%s %s)", filepath.Base(exe), hex.EncodeToString(sum[:4]))

		if netsh(fmt.Sprintf(`advfirewall firewall show rule name="%s"`, name)) == nil {
			return
		}
		firewallErr = netsh(fmt.Sprintf(
			`advfirewall firewall add rule name="%s" dir=in action=allow program="%s" protocol=TCP profile=any enable=yes`,
			name, exe,
		))
	})
	return firewallErr
}

// netsh runs netsh with an exact command line (netsh expects key="value"
// quoting that the default argument escaping cannot produce).
func netsh(args string) error {
	path := filepath.Join(os.Getenv("SystemRoot"), "System32", "netsh.exe")
	if _, err := os.Stat(path); err != nil {
		path = "netsh.exe"
	}
	cmd := exec.Command(path)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow: true,
		CmdLine:    `"` + path + `" ` + args,
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh %s: %w: %s", args, err, strings.TrimSpace(string(out)))
	}
	return nil
}
