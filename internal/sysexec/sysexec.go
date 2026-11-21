// Package sysexec runs the system tools the network setup depends on (ip,
// resolvectl, nft, route, scutil, pfctl, netsh) with a timeout and, on Linux,
// with the network capabilities of the calling process passed on.
//
// On Linux Beam does not run as root: the binary carries cap_net_admin and
// cap_net_raw as file capabilities. Those are not inherited across exec, so a
// plain `ip route add` started by Beam fails with "Operation not permitted".
// The fix is the ambient capability set, which survives exec; see
// caps_linux.go.
package sysexec

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Timeout bounds one command. A hung tool (netsh on a broken adapter, nft on
// a wedged netlink socket) must never hold a disconnect forever.
const Timeout = 15 * time.Second

// Run executes args and returns the combined output on failure as part of
// the error. input, when non-empty, is fed to stdin (nft -f -, scutil,
// pfctl -f -).
func Run(args []string, input string) error {
	_, err := run(args, input, true)
	return err
}

// Output executes args and returns stdout.
func Output(args []string) (string, error) {
	return run(args, "", false)
}

// OutputInput executes args with input on stdin and returns stdout.
func OutputInput(args []string, input string) (string, error) {
	return run(args, input, false)
}

// Combined executes args and returns stdout and stderr together, also on
// success (pfctl -E prints its token to stderr).
func Combined(args []string, input string) (string, error) {
	return run(args, input, true)
}

func run(args []string, input string, combined bool) (string, error) {
	if len(args) == 0 {
		return "", nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	prepare(cmd)
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	if combined {
		cmd.Stderr = &stdout
	} else {
		cmd.Stderr = &stderr
	}

	err := start(cmd)
	if ctx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("%s: timed out after %s", strings.Join(args, " "), Timeout)
	}
	if err != nil {
		detail := strings.TrimSpace(stdout.String())
		if !combined {
			detail = strings.TrimSpace(stderr.String())
		}
		if detail != "" {
			return stdout.String(), fmt.Errorf("%s: %w: %s", strings.Join(args, " "), err, detail)
		}
		return stdout.String(), fmt.Errorf("%s: %w", strings.Join(args, " "), err)
	}
	return stdout.String(), nil
}

// Available reports whether the tool is installed.
func Available(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
