package netcfg

import (
	"fmt"
	"strings"
	"sync"

	"beam-tun/internal/sysexec"
)

// commandNetwork is a Network configured by external commands (ip, ifconfig,
// route): setup is replayed on Reapply and cleanup runs in reverse on Close.
type commandNetwork struct {
	mu      sync.Mutex
	setup   [][]string
	cleanup [][]string
	verify  []func() error
	// extras are best-effort steps that must not fail the tunnel (DNS on
	// the link, the IPv6 cut-off): applied after setup and on every
	// Reapply, released before the cleanup commands.
	extras []extra
	closed bool
}

// extra is one optional piece of network setup with its own state.
type extra interface {
	apply() error
	release()
}

// Warnings collects the errors of optional steps; the caller may log them.
var Warnings = func(error) {}

func (n *commandNetwork) Reapply() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return nil
	}

	var failures []string
	for _, args := range n.setup {
		if err := runSetupCommand(args); err != nil {
			failures = append(failures, err.Error())
		}
	}
	for _, check := range n.verify {
		if err := check(); err != nil {
			failures = append(failures, err.Error())
		}
	}
	for _, e := range n.extras {
		if err := e.apply(); err != nil {
			Warnings(err)
		}
	}
	if len(failures) == 0 {
		return nil
	}
	return fmt.Errorf("tun: reapply network: %s", strings.Join(failures, "; "))
}

func (n *commandNetwork) Close() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return nil
	}
	n.closed = true

	for i := len(n.extras) - 1; i >= 0; i-- {
		n.extras[i].release()
	}

	var failures []string
	for i := len(n.cleanup) - 1; i >= 0; i-- {
		if err := runCommand(n.cleanup[i]); err != nil && !isAlreadyRemoved(err) {
			failures = append(failures, err.Error())
		}
	}
	if len(failures) == 0 {
		return nil
	}
	return fmt.Errorf("tun: restore network: %s", strings.Join(failures, "; "))
}

// isAlreadyApplied reports whether a setup command failed only because the
// route or address it installs is already in place. Reapply intentionally
// re-runs the full setup, so on an unchanged network every "add route" call
// hits this - it means the tunnel is configured correctly, not broken.
// netsh localizes its output, hence the message list.
func isAlreadyApplied(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	for _, marker := range alreadyAppliedMarkers {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}

// isAlreadyRemoved reports whether a cleanup command failed only because
// what it removes is already gone - typically because the adapter itself
// disappeared. Restoring the host network is then a no-op, not a failure.
func isAlreadyRemoved(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	for _, marker := range alreadyRemovedMarkers {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}

// netsh reports a missing interface as a syntax error (Windows error 0x7B),
// hence the odd looking markers. The list is localized too.
var alreadyRemovedMarkers = []string{
	"element not found",
	"cannot find",
	"not found",
	"no such",
	"syntax is incorrect",
	"не удается найти",
	"не найден",
	"указано неверно",
}

var alreadyAppliedMarkers = []string{
	"already exists",
	"object already exists",
	"file exists",
	"уже существует",
}

// commandTimeout — верхняя граница на одну команду настройки сети. Зависший
// netsh (а он зависает на сломанных адаптерах) раньше вечно держал Stop:
// отсюда бесконечный «disconnecting» в UI. Теперь команда убивается по
// таймауту, и останов завершается.
//
// На Linux sysexec передаёт дочернему процессу CAP_NET_ADMIN/CAP_NET_RAW
// через ambient-набор: без этого ip/resolvectl, запущенные из Beam с
// file capabilities, получали бы "Operation not permitted".
const commandTimeout = sysexec.Timeout

func runCommand(args []string) error {
	return sysexec.Run(args, "")
}

func commandOutput(args []string) (string, error) {
	return sysexec.Output(args)
}

// runSetupCommand runs one setup step. A route left behind by a previous run
// (for example after a crash, where cleanup never ran) makes netsh fail even
// though the desired state is already in place, and a delete of something that
// is not there is a no-op by definition. Both are success.
//
// "Already exists" is deliberately NOT treated as proof that the desired state
// is in place: netsh matches a prefix on any interface, so the message also
// appears when the existing route points somewhere else entirely. Whatever
// depends on a route being correct has to be verified explicitly.
func runSetupCommand(args []string) error {
	if err := runCommand(args); err != nil && !isAlreadyApplied(err) && !isAlreadyRemoved(err) {
		return err
	}
	return nil
}

// applyCommandsWith is applyCommands plus best-effort extras.
func applyCommandsWith(setup, cleanup [][]string, extras []extra) (Network, error) {
	network, err := applyCommands(setup, cleanup)
	if err != nil {
		return nil, err
	}
	cn := network.(*commandNetwork)
	cn.extras = extras
	for _, e := range extras {
		if err := e.apply(); err != nil {
			Warnings(err)
		}
	}
	return cn, nil
}

func applyCommands(setup [][]string, cleanup [][]string, verify ...func() error) (Network, error) {
	for i, args := range setup {
		if err := runSetupCommand(args); err != nil {
			if i > 0 {
				_ = (&commandNetwork{cleanup: cleanup[:i]}).Close()
			}
			return nil, err
		}
	}

	// Fail loudly instead of handing back a tunnel that cannot carry traffic.
	for _, check := range verify {
		if err := check(); err != nil {
			_ = (&commandNetwork{cleanup: cleanup}).Close()
			return nil, err
		}
	}

	return &commandNetwork{setup: setup, cleanup: cleanup, verify: verify}, nil
}
