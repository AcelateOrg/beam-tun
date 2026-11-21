//go:build (linux && !android) || darwin

package netcfg

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
)

// bypassRoutes keeps one host route per proxy server through the physical
// default gateway. The gateway is looked up again on every apply, so after
// a Wi-Fi <-> Ethernet switch the routes follow the new uplink instead of
// pointing at a gateway that no longer exists.
type bypassRoutes struct {
	mu        sync.Mutex
	tun       string
	addrs     []netip.Addr
	installed map[string][]string // add command (joined) -> delete command
}

func (b *bypassRoutes) apply() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.applyLocked()
}

func (b *bypassRoutes) applyLocked() error {
	want := make(map[string][][]string, len(b.addrs))
	var missing []string
	for _, addr := range b.addrs {
		if !addr.IsValid() || addr.IsLoopback() || addr.IsUnspecified() {
			continue
		}
		add, del := bypassRouteCommands(addr, b.tun)
		if add == nil {
			if addr.Unmap().Is4() {
				missing = append(missing, addr.String())
			}
			continue
		}
		want[strings.Join(add, " ")] = [][]string{add, del}
	}

	// Routes through a gateway that is no longer current go first.
	for key, del := range b.installed {
		if _, keep := want[key]; !keep {
			_ = runCommand(del)
			delete(b.installed, key)
		}
	}
	if b.installed == nil {
		b.installed = make(map[string][]string)
	}

	var failures []string
	for key, pair := range want {
		if err := runSetupCommand(pair[0]); err != nil {
			failures = append(failures, err.Error())
			continue
		}
		b.installed[key] = pair[1]
	}
	if len(missing) > 0 {
		failures = append(failures, "no default route for "+strings.Join(missing, ", "))
	}
	if len(failures) > 0 {
		return fmt.Errorf("tun: bypass routes: %s", strings.Join(failures, "; "))
	}
	return nil
}

func (b *bypassRoutes) release() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for key, del := range b.installed {
		_ = runCommand(del)
		delete(b.installed, key)
	}
}

func (b *bypassRoutes) update(addrs []netip.Addr) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if slices.Equal(addrs, b.addrs) {
		return nil
	}
	b.addrs = append([]netip.Addr(nil), addrs...)
	return b.applyLocked()
}

// UpdateBypass moves the bypass routes to the servers of a new config
// without touching the rest of the tunnel setup (node switch).
func (n *commandNetwork) UpdateBypass(addrs []netip.Addr) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return fmt.Errorf("tun: network closed")
	}
	for _, e := range n.extras {
		if b, ok := e.(*bypassRoutes); ok {
			return b.update(addrs)
		}
	}
	return fmt.Errorf("tun: no bypass routes to update")
}
