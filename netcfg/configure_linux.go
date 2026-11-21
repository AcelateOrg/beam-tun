//go:build linux && !android

package netcfg

import (
	"fmt"
	"net/netip"
	"strconv"

	"beam-tun/internal/sysexec"
)

// Configure applies cfg with iproute2 (run with Beam's capabilities, see
// sysexec) plus best-effort extras:
//
//   - bypass routes for the proxy servers through the physical gateway,
//     recomputed on every Reapply (the gateway changes with the network);
//   - IPv6 cut-off: the tunnel is IPv4-only, so while it is up IPv6 traffic
//     would leave around it. Two unreachable /1 routes make every global
//     IPv6 destination fail fast (apps fall back to IPv4 at once); on-link
//     and link-local stay reachable, and Beam's own sockets are bound to the
//     physical interface, which the oif-restricted lookup keeps on its route;
//   - DNS through systemd-resolved: the tunnel resolver becomes the default
//     route for every domain (~.), and resolved forgets it by itself when the
//     link disappears.
func Configure(cfg Config) (Network, error) {
	if cfg.Name == "" || !cfg.Address.IsValid() {
		return nil, fmt.Errorf("tun: incomplete network configuration")
	}

	var setup, cleanup [][]string

	setup = append(setup, []string{"ip", "address", "replace", cfg.Address.String(), "dev", cfg.Name})
	cleanup = append(cleanup, []string{"ip", "address", "del", cfg.Address.String(), "dev", cfg.Name})

	link := []string{"ip", "link", "set", "dev", cfg.Name, "up"}
	if cfg.MTU > 0 {
		link = append(link, "mtu", strconv.Itoa(cfg.MTU))
	}
	setup = append(setup, link)
	cleanup = append(cleanup, []string{"ip", "link", "set", "dev", cfg.Name, "down"})

	for _, prefix := range splitRoutes {
		setup = append(setup, []string{"ip", "-4", "route", "replace", prefix, "dev", cfg.Name})
		cleanup = append(cleanup, []string{"ip", "-4", "route", "del", prefix, "dev", cfg.Name})
	}

	// Without a physical default route the bypass routes cannot be built
	// and the core's own connection to the server would loop through the
	// tunnel: refuse instead of handing back a dead tunnel.
	if hasFamily(cfg.Bypass, true) {
		if _, err := defaultRoute4(cfg.Name); err != nil {
			return nil, err
		}
	}

	bypass := &bypassRoutes{tun: cfg.Name}
	bypass.addrs = append([]netip.Addr(nil), cfg.Bypass...)
	extras := []extra{bypass, &ipv6Guard{tun: cfg.Name}}
	if cfg.DNS.IsValid() {
		extras = append(extras, &linkDNS{name: cfg.Name, dns: cfg.DNS})
	}
	return applyCommandsWith(setup, cleanup, extras)
}

func hasFamily(addrs []netip.Addr, v4 bool) bool {
	for _, a := range addrs {
		if a.Unmap().Is4() == v4 {
			return true
		}
	}
	return false
}

// bypassRouteCommands returns the add and delete commands routing addr
// around the tunnel, or nil when the host has no matching default route.
func bypassRouteCommands(addr netip.Addr, tun string) (add, del []string) {
	addr = addr.Unmap()
	if addr.Is4() {
		route, err := defaultRoute4(tun)
		if err != nil {
			return nil, nil
		}
		return routeVia("-4", addr.String()+"/32", route)
	}
	route, ok := defaultRoute6(tun)
	if !ok {
		return nil, nil
	}
	return routeVia("-6", addr.String()+"/128", route)
}

func routeVia(family, host string, route hostRoute) (add, del []string) {
	tail := []string{host}
	if route.gateway.IsValid() && !route.gateway.IsUnspecified() {
		tail = append(tail, "via", route.gateway.String())
	}
	tail = append(tail, "dev", route.iface)
	add = append([]string{"ip", family, "route", "replace"}, tail...)
	del = append([]string{"ip", family, "route", "del"}, tail...)
	return add, del
}

// ipv6Guard installs the unreachable /1 routes while the host has an IPv6
// uplink. Without one there is nothing to leak and nothing is touched.
type ipv6Guard struct {
	tun       string
	installed bool
}

var ipv6CutRoutes = []string{"::/1", "8000::/1"}

func (g *ipv6Guard) apply() error {
	if _, ok := defaultRoute6(g.tun); !ok && !g.installed {
		return nil
	}
	var firstErr error
	for _, prefix := range ipv6CutRoutes {
		if err := runCommand([]string{"ip", "-6", "route", "replace", "unreachable", prefix}); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("tun: ipv6 cut-off: %w", err)
		}
	}
	g.installed = firstErr == nil
	return firstErr
}

func (g *ipv6Guard) release() {
	if !g.installed {
		return
	}
	removeIPv6Cut()
	g.installed = false
}

func removeIPv6Cut() {
	for _, prefix := range ipv6CutRoutes {
		_ = runCommand([]string{"ip", "-6", "route", "del", "unreachable", prefix})
	}
}

// RecoverStale undoes what a crashed run left behind. The tunnel's own
// routes and its resolved link vanish with the interface; the unreachable
// IPv6 routes are not bound to it and would keep IPv6 dead until reboot.
func RecoverStale() {
	removeIPv6Cut()
}

// linkDNS points systemd-resolved at the tunnel resolver for all domains.
// Hosts without resolved keep their resolver (reported once as a warning).
type linkDNS struct {
	name   string
	dns    netip.Addr
	warned bool
	set    bool
}

func (d *linkDNS) apply() error {
	if !sysexec.Available("resolvectl") {
		if d.warned {
			return nil
		}
		d.warned = true
		return fmt.Errorf("tun: resolvectl not found, system DNS left as is")
	}
	if err := runCommand([]string{"resolvectl", "dns", d.name, d.dns.String()}); err != nil {
		return fmt.Errorf("tun: set dns: %w", err)
	}
	d.set = true
	if err := runCommand([]string{"resolvectl", "domain", d.name, "~."}); err != nil {
		return fmt.Errorf("tun: set dns domain: %w", err)
	}
	// Older resolved has no default-route verb; "~." alone does the job.
	_ = runCommand([]string{"resolvectl", "default-route", d.name, "yes"})
	_ = runCommand([]string{"resolvectl", "flush-caches"})
	return nil
}

func (d *linkDNS) release() {
	if !d.set {
		return
	}
	_ = runCommand([]string{"resolvectl", "revert", d.name})
	_ = runCommand([]string{"resolvectl", "flush-caches"})
	d.set = false
}
