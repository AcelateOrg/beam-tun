//go:build darwin

package netcfg

import (
	"fmt"
	"net/netip"
	"strconv"
)

// Configure applies cfg with ifconfig and route (Beam runs as root on macOS)
// plus best-effort extras:
//
//   - bypass routes for the proxy servers through the physical gateway,
//     recomputed on every Reapply;
//   - IPv6 cut-off: two reject /1 routes while the host has an IPv6 uplink.
//     Beam's own sockets are bound to the physical interface (IP_BOUND_IF),
//     which makes the kernel use that interface's scoped routes, so they
//     are not affected;
//   - DNS: the resolver of the primary network service is pointed at the
//     tunnel in the dynamic store (scutil) and restored on close; see
//     dns_darwin.go.
func Configure(cfg Config) (Network, error) {
	if cfg.Name == "" || !cfg.Address.IsValid() {
		return nil, fmt.Errorf("tun: incomplete network configuration")
	}

	address := cfg.Address.Addr()
	peer := address.Next()

	var setup, cleanup [][]string

	ifconfig := []string{"ifconfig", cfg.Name, "inet", address.String(), peer.String(), "netmask", maskOf(cfg.Address), "up"}
	if cfg.MTU > 0 {
		ifconfig = append(ifconfig, "mtu", strconv.Itoa(cfg.MTU))
	}
	setup = append(setup, ifconfig)
	cleanup = append(cleanup, []string{"ifconfig", cfg.Name, "down"})

	for _, prefix := range splitRoutes {
		setup = append(setup, []string{"route", "-n", "add", "-net", prefix, "-interface", cfg.Name})
		cleanup = append(cleanup, []string{"route", "-n", "delete", "-net", prefix, "-interface", cfg.Name})
	}

	if hasFamily(cfg.Bypass, true) {
		if _, err := defaultRoute4(cfg.Name); err != nil {
			return nil, err
		}
	}

	bypass := &bypassRoutes{tun: cfg.Name}
	bypass.addrs = append([]netip.Addr(nil), cfg.Bypass...)
	extras := []extra{bypass, &ipv6Guard{tun: cfg.Name}}
	if cfg.DNS.IsValid() {
		extras = append(extras, &dnsOverride{dns: cfg.DNS})
	}
	return applyCommandsWith(setup, cleanup, extras)
}

func maskOf(p netip.Prefix) string {
	bits := p.Bits()
	var m [4]byte
	for i := 0; i < 4; i++ {
		n := bits - i*8
		switch {
		case n >= 8:
			m[i] = 0xff
		case n > 0:
			m[i] = byte(0xff << (8 - n))
		}
	}
	return netip.AddrFrom4(m).String()
}

func hasFamily(addrs []netip.Addr, v4 bool) bool {
	for _, a := range addrs {
		if a.Unmap().Is4() == v4 {
			return true
		}
	}
	return false
}

func bypassRouteCommands(addr netip.Addr, tun string) (add, del []string) {
	addr = addr.Unmap()
	family := []string{}
	var r hostRoute
	if addr.Is4() {
		var err error
		if r, err = defaultRoute4(tun); err != nil {
			return nil, nil
		}
	} else {
		var ok bool
		if r, ok = defaultRoute6(tun); !ok {
			return nil, nil
		}
		family = []string{"-inet6"}
	}
	tail := append(append([]string{}, family...), "-host", addr.String())
	if r.gateway.IsValid() && !r.gateway.IsUnspecified() {
		tail = append(tail, r.gateway.String())
	} else {
		tail = append(tail, "-interface", r.iface)
	}
	add = append([]string{"route", "-n", "add"}, tail...)
	del = append([]string{"route", "-n", "delete"}, tail...)
	return add, del
}

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
		err := runSetupCommand([]string{"route", "-n", "add", "-inet6", "-net", prefix, "::1", "-reject"})
		if err != nil && firstErr == nil {
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
		_ = runCommand([]string{"route", "-n", "delete", "-inet6", "-net", prefix, "::1"})
	}
}

// RecoverStale undoes what a crashed run left behind: the DNS override (the
// dynamic store outlives the process) and the IPv6 reject routes (they are
// not bound to the tunnel interface, so its removal does not take them).
func RecoverStale() {
	restoreStaleDNS()
	removeIPv6Cut()
}
