// Package netcfg configures the host network around a tunnel adapter:
// address, MTU, DNS, the split default routes and bypass routes for the proxy
// servers. It also finds the physical interface, detects address conflicts
// with other tunnels and watches for host network changes.
//
// Windows uses the IP Helper API directly; Linux and macOS use the system
// tools (ip, ifconfig, route).
package netcfg

import (
	"errors"
	"net/netip"
)

// Config describes the network setup of one tunnel adapter.
type Config struct {
	// Name is the adapter name as reported by the OS.
	Name string
	// Address is the adapter address with its prefix (e.g. 172.19.0.1/30).
	Address netip.Prefix
	// DNS is the resolver announced on the adapter; optional.
	DNS netip.Addr
	MTU int
	// Bypass lists hosts (the proxy servers) routed around the tunnel
	// through the physical default gateway.
	Bypass []netip.Addr
}

// Network is an applied configuration.
type Network interface {
	// Close restores the host network.
	Close() error
	// Reapply re-runs the setup so routes and DNS survive a network change
	// such as switching between Wi-Fi and Ethernet.
	Reapply() error
}

// ErrUnsupported is returned on platforms without a configurator.
var ErrUnsupported = errors.New("tun: network configuration is not supported on this platform")

// splitRoutes cover the whole IPv4 space with two /1 routes: more specific
// than the host default route, so the tunnel wins without deleting it.
var splitRoutes = []string{"0.0.0.0/1", "128.0.0.0/1"}
