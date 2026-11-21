// Package firewall is the Beam kill switch and leak protection.
//
// Two independent filter sets live in one firewall session:
//
//   - Lockdown (the kill switch itself): while the VPN is down after an
//     unexpected drop, nothing but Beam, loopback, the local network and DHCP
//     may talk. Beam stays allowed so it can reconnect; AllowDNS opens plain
//     DNS for the duration of a reconnect attempt, because resolving the
//     server name goes through the system resolver, not through Beam.
//   - Protect (leak protection while the tunnel is up): DNS outside the
//     tunnel and all IPv6 (the tunnel is IPv4-only) are blocked for every
//     process except Beam.
//
// On Windows the sets are WFP filters of a dynamic session: Windows removes
// them by itself when the process exits or crashes, so a dead Beam can never
// leave the machine offline. Other platforms are not supported yet.
package firewall

import "errors"

// ErrUnsupported is returned where the kill switch is not implemented.
var ErrUnsupported = errors.New("firewall: kill switch is not supported on this platform")

// Default returns the process-wide firewall. There is one per process: the
// filters of both sets share a single session.
func Default() *Firewall { return defaultFirewall }
