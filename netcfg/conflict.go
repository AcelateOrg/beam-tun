package netcfg

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// ErrAddressInUse is returned by CheckAddressFree when another live interface
// already carries the tunnel address.
var ErrAddressInUse = errors.New("tun: tunnel address is already assigned to another active interface (another Beam or VPN client is connected)")

// CheckAddressFree fails with ErrAddressInUse when an interface other than
// own is up and holds addr. Two tunnels with the same address both claim the
// default route: packets and NAT replies land on the wrong adapter, latency
// multiplies and ICMP dies, so starting a second one is refused.
func CheckAddressFree(addr netip.Addr, own string) error {
	return checkAddressFree(addr.Unmap(), own)
}

// checkAddressFreeGeneric is the portable implementation on top of the
// standard library.
func checkAddressFreeGeneric(addr netip.Addr, own string) error {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || strings.EqualFold(iface.Name, own) {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			prefix, err := netip.ParsePrefix(a.String())
			if err != nil {
				continue
			}
			if prefix.Addr().Unmap() == addr {
				return fmt.Errorf("%w: %s on %q", ErrAddressInUse, addr, iface.Name)
			}
		}
	}
	return nil
}
