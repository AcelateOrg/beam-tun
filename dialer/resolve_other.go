//go:build !windows

package dialer

import (
	"net"
	"net/netip"
)

func resolveInterface(name string) (Interface, error) {
	resolved, err := net.InterfaceByName(name)
	if err != nil {
		return Interface{}, err
	}
	iface := Interface{Name: resolved.Name, Index: resolved.Index}
	if addrs, err := resolved.Addrs(); err == nil {
		for _, a := range addrs {
			if prefix, err := netip.ParsePrefix(a.String()); err == nil {
				iface.pickAddress(prefix.Addr())
			}
		}
	}
	return iface, nil
}
