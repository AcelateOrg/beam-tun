//go:build windows

package dialer

import (
	"net"
	"net/netip"

	"beam-tun/internal/winip"
)

// resolveInterface reads the interface straight from the IP Helper tables;
// net.InterfaceByName + Addrs walk GetAdaptersAddresses twice (slow).
func resolveInterface(name string) (Interface, error) {
	luid, err := winip.LuidByName(name)
	if err != nil {
		return resolveInterfaceGeneric(name)
	}
	index, err := winip.IndexOf(luid)
	if err != nil {
		return resolveInterfaceGeneric(name)
	}
	iface := Interface{Name: name, Index: index}
	if addrs, err := winip.Addresses(); err == nil {
		for _, a := range addrs {
			if a.Luid == luid {
				iface.pickAddress(a.Prefix.Addr())
			}
		}
	}
	return iface, nil
}

func resolveInterfaceGeneric(name string) (Interface, error) {
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
