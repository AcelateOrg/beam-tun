//go:build darwin

package netcfg

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/net/route"
)

// hostRoute is a default route of the host: the gateway and the interface
// that carries it.
type hostRoute struct {
	gateway netip.Addr
	iface   string
}

// DefaultInterface returns the interface holding the IPv4 default route,
// the tunnel excluded. Read from the routing table through a route socket:
// no process spawn, and the tunnel's /1 split routes are never mistaken for
// a default route (`route get default` would answer with the tunnel).
func DefaultInterface(exclude string) (string, error) {
	r, ok := defaultRoute(syscall.AF_INET, exclude)
	if !ok {
		return "", fmt.Errorf("tun: no default route")
	}
	return r.iface, nil
}

func defaultRoute4(exclude string) (hostRoute, error) {
	r, ok := defaultRoute(syscall.AF_INET, exclude)
	if !ok {
		return hostRoute{}, fmt.Errorf("tun: no default route to bypass through")
	}
	return r, nil
}

func defaultRoute6(exclude string) (hostRoute, bool) {
	return defaultRoute(syscall.AF_INET6, exclude)
}

// defaultRoute picks the primary (unscoped) default route of the family;
// an interface-scoped one (RTF_IFSCOPE, one per active service) is the
// fallback when no primary exists outside the tunnel.
func defaultRoute(family int, exclude string) (hostRoute, bool) {
	rib, err := route.FetchRIB(family, route.RIBTypeRoute, 0)
	if err != nil {
		return hostRoute{}, false
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return hostRoute{}, false
	}

	var scoped hostRoute
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok || rm.Flags&syscall.RTF_UP == 0 || rm.Flags&syscall.RTF_REJECT != 0 {
			continue
		}
		if len(rm.Addrs) <= syscall.RTAX_GATEWAY || !isZeroAddr(rm.Addrs[syscall.RTAX_DST]) {
			continue
		}
		if len(rm.Addrs) > syscall.RTAX_NETMASK && !isZeroAddr(rm.Addrs[syscall.RTAX_NETMASK]) {
			continue
		}
		ifi, err := net.InterfaceByIndex(rm.Index)
		if err != nil || ifi.Name == exclude || ifi.Name == "lo0" {
			continue
		}
		r := hostRoute{gateway: gatewayAddr(rm.Addrs[syscall.RTAX_GATEWAY], ifi.Name), iface: ifi.Name}
		if rm.Flags&syscall.RTF_IFSCOPE != 0 {
			if scoped.iface == "" {
				scoped = r
			}
			continue
		}
		return r, true
	}
	return scoped, scoped.iface != ""
}

// isZeroAddr treats a missing address (a zero-length netmask sockaddr) as
// the all-zero one, which is how the kernel reports a /0.
func isZeroAddr(a route.Addr) bool {
	switch v := a.(type) {
	case nil:
		return true
	case *route.Inet4Addr:
		return v.IP == [4]byte{}
	case *route.Inet6Addr:
		return v.IP == [16]byte{}
	}
	return false
}

func gatewayAddr(a route.Addr, iface string) netip.Addr {
	switch v := a.(type) {
	case *route.Inet4Addr:
		return netip.AddrFrom4(v.IP)
	case *route.Inet6Addr:
		addr := netip.AddrFrom16(v.IP)
		if addr.IsLinkLocalUnicast() {
			addr = addr.WithZone(iface)
		}
		return addr
	}
	// A link-layer gateway: the route points straight at the interface.
	return netip.Addr{}
}
