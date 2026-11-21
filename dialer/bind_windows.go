//go:build windows

package dialer

import (
	"encoding/binary"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// IP_UNICAST_IF / IPV6_UNICAST_IF (ws2ipdef.h). The IPv4 option takes the
// interface index in network byte order, the IPv6 one in host order.
const (
	ipUnicastIf   = 31
	ipv6UnicastIf = 31
)

func bindToInterface(fd uintptr, network string, iface Interface) error {
	handle := windows.Handle(fd)
	index := uint32(iface.Index)

	v4 := !strings.HasSuffix(network, "6")
	v6 := !strings.HasSuffix(network, "4")

	if v4 {
		var be [4]byte
		binary.BigEndian.PutUint32(be[:], index)
		value := *(*uint32)(unsafe.Pointer(&be[0]))
		if err := windows.SetsockoptInt(handle, windows.IPPROTO_IP, ipUnicastIf, int(value)); err != nil {
			// A pure IPv6 socket rejects the IPv4 option; that is fine for
			// dual-stack networks ("tcp", "udp") resolved to IPv6.
			if !v6 {
				return err
			}
		}
	}
	if v6 {
		if err := windows.SetsockoptInt(handle, windows.IPPROTO_IPV6, ipv6UnicastIf, int(index)); err != nil {
			if !v4 {
				return err
			}
		}
	}
	return nil
}
