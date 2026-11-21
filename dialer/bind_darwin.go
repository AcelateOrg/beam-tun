//go:build darwin

package dialer

import (
	"strings"

	"golang.org/x/sys/unix"
)

func bindToInterface(fd uintptr, network string, iface Interface) error {
	if strings.HasSuffix(network, "6") {
		return unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, iface.Index)
	}
	if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, iface.Index); err != nil {
		// Dual-stack socket resolved to IPv6.
		return unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, iface.Index)
	}
	return nil
}
