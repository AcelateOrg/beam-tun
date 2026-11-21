//go:build darwin

package stack

import (
	"fmt"
	"net/netip"

	"golang.org/x/sys/unix"
)

// pinToInterface scopes the socket to the physical interface so its route
// lookup ignores the utun split routes.
func pinToInterface(fd int, source netip.Addr) error {
	iface, err := interfaceOf(source)
	if err != nil {
		return err
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_BOUND_IF, iface.Index); err != nil {
		return fmt.Errorf("bind icmp to %s: %w", iface.Name, err)
	}
	return nil
}
