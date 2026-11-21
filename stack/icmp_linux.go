//go:build linux && !android

package stack

import (
	"fmt"
	"net/netip"

	"golang.org/x/sys/unix"

	"beam-tun"
)

// pinToInterface binds the socket to the physical device and marks it so
// the kill switch lets it through.
func pinToInterface(fd int, source netip.Addr) error {
	iface, err := interfaceOf(source)
	if err != nil {
		return err
	}
	if err := unix.BindToDevice(fd, iface.Name); err != nil {
		return fmt.Errorf("bind icmp to %s: %w", iface.Name, err)
	}
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, tun.SocketMark)
	return nil
}
