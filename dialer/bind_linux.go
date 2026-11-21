//go:build linux

package dialer

import (
	"golang.org/x/sys/unix"

	tun "beam-tun"
)

func bindToInterface(fd uintptr, _ string, iface Interface) error {
	// The mark lets the socket through the kill switch; setting it needs
	// CAP_NET_ADMIN, which Beam has whenever it can run the tunnel at all.
	_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, tun.SocketMark)
	return unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface.Name)
}
