//go:build linux

package tun

import (
	"sync"

	"golang.org/x/sys/unix"
)

var markProbe = sync.OnceValue(func() bool {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return false
	}
	defer unix.Close(fd)
	return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, SocketMark) == nil
})

// SocketMarkUsable reports whether this process may set SO_MARK (it needs
// CAP_NET_ADMIN). Without it a socket option that fails would fail the dial,
// so callers only request the mark when it works.
func SocketMarkUsable() bool { return markProbe() }
