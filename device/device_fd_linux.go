//go:build linux

package device

import (
	"fmt"

	wgtun "golang.zx2c4.com/wireguard/tun"

	"beam-tun"
)

// OpenFD wraps a TUN interface the platform already created and configured,
// for example the descriptor Android's VpnService.Builder.establish() hands
// out. The caller keeps no other reference to fd: closing the device closes it.
func OpenFD(fd int, mtu int) (tun.Device, error) {
	if fd < 0 {
		return nil, fmt.Errorf("tun: invalid file descriptor %d", fd)
	}
	mtu = tun.ClampMTU(mtu)
	dev, name, err := wgtun.CreateUnmonitoredTUNFromFD(fd)
	if err != nil {
		return nil, fmt.Errorf("tun: adopt descriptor %d: %w", fd, err)
	}
	return wrap(dev, name, mtu), nil
}
