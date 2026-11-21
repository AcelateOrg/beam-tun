//go:build windows

package netcfg

import (
	"fmt"
	"net/netip"

	"beam-tun/internal/winip"
)

// checkAddressFree reads the unicast address table directly (one kernel
// table instead of GetAdaptersAddresses per interface). Falls back to the
// portable scan if the table cannot be read.
func checkAddressFree(addr netip.Addr, own string) error {
	entries, err := winip.Addresses()
	if err != nil {
		return checkAddressFreeGeneric(addr, own)
	}
	ownLuid, _ := winip.LuidByName(own)
	for _, entry := range entries {
		if entry.Prefix.Addr().Unmap() != addr || entry.Luid == ownLuid {
			continue
		}
		if !winip.Connected(entry.Luid) {
			continue
		}
		name, _ := winip.NameOf(entry.Luid)
		return fmt.Errorf("%w: %s on %q", ErrAddressInUse, addr, name)
	}
	return nil
}
