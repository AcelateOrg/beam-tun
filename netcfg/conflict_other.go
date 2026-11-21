//go:build !windows

package netcfg

import "net/netip"

func checkAddressFree(addr netip.Addr, own string) error {
	return checkAddressFreeGeneric(addr, own)
}
