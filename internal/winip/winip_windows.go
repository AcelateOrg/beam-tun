//go:build windows

// Package winip is a handful of direct IP Helper API lookups.
//
// The standard library resolves interfaces on Windows through
// GetAdaptersAddresses, which walks every adapter with all its addresses,
// gateways and DNS servers: tens to hundreds of milliseconds per call on a
// machine with Hyper-V/VPN/Bluetooth adapters, and net.Interface.Addrs calls
// it again for every interface. The connect path did that a dozen times.
// These helpers read only the kernel tables they need - microseconds.
package winip

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modIphlpapi = windows.NewLazySystemDLL("iphlpapi.dll")

	procConvertInterfaceAliasToLuid = modIphlpapi.NewProc("ConvertInterfaceAliasToLuid")
	procConvertInterfaceLuidToAlias = modIphlpapi.NewProc("ConvertInterfaceLuidToAlias")
	procConvertInterfaceLuidToIndex = modIphlpapi.NewProc("ConvertInterfaceLuidToIndex")
	procConvertInterfaceIndexToLuid = modIphlpapi.NewProc("ConvertInterfaceIndexToLuid")
	procGetUnicastIpAddressTable    = modIphlpapi.NewProc("GetUnicastIpAddressTable")
	procGetIpInterfaceEntry         = modIphlpapi.NewProc("GetIpInterfaceEntry")
	procFreeMibTable                = modIphlpapi.NewProc("FreeMibTable")
)

// ndisIfMaxStringSize is NDIS_IF_MAX_STRING_SIZE (alias length in WCHARs).
const ndisIfMaxStringSize = 256

func errnoOf(r1 uintptr) error {
	if r1 == 0 {
		return nil
	}
	return windows.Errno(r1)
}

// LuidByName returns the LUID of the interface with the given alias (the
// name net.Interface reports on Windows).
func LuidByName(name string) (uint64, error) {
	alias, err := windows.UTF16PtrFromString(strings.TrimSpace(name))
	if err != nil {
		return 0, err
	}
	var luid uint64
	r1, _, _ := procConvertInterfaceAliasToLuid.Call(uintptr(unsafe.Pointer(alias)), uintptr(unsafe.Pointer(&luid)))
	return luid, errnoOf(r1)
}

// NameOf returns the alias of the interface.
func NameOf(luid uint64) (string, error) {
	var buf [ndisIfMaxStringSize + 1]uint16
	r1, _, _ := procConvertInterfaceLuidToAlias.Call(
		uintptr(unsafe.Pointer(&luid)), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if err := errnoOf(r1); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:]), nil
}

// IndexOf returns the interface index.
func IndexOf(luid uint64) (int, error) {
	var index uint32
	r1, _, _ := procConvertInterfaceLuidToIndex.Call(uintptr(unsafe.Pointer(&luid)), uintptr(unsafe.Pointer(&index)))
	return int(index), errnoOf(r1)
}

// LuidOf returns the LUID of the interface with the given index.
func LuidOf(index int) (uint64, error) {
	var luid uint64
	r1, _, _ := procConvertInterfaceIndexToLuid.Call(uintptr(uint32(index)), uintptr(unsafe.Pointer(&luid)))
	return luid, errnoOf(r1)
}

// IndexByName resolves an interface alias to its index.
func IndexByName(name string) (int, error) {
	luid, err := LuidByName(name)
	if err != nil {
		return 0, err
	}
	return IndexOf(luid)
}

// Address is one unicast address of an interface.
type Address struct {
	Luid   uint64
	Prefix netip.Prefix
}

type unicastTable struct {
	NumEntries uint32
	Table      [1]windows.MibUnicastIpAddressRow
}

// Addresses lists the unicast addresses of every interface (IPv4 and IPv6).
func Addresses() ([]Address, error) {
	var table *unicastTable
	r1, _, _ := procGetUnicastIpAddressTable.Call(uintptr(windows.AF_UNSPEC), uintptr(unsafe.Pointer(&table)))
	if err := errnoOf(r1); err != nil {
		return nil, err
	}
	if table == nil {
		return nil, nil
	}
	defer procFreeMibTable.Call(uintptr(unsafe.Pointer(table)))

	rows := unsafe.Slice(&table.Table[0], table.NumEntries)
	out := make([]Address, 0, len(rows))
	for i := range rows {
		addr, ok := sockaddrAddr(&rows[i].Address)
		if !ok {
			continue
		}
		out = append(out, Address{
			Luid:   rows[i].InterfaceLuid,
			Prefix: netip.PrefixFrom(addr, int(rows[i].OnLinkPrefixLength)),
		})
	}
	return out, nil
}

// sockaddrAddr decodes a SOCKADDR_INET stored in a RawSockaddrInet6.
func sockaddrAddr(sa *windows.RawSockaddrInet6) (netip.Addr, bool) {
	switch sa.Family {
	case windows.AF_INET:
		// SOCKADDR_IN: family, port, then the address where sin6_flowinfo is.
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], sa.Flowinfo)
		return netip.AddrFrom4(b), true
	case windows.AF_INET6:
		return netip.AddrFrom16(sa.Addr), true
	}
	return netip.Addr{}, false
}

// Connected reports whether the interface is up for IPv4 (media connected).
func Connected(luid uint64) bool {
	row := windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceLuid: luid}
	r1, _, _ := procGetIpInterfaceEntry.Call(uintptr(unsafe.Pointer(&row)))
	return r1 == 0 && row.Connected != 0
}
