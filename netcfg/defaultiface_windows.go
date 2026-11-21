package netcfg

import (
	"fmt"
	"strings"

	"beam-tun/internal/winip"
)

// DefaultInterface returns the name of the interface that carries the
// host's default route, excluding the tunnel itself.
//
// Outbounds that must not be tunnelled (the "direct" one above all) have to
// bind their sockets to this interface. Without it the OS routes them through
// the tunnel - the default route belongs to it - the packets re-enter the
// stack, get dispatched to the same outbound again and the core spins in a
// loop opening thousands of connections per second.
func DefaultInterface(exclude string) (string, error) {
	// Туннеля на момент вызова может ещё не быть — тогда исключать нечего.
	var excludeLuid uint64
	if luid, err := interfaceLuid(exclude); err == nil {
		excludeLuid = luid
	}

	_, luid, err := defaultRoute4(excludeLuid)
	if err != nil {
		return "", err
	}

	// The alias is what net.Interface calls Name on Windows, read without
	// GetAdaptersAddresses.
	name, err := winip.NameOf(luid)
	if err != nil {
		return "", fmt.Errorf("tun: resolve interface %d: %w", luid, err)
	}
	if name == "" || strings.EqualFold(name, strings.TrimSpace(exclude)) {
		return "", fmt.Errorf("tun: no usable default interface")
	}
	return name, nil
}
