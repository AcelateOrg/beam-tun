//go:build !windows && !darwin && (!linux || android)

package process

import (
	"net/netip"

	"beam-tun"
)

type noopResolver struct{}

// NewResolver returns a resolver that never finds an owner: per-app split
// tunneling is not supported on this platform.
func NewResolver() tun.ProcessResolver { return noopResolver{} }

func (noopResolver) Resolve(string, netip.AddrPort, netip.AddrPort) (string, error) {
	return "", ErrNotFound
}
