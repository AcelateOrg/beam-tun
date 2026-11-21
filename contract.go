// Package tun is the Beam TUN layer. The root package holds only the contract
// shared by the packet engine, the OS-facing pieces and their consumers.
//
// Layout:
//
//	tun                  — contract (Device, Handler, Metadata, ProcessResolver),
//	                       MTU bounds, metrics
//	tun/device           — the OS TUN adapter (Open): WinTun on Windows,
//	                       wireguard-go elsewhere
//	tun/netcfg           — adapter network configuration (Configure), default
//	                       interface lookup, network change monitor, conflict
//	                       checks
//	tun/process          — flow -> owning process resolver (per-app routing)
//	tun/stack            — the "mixed" packet engine: TCP is terminated by the
//	                       host kernel through an in-place NAT, UDP and ICMP are
//	                       handled in userspace
//	tun/dialer           — sockets pinned to the physical interface (bypass)
//	tun/internal/packet  — IPv4/IPv6/TCP/UDP/ICMP parsing, checksums, builders
//
// The package carries no dependency on any proxy core: the core plugs in
// through Handler.
package tun

import (
	"io"
	"net"
	"net/netip"
)

// MTU bounds shared by the adapter and the network configurator.
//
// TCP is terminated by the host kernel on both sides of the NAT and
// re-segmented by the proxy core for the real path, so the tunnel MTU does not
// have to match the path MTU. A large MTU means fewer packets (and fewer ring
// operations) for the same throughput; memory stays proportional to real
// traffic because the WinTun ring is fixed-size and per-packet buffers are
// pooled by size.
const (
	DefaultMTU   = 9000
	MinTunnelMTU = 1280
	MaxTunnelMTU = 65535
)

// OffsetHeadroom is the spare space kept after the MTU in every read buffer.
const OffsetHeadroom = 64

// ClampMTU normalises a configured MTU into the supported range.
func ClampMTU(mtu int) int {
	switch {
	case mtu <= 0:
		return DefaultMTU
	case mtu < MinTunnelMTU:
		return MinTunnelMTU
	case mtu > MaxTunnelMTU:
		return MaxTunnelMTU
	}
	return mtu
}

// Metadata describes one tunnelled flow. The engine fills the addresses from the
// packet and, off the hot path, the owning process for split tunneling.
type Metadata struct {
	Network     string
	Source      netip.AddrPort
	Destination netip.AddrPort
	ProcessPath string
}

// Handler receives established flows from the engine. The core implements it to
// dial the destination through the proxy (or directly, for bypassed apps). It
// is the single seam between the TUN stack and any engine: the stack never
// imports the core. Handlers own the connection and must close it.
type Handler interface {
	HandleTCP(conn net.Conn, meta *Metadata)
	HandleUDP(conn net.PacketConn, meta *Metadata)
}

// Device is a TUN adapter: raw IP packets in and out. Write must be safe for
// concurrent use; Read is called from a single goroutine.
type Device interface {
	Read(buf []byte) (int, error)
	Write(buf []byte) (int, error)
	MTU() int
	io.Closer
}

// BatchReader and BatchWriter are optional Device extensions. When the adapter
// can move packets in batches (WinTun can), the engine takes that path and saves
// a call per packet.
type BatchReader interface {
	ReadBatch(bufs [][]byte, sizes []int) (int, error)
	BatchSize() int
}

type BatchWriter interface {
	WriteBatch(bufs [][]byte) error
	BatchSize() int
}

// ProcessResolver maps a flow to the path of the process that owns it, used for
// per-app split tunneling.
type ProcessResolver interface {
	Resolve(network string, source, destination netip.AddrPort) (string, error)
}
