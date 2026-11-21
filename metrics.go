package tun

import "sync/atomic"

// Metrics are process-wide counters of the TUN layer. They are cheap atomic
// increments on the hot path and are sampled by the core's developer-mode
// debug logger once per second.
var Metrics metrics

type metrics struct {
	// RingFullDrops: packets towards the host dropped because the adapter
	// send ring stayed full past the backpressure budget.
	RingFullDrops atomic.Uint64
	// UDPQueueDrops: datagrams from apps dropped because the session queue
	// was full (the core does not keep up).
	UDPQueueDrops atomic.Uint64
	// UDPSessionLimitDrops: datagrams dropped because the session table is
	// full.
	UDPSessionLimitDrops atomic.Uint64
	// TCPUnknownFlow: TCP segments without a NAT session (answered with RST).
	TCPUnknownFlow atomic.Uint64
	// TCPPortExhausted: SYNs dropped because no NAT port was free.
	TCPPortExhausted atomic.Uint64
	// Unsupported: fragments, unknown protocols, malformed packets.
	Unsupported atomic.Uint64
	// Oversized: replies larger than the tunnel MTU (dropped).
	Oversized atomic.Uint64
	// ICMPEchoes / ICMPEchoFailures: relayed pings and those that got no
	// answer (timeout, unreachable without a reply, no physical source).
	ICMPEchoes       atomic.Uint64
	ICMPEchoFailures atomic.Uint64

	TCPActive atomic.Int64
	UDPActive atomic.Int64

	PacketsIn  atomic.Uint64
	PacketsOut atomic.Uint64
}

// MetricsSnapshot is a point-in-time copy of Metrics.
type MetricsSnapshot struct {
	RingFullDrops        uint64
	UDPQueueDrops        uint64
	UDPSessionLimitDrops uint64
	TCPUnknownFlow       uint64
	TCPPortExhausted     uint64
	Unsupported          uint64
	Oversized            uint64
	ICMPEchoes           uint64
	ICMPEchoFailures     uint64
	TCPActive            int64
	UDPActive            int64
	PacketsIn            uint64
	PacketsOut           uint64
}

// Snapshot returns the current counter values.
func (m *metrics) Snapshot() MetricsSnapshot {
	return MetricsSnapshot{
		RingFullDrops:        m.RingFullDrops.Load(),
		UDPQueueDrops:        m.UDPQueueDrops.Load(),
		UDPSessionLimitDrops: m.UDPSessionLimitDrops.Load(),
		TCPUnknownFlow:       m.TCPUnknownFlow.Load(),
		TCPPortExhausted:     m.TCPPortExhausted.Load(),
		Unsupported:          m.Unsupported.Load(),
		Oversized:            m.Oversized.Load(),
		ICMPEchoes:           m.ICMPEchoes.Load(),
		ICMPEchoFailures:     m.ICMPEchoFailures.Load(),
		TCPActive:            m.TCPActive.Load(),
		UDPActive:            m.UDPActive.Load(),
		PacketsIn:            m.PacketsIn.Load(),
		PacketsOut:           m.PacketsOut.Load(),
	}
}
