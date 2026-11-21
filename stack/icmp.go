package stack

import (
	"net/netip"
	"time"

	"beam-tun"
	"beam-tun/internal/packet"
)

const (
	maxConcurrentEchoes = 64
	echoTimeout         = 4 * time.Second
)

type echoKind int

const (
	echoNone echoKind = iota
	echoReply
	echoTimeExceeded
	echoUnreachable
)

// echoResult is what the platform relay learned about one echo request.
type echoResult struct {
	kind echoKind
	// from is the answering host (the router for errors).
	from netip.Addr
	ttl  uint8
	code uint8
}

// handleICMP4 relays echo requests through the physical interface. Other ICMP
// messages from the host (errors about tunnelled flows) are dropped: the
// flows themselves are carried by the core.
func (s *Stack) handleICMP4(ip packet.IP) {
	msg := ip.Payload
	if len(msg) < packet.ICMPHeaderLen || msg[0] != packet.ICMPEchoRequest || msg[1] != 0 {
		return
	}
	if !echoSupported || s.opts.EchoSource == nil {
		return
	}
	source := s.opts.EchoSource()
	if !source.Is4() {
		// Without a physical source the request would follow the default
		// route straight back into the tunnel.
		tun.Metrics.ICMPEchoFailures.Add(1)
		return
	}
	select {
	case s.icmpSlots <- struct{}{}:
	default:
		tun.Metrics.ICMPEchoFailures.Add(1)
		return
	}
	request := append([]byte(nil), ip.Packet...)
	go func() {
		defer func() { <-s.icmpSlots }()
		defer s.contain("icmp echo")
		s.relayEcho4(source, request)
	}()
}

func (s *Stack) relayEcho4(source netip.Addr, request []byte) {
	ip, ok := packet.Parse(request)
	if !ok {
		return
	}
	msg := ip.Payload
	tun.Metrics.ICMPEchoes.Add(1)

	result, err := sendEcho4(source, ip.Dst, ip.TTL, msg[packet.ICMPHeaderLen:], echoTimeout)
	if err != nil || result.kind == echoNone {
		tun.Metrics.ICMPEchoFailures.Add(1)
		return
	}

	var buf *[]byte
	var n int
	switch result.kind {
	case echoReply:
		buf = getBuffer(packet.IPv4HeaderLen + len(msg))
		n = packet.BuildEchoReply4(*buf, ip.Dst, ip.Src, result.ttl, msg)
	case echoTimeExceeded, echoUnreachable:
		if !result.from.Is4() {
			return
		}
		typ := uint8(packet.ICMPTimeExceeded)
		if result.kind == echoUnreachable {
			typ = packet.ICMPUnreachable
		}
		buf = getBuffer(packet.ICMPErrorLen4(ip.Packet))
		n = packet.BuildICMPError4(*buf, result.from, ip.Src, typ, result.code, ip.Packet)
	default:
		return
	}
	_ = s.write((*buf)[:n])
	putBuffer(buf)
}
