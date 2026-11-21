// Package packet parses and builds the IPv4/IPv6 packets the engine handles:
// TCP (NAT rewrite, RST), UDP (replies) and ICMP (echo replies, errors). All
// functions work in place on caller buffers and never allocate.
package packet

import (
	"encoding/binary"
	"net/netip"
)

// IP protocol numbers.
const (
	ProtoICMP   = 1
	ProtoTCP    = 6
	ProtoUDP    = 17
	ProtoICMPv6 = 58
)

const (
	IPv4HeaderLen = 20
	IPv6HeaderLen = 40
	TCPHeaderLen  = 20
	UDPHeaderLen  = 8
	ICMPHeaderLen = 8
)

// TCP flags.
const (
	TCPFin = 0x01
	TCPSyn = 0x02
	TCPRst = 0x04
	TCPPsh = 0x08
	TCPAck = 0x10
)

const defaultTTL = 64

// IP is a parsed network-layer header. Payload aliases the packet buffer.
type IP struct {
	Version   int
	HeaderLen int
	Protocol  uint8
	TTL       uint8
	Src       netip.Addr
	Dst       netip.Addr
	// Packet is the whole datagram trimmed to its declared length.
	Packet  []byte
	Payload []byte
}

// Parse validates and decodes the IP header. It reports false for malformed
// packets, IPv4 fragments and IPv6 packets with extension headers (the engine
// only relays whole, directly-carried transport segments).
func Parse(b []byte) (IP, bool) {
	if len(b) < 1 {
		return IP{}, false
	}
	switch b[0] >> 4 {
	case 4:
		return parse4(b)
	case 6:
		return parse6(b)
	}
	return IP{}, false
}

func parse4(b []byte) (IP, bool) {
	if len(b) < IPv4HeaderLen {
		return IP{}, false
	}
	ihl := int(b[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(b[2:4]))
	if ihl < IPv4HeaderLen || total < ihl || total > len(b) {
		return IP{}, false
	}
	// More-fragments flag or a non-zero offset: a fragment.
	if binary.BigEndian.Uint16(b[6:8])&0x3fff != 0 {
		return IP{}, false
	}
	b = b[:total]
	return IP{
		Version:   4,
		HeaderLen: ihl,
		Protocol:  b[9],
		TTL:       b[8],
		Src:       netip.AddrFrom4([4]byte(b[12:16])),
		Dst:       netip.AddrFrom4([4]byte(b[16:20])),
		Packet:    b,
		Payload:   b[ihl:],
	}, true
}

func parse6(b []byte) (IP, bool) {
	if len(b) < IPv6HeaderLen {
		return IP{}, false
	}
	total := IPv6HeaderLen + int(binary.BigEndian.Uint16(b[4:6]))
	if total > len(b) {
		return IP{}, false
	}
	b = b[:total]
	switch next := b[6]; next {
	case ProtoTCP, ProtoUDP, ProtoICMPv6:
	default:
		return IP{}, false
	}
	return IP{
		Version:   6,
		HeaderLen: IPv6HeaderLen,
		Protocol:  b[6],
		TTL:       b[7],
		Src:       netip.AddrFrom16([16]byte(b[8:24])),
		Dst:       netip.AddrFrom16([16]byte(b[24:40])),
		Packet:    b,
		Payload:   b[IPv6HeaderLen:],
	}, true
}

// TCP accessors over a TCP segment (the IP payload).

func TCPValid(seg []byte) bool {
	if len(seg) < TCPHeaderLen {
		return false
	}
	off := int(seg[12]>>4) * 4
	return off >= TCPHeaderLen && off <= len(seg)
}

func TCPSrcPort(seg []byte) uint16 { return binary.BigEndian.Uint16(seg[0:2]) }
func TCPDstPort(seg []byte) uint16 { return binary.BigEndian.Uint16(seg[2:4]) }
func TCPSeq(seg []byte) uint32     { return binary.BigEndian.Uint32(seg[4:8]) }
func TCPAckNum(seg []byte) uint32  { return binary.BigEndian.Uint32(seg[8:12]) }
func TCPFlags(seg []byte) uint8    { return seg[13] }
func TCPDataLen(seg []byte) int    { return len(seg) - int(seg[12]>>4)*4 }

// UDP accessors over a UDP datagram (the IP payload).

func UDPValid(dg []byte) bool {
	if len(dg) < UDPHeaderLen {
		return false
	}
	l := int(binary.BigEndian.Uint16(dg[4:6]))
	return l >= UDPHeaderLen && l <= len(dg)
}

func UDPSrcPort(dg []byte) uint16 { return binary.BigEndian.Uint16(dg[0:2]) }
func UDPDstPort(dg []byte) uint16 { return binary.BigEndian.Uint16(dg[2:4]) }

// UDPPayload returns the datagram payload trimmed to the UDP length field.
func UDPPayload(dg []byte) []byte {
	return dg[UDPHeaderLen:binary.BigEndian.Uint16(dg[4:6])]
}

// ---- checksums ----

// Sum adds b to a ones-complement accumulator. 32-bit words are summed into a
// 64-bit accumulator; folding later is valid because 2^16 ≡ 1 (mod 2^16-1).
func Sum(b []byte, acc uint64) uint64 {
	for len(b) >= 8 {
		acc += uint64(binary.BigEndian.Uint32(b)) + uint64(binary.BigEndian.Uint32(b[4:]))
		b = b[8:]
	}
	if len(b) >= 4 {
		acc += uint64(binary.BigEndian.Uint32(b))
		b = b[4:]
	}
	if len(b) >= 2 {
		acc += uint64(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		acc += uint64(b[0]) << 8
	}
	return acc
}

// Fold reduces an accumulator to 16 bits.
func Fold(acc uint64) uint16 {
	for acc>>16 != 0 {
		acc = (acc & 0xffff) + acc>>16
	}
	return uint16(acc)
}

// Checksum is the final ones-complement checksum of b plus acc.
func Checksum(b []byte, acc uint64) uint16 { return ^Fold(Sum(b, acc)) }

func pseudoSum(src, dst netip.Addr, proto uint8, length int) uint64 {
	var acc uint64
	if src.Is4() {
		s, d := src.As4(), dst.As4()
		acc = Sum(s[:], acc)
		acc = Sum(d[:], acc)
	} else {
		s, d := src.As16(), dst.As16()
		acc = Sum(s[:], acc)
		acc = Sum(d[:], acc)
	}
	return acc + uint64(proto) + uint64(length)
}

// adjust updates a checksum for a change of the 16-bit-aligned words old->new
// (RFC 1624, eqn. 3: HC' = ~(~HC + ~m + m')).
func adjust(check uint16, old, new []byte) uint16 {
	acc := uint64(^check)
	for i := 0; i+1 < len(old); i += 2 {
		acc += uint64(^binary.BigEndian.Uint16(old[i:]))
		acc += uint64(binary.BigEndian.Uint16(new[i:]))
	}
	return ^Fold(acc)
}

// RewriteTCP replaces the addresses and ports of a TCP segment in place,
// patching the IPv4 header checksum and the TCP checksum incrementally.
// src/dst must be of the packet's IP family.
func RewriteTCP(ip IP, src, dst netip.AddrPort) {
	pkt := ip.Packet
	seg := ip.Payload
	var old, cur [36]byte
	var addrLen int
	var addrOff int
	if ip.Version == 4 {
		addrLen, addrOff = 8, 12
		s, d := src.Addr().As4(), dst.Addr().As4()
		copy(cur[0:4], s[:])
		copy(cur[4:8], d[:])
	} else {
		addrLen, addrOff = 32, 8
		s, d := src.Addr().As16(), dst.Addr().As16()
		copy(cur[0:16], s[:])
		copy(cur[16:32], d[:])
	}
	copy(old[:addrLen], pkt[addrOff:addrOff+addrLen])
	copy(old[addrLen:addrLen+4], seg[0:4])
	binary.BigEndian.PutUint16(cur[addrLen:], src.Port())
	binary.BigEndian.PutUint16(cur[addrLen+2:], dst.Port())
	n := addrLen + 4

	if ip.Version == 4 {
		ipCheck := binary.BigEndian.Uint16(pkt[10:12])
		binary.BigEndian.PutUint16(pkt[10:12], adjust(ipCheck, old[:addrLen], cur[:addrLen]))
	}
	tcpCheck := binary.BigEndian.Uint16(seg[16:18])
	binary.BigEndian.PutUint16(seg[16:18], adjust(tcpCheck, old[:n], cur[:n]))

	copy(pkt[addrOff:addrOff+addrLen], cur[:addrLen])
	copy(seg[0:4], cur[addrLen:n])
}

// ---- builders ----

// HeaderLen is the IP header length the builders use for a family.
func HeaderLen(addr netip.Addr) int {
	if addr.Is4() {
		return IPv4HeaderLen
	}
	return IPv6HeaderLen
}

// putIP writes an IP header for a datagram of payloadLen bytes and returns the
// header length. id is used for IPv4 only.
func putIP(buf []byte, src, dst netip.Addr, proto uint8, ttl uint8, payloadLen int, id uint16) int {
	if ttl == 0 {
		ttl = defaultTTL
	}
	if src.Is4() {
		h := buf[:IPv4HeaderLen]
		h[0] = 0x45
		h[1] = 0
		binary.BigEndian.PutUint16(h[2:], uint16(IPv4HeaderLen+payloadLen))
		binary.BigEndian.PutUint16(h[4:], id)
		binary.BigEndian.PutUint16(h[6:], 0)
		h[8] = ttl
		h[9] = proto
		h[10], h[11] = 0, 0
		s, d := src.As4(), dst.As4()
		copy(h[12:16], s[:])
		copy(h[16:20], d[:])
		binary.BigEndian.PutUint16(h[10:], Checksum(h, 0))
		return IPv4HeaderLen
	}
	h := buf[:IPv6HeaderLen]
	h[0], h[1], h[2], h[3] = 0x60, 0, 0, 0
	binary.BigEndian.PutUint16(h[4:], uint16(payloadLen))
	h[6] = proto
	h[7] = ttl
	s, d := src.As16(), dst.As16()
	copy(h[8:24], s[:])
	copy(h[24:40], d[:])
	return IPv6HeaderLen
}

// UDPOverhead is the header space BuildUDP needs in front of the payload.
func UDPOverhead(addr netip.Addr) int { return HeaderLen(addr) + UDPHeaderLen }

// BuildUDP completes a UDP datagram whose payload the caller already placed at
// buf[UDPOverhead(src.Addr()):][:payloadLen]. It returns the packet length.
func BuildUDP(buf []byte, src, dst netip.AddrPort, payloadLen int, id uint16) int {
	hl := HeaderLen(src.Addr())
	udpLen := UDPHeaderLen + payloadLen
	putIP(buf, src.Addr(), dst.Addr(), ProtoUDP, 0, udpLen, id)
	u := buf[hl : hl+udpLen]
	binary.BigEndian.PutUint16(u[0:], src.Port())
	binary.BigEndian.PutUint16(u[2:], dst.Port())
	binary.BigEndian.PutUint16(u[4:], uint16(udpLen))
	u[6], u[7] = 0, 0
	sum := Checksum(u, pseudoSum(src.Addr(), dst.Addr(), ProtoUDP, udpLen))
	if sum == 0 {
		sum = 0xffff
	}
	binary.BigEndian.PutUint16(u[6:], sum)
	return hl + udpLen
}

// Fragment4 splits a complete IPv4 packet (20-byte header) into fragments of
// at most mtu bytes, each written into scratch (len >= mtu) and passed to
// emit. The header's identification field must already be set.
func Fragment4(pkt []byte, mtu int, scratch []byte, emit func([]byte) error) error {
	const hl = IPv4HeaderLen
	data := pkt[hl:]
	chunk := (mtu - hl) &^ 7
	if chunk <= 0 {
		return nil
	}
	for off := 0; off < len(data); off += chunk {
		end := min(off+chunk, len(data))
		f := scratch[:hl+end-off]
		copy(f[:hl], pkt[:hl])
		copy(f[hl:], data[off:end])
		binary.BigEndian.PutUint16(f[2:], uint16(len(f)))
		field := uint16(off / 8)
		if end < len(data) {
			field |= 0x2000 // more fragments
		}
		binary.BigEndian.PutUint16(f[6:], field)
		f[10], f[11] = 0, 0
		binary.BigEndian.PutUint16(f[10:], Checksum(f[:hl], 0))
		if err := emit(f); err != nil {
			return err
		}
	}
	return nil
}

// BuildTCPReset writes into buf the RST answering the segment seg that was
// sent from src to dst (so the RST goes dst -> src). Returns the length.
func BuildTCPReset(buf []byte, src, dst netip.AddrPort, seg []byte) int {
	hl := HeaderLen(src.Addr())
	putIP(buf, dst.Addr(), src.Addr(), ProtoTCP, 0, TCPHeaderLen, 0)
	t := buf[hl : hl+TCPHeaderLen]
	clear(t)
	binary.BigEndian.PutUint16(t[0:], dst.Port())
	binary.BigEndian.PutUint16(t[2:], src.Port())
	flags := TCPFlags(seg)
	if flags&TCPAck != 0 {
		binary.BigEndian.PutUint32(t[4:], TCPAckNum(seg))
		t[13] = TCPRst
	} else {
		ack := TCPSeq(seg) + uint32(TCPDataLen(seg))
		if flags&TCPSyn != 0 {
			ack++
		}
		if flags&TCPFin != 0 {
			ack++
		}
		binary.BigEndian.PutUint32(t[8:], ack)
		t[13] = TCPRst | TCPAck
	}
	t[12] = (TCPHeaderLen / 4) << 4
	binary.BigEndian.PutUint16(t[16:], Checksum(t, pseudoSum(dst.Addr(), src.Addr(), ProtoTCP, TCPHeaderLen)))
	return hl + TCPHeaderLen
}

// ICMP message types (IPv4).
const (
	ICMPEchoReply      = 0
	ICMPUnreachable    = 3
	ICMPEchoRequest    = 8
	ICMPTimeExceeded   = 11
	ICMPv6EchoRequest  = 128
	ICMPv6EchoReply    = 129
	maxQuotedICMPBytes = 8
)

// ICMPEcho returns the identifier and sequence of an echo message.
func ICMPEcho(msg []byte) (id, seq uint16) {
	return binary.BigEndian.Uint16(msg[4:6]), binary.BigEndian.Uint16(msg[6:8])
}

// BuildEchoReply4 writes an ICMPv4 echo reply from -> to carrying the
// identifier, sequence and data of the request message req.
func BuildEchoReply4(buf []byte, from, to netip.Addr, ttl uint8, req []byte) int {
	msgLen := len(req)
	putIP(buf, from, to, ProtoICMP, ttl, msgLen, 0)
	m := buf[IPv4HeaderLen : IPv4HeaderLen+msgLen]
	copy(m, req)
	m[0], m[1] = ICMPEchoReply, 0
	m[2], m[3] = 0, 0
	binary.BigEndian.PutUint16(m[2:], Checksum(m, 0))
	return IPv4HeaderLen + msgLen
}

// BuildICMPError4 writes an ICMPv4 error (time exceeded, unreachable) from
// router -> to quoting the original datagram's header plus 8 bytes.
func BuildICMPError4(buf []byte, router, to netip.Addr, typ, code uint8, original []byte) int {
	ihl := int(original[0]&0x0f) * 4
	quote := min(len(original), ihl+maxQuotedICMPBytes)
	msgLen := ICMPHeaderLen + quote
	putIP(buf, router, to, ProtoICMP, 0, msgLen, 0)
	m := buf[IPv4HeaderLen : IPv4HeaderLen+msgLen]
	clear(m[:ICMPHeaderLen])
	m[0], m[1] = typ, code
	copy(m[ICMPHeaderLen:], original[:quote])
	binary.BigEndian.PutUint16(m[2:], Checksum(m, 0))
	return IPv4HeaderLen + msgLen
}

// ICMPErrorLen4 is the buffer size BuildICMPError4 needs.
func ICMPErrorLen4(original []byte) int {
	ihl := int(original[0]&0x0f) * 4
	return IPv4HeaderLen + ICMPHeaderLen + min(len(original), ihl+maxQuotedICMPBytes)
}
