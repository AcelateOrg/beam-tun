//go:build (linux && !android) || darwin

package stack

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"time"

	"golang.org/x/sys/unix"
)

// Echo requests leave through an ICMP socket pinned to the physical
// interface owning the source address (SO_BINDTODEVICE on Linux,
// IP_BOUND_IF on macOS), so they bypass the tunnel's default routes. A raw
// socket is preferred: it also sees Time Exceeded / Unreachable replies,
// which traceroute needs. Without privileges an unprivileged ICMP datagram
// socket still relays plain pings.

const echoSupported = true

const (
	icmpEchoReply      = 0
	icmpUnreachable    = 3
	icmpEchoRequest    = 8
	icmpTimeExceeded   = 11
	ipv4MinHeaderLen   = 20
	icmpHeaderLen      = 8
	defaultEchoTTL     = 64
	maxEchoReplyLength = 64 * 1024
)

func sendEcho4(source, destination netip.Addr, ttl uint8, data []byte, timeout time.Duration) (echoResult, error) {
	fd, raw, err := openICMP4()
	if err != nil {
		return echoResult{}, err
	}
	defer unix.Close(fd)

	if err := pinToInterface(fd, source); err != nil {
		return echoResult{}, err
	}
	if err := unix.Bind(fd, &unix.SockaddrInet4{Addr: source.As4()}); err != nil {
		return echoResult{}, fmt.Errorf("bind icmp: %w", err)
	}
	if ttl == 0 {
		ttl = defaultEchoTTL
	}
	_ = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TTL, int(ttl))

	id := uint16(rand.Uint32())
	seq := uint16(rand.Uint32())
	msg := make([]byte, icmpHeaderLen+len(data))
	msg[0] = icmpEchoRequest
	binary.BigEndian.PutUint16(msg[4:], id)
	binary.BigEndian.PutUint16(msg[6:], seq)
	copy(msg[icmpHeaderLen:], data)
	binary.BigEndian.PutUint16(msg[2:], icmpChecksum(msg))

	if err := unix.Sendto(fd, msg, 0, &unix.SockaddrInet4{Addr: destination.As4()}); err != nil {
		return echoResult{}, fmt.Errorf("send icmp: %w", err)
	}

	// A datagram socket has its echo id rewritten by the kernel and only
	// ever receives its own replies, so only the sequence is compared.
	m := echoMatcher{id: id, seq: seq, dst: destination, checkID: raw}
	buf := make([]byte, maxEchoReplyLength)
	deadline := time.Now().Add(timeout)
	for {
		left := time.Until(deadline)
		if left <= 0 {
			return echoResult{kind: echoNone}, nil
		}
		tv := unix.NsecToTimeval(left.Nanoseconds())
		if tv.Sec == 0 && tv.Usec == 0 {
			tv.Usec = 1
		}
		_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)

		n, from, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR) {
				continue
			}
			return echoResult{}, fmt.Errorf("recv icmp: %w", err)
		}
		var fromAddr netip.Addr
		if sa, ok := from.(*unix.SockaddrInet4); ok {
			fromAddr = netip.AddrFrom4(sa.Addr)
		}
		if result, ok := m.match(buf[:n], fromAddr); ok {
			return result, nil
		}
	}
}

func openICMP4() (fd int, raw bool, err error) {
	fd, err = unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP)
	if err == nil {
		unix.CloseOnExec(fd)
		return fd, true, nil
	}
	fd, dgramErr := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_ICMP)
	if dgramErr == nil {
		unix.CloseOnExec(fd)
		return fd, false, nil
	}
	return -1, false, fmt.Errorf("icmp socket: %w", err)
}

// interfaceOf finds the interface that owns addr.
func interfaceOf(addr netip.Addr) (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for i := range ifaces {
		addrs, err := ifaces[i].Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if ip, ok := netip.AddrFromSlice(ipNet.IP); ok && ip.Unmap() == addr {
				return &ifaces[i], nil
			}
		}
	}
	return nil, fmt.Errorf("no interface owns %s", addr)
}

type echoMatcher struct {
	id, seq uint16
	dst     netip.Addr
	checkID bool
}

// match decodes one received datagram. Raw sockets (and macOS datagram
// sockets) deliver the IPv4 header; Linux datagram sockets do not. An
// ICMP type byte never has the IPv4 version nibble, so the two are told
// apart by the first byte.
func (m echoMatcher) match(pkt []byte, from netip.Addr) (echoResult, bool) {
	replyTTL := uint8(defaultEchoTTL)
	if len(pkt) >= ipv4MinHeaderLen && pkt[0]>>4 == 4 {
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < ipv4MinHeaderLen || len(pkt) < ihl {
			return echoResult{}, false
		}
		replyTTL = pkt[8]
		if !from.IsValid() {
			from = netip.AddrFrom4([4]byte(pkt[12:16]))
		}
		pkt = pkt[ihl:]
	}
	if len(pkt) < icmpHeaderLen {
		return echoResult{}, false
	}

	switch pkt[0] {
	case icmpEchoReply:
		if from != m.dst || !m.same(pkt[4:8]) {
			return echoResult{}, false
		}
		if replyTTL == 0 {
			replyTTL = defaultEchoTTL
		}
		return echoResult{kind: echoReply, from: from, ttl: replyTTL}, true
	case icmpTimeExceeded, icmpUnreachable:
		// The error quotes the original IPv4 header plus 8 bytes of our
		// echo request.
		inner := pkt[icmpHeaderLen:]
		if len(inner) < ipv4MinHeaderLen || inner[0]>>4 != 4 {
			return echoResult{}, false
		}
		ihl := int(inner[0]&0x0f) * 4
		if ihl < ipv4MinHeaderLen || len(inner) < ihl+icmpHeaderLen {
			return echoResult{}, false
		}
		if inner[9] != unix.IPPROTO_ICMP || netip.AddrFrom4([4]byte(inner[16:20])) != m.dst {
			return echoResult{}, false
		}
		quoted := inner[ihl:]
		if quoted[0] != icmpEchoRequest || !m.same(quoted[4:8]) {
			return echoResult{}, false
		}
		kind := echoTimeExceeded
		if pkt[0] == icmpUnreachable {
			kind = echoUnreachable
		}
		return echoResult{kind: kind, from: from, code: pkt[1]}, true
	}
	return echoResult{}, false
}

func (m echoMatcher) same(idSeq []byte) bool {
	if binary.BigEndian.Uint16(idSeq[2:4]) != m.seq {
		return false
	}
	return !m.checkID || binary.BigEndian.Uint16(idSeq[0:2]) == m.id
}

func icmpChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
