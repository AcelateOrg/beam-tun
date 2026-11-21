package stack

import (
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"beam-tun"
	"beam-tun/internal/packet"
)

// udpQueueLen bounds datagrams buffered per session between the read loop and
// the handler. At game/voice packet rates this is hundreds of milliseconds of
// traffic; beyond it the core is not keeping up and dropping is the right
// answer for real-time traffic (stale datagrams are worse than lost ones).
const udpQueueLen = 256

type udpTable struct {
	s        *Stack
	mu       sync.RWMutex
	sessions map[flowKey]*udpSession
	limit    int
}

func newUDPTable(s *Stack, limit int) *udpTable {
	return &udpTable{s: s, sessions: make(map[flowKey]*udpSession), limit: limit}
}

// deliver queues one datagram from an app, creating the session on first use.
// Runs on the read goroutine and never blocks.
func (t *udpTable) deliver(key flowKey, payload []byte) {
	t.mu.RLock()
	sess := t.sessions[key]
	t.mu.RUnlock()

	if sess == nil {
		created := false
		t.mu.Lock()
		if t.s.ctx.Err() != nil {
			t.mu.Unlock()
			return
		}
		if sess = t.sessions[key]; sess == nil {
			if len(t.sessions) >= t.limit {
				t.mu.Unlock()
				tun.Metrics.UDPSessionLimitDrops.Add(1)
				return
			}
			sess = newUDPSession(t, key)
			t.sessions[key] = sess
			created = true
		}
		t.mu.Unlock()
		if created {
			go t.s.serveUDP(sess)
		}
	}

	buf := getBuffer(len(payload))
	copy(*buf, payload)
	select {
	case sess.queue <- buf:
	default:
		putBuffer(buf)
		tun.Metrics.UDPQueueDrops.Add(1)
	}
}

func (t *udpTable) remove(sess *udpSession) {
	t.mu.Lock()
	if t.sessions[sess.key] == sess {
		delete(t.sessions, sess.key)
	}
	t.mu.Unlock()
}

func (t *udpTable) closeAll() {
	t.mu.Lock()
	sessions := make([]*udpSession, 0, len(t.sessions))
	for _, sess := range t.sessions {
		sessions = append(sessions, sess)
	}
	t.mu.Unlock()
	for _, sess := range sessions {
		_ = sess.Close()
	}
}

func (s *Stack) handleUDP(_ *family, ip packet.IP) {
	dg := ip.Payload
	if !packet.UDPValid(dg) {
		tun.Metrics.Unsupported.Add(1)
		return
	}
	dport := packet.UDPDstPort(dg)
	if dport == 0 {
		return
	}
	key := flowKey{
		src: netip.AddrPortFrom(ip.Src, packet.UDPSrcPort(dg)),
		dst: netip.AddrPortFrom(ip.Dst, dport),
	}
	s.udp.deliver(key, packet.UDPPayload(dg))
}

func (s *Stack) serveUDP(sess *udpSession) {
	defer s.contain("udp flow")
	tun.Metrics.UDPActive.Add(1)
	defer tun.Metrics.UDPActive.Add(-1)
	defer sess.Close()

	meta := &tun.Metadata{
		Network:     "udp",
		Source:      sess.key.src,
		Destination: sess.key.dst,
	}
	meta.ProcessPath = s.resolveProcess("udp", sess.key.src, sess.key.dst)
	s.handler.HandleUDP(sess, meta)
}

// writeUDP builds a datagram from -> to and writes it to the device directly
// from the calling (handler) goroutine. Oversized IPv4 replies are
// fragmented; oversized IPv6 replies are dropped.
func (s *Stack) writeUDP(from, to netip.AddrPort, payload []byte) error {
	hdr := packet.UDPOverhead(from.Addr())
	total := hdr + len(payload)
	if total > 0xffff {
		tun.Metrics.Oversized.Add(1)
		return nil
	}
	buf := getBuffer(total)
	defer putBuffer(buf)
	b := *buf
	copy(b[hdr:], payload)
	n := packet.BuildUDP(b, from, to, len(payload), s.nextIPID())
	if n <= s.mtu {
		return s.write(b[:n])
	}
	if !from.Addr().Is4() {
		tun.Metrics.Oversized.Add(1)
		return nil
	}
	scratch := getBuffer(s.mtu)
	defer putBuffer(scratch)
	return packet.Fragment4(b[:n], s.mtu, *scratch, s.write)
}

// udpSession is one (app source, destination) UDP flow, exposed to the handler
// as a net.PacketConn. ReadFrom yields the app's datagrams; WriteTo sends a
// reply to the app that appears to come from the original destination.
type udpSession struct {
	table *udpTable
	key   flowKey
	local *net.UDPAddr

	queue chan *[]byte
	done  chan struct{}

	closeOnce sync.Once

	readDeadline atomic.Int64
	// timer is used by the single reader only.
	timer *time.Timer
}

var _ net.PacketConn = (*udpSession)(nil)

func newUDPSession(t *udpTable, key flowKey) *udpSession {
	return &udpSession{
		table: t,
		key:   key,
		local: net.UDPAddrFromAddrPort(key.dst),
		queue: make(chan *[]byte, udpQueueLen),
		done:  make(chan struct{}),
	}
}

func (c *udpSession) ReadFrom(p []byte) (int, net.Addr, error) {
	// Fast path: a datagram is already waiting.
	select {
	case buf := <-c.queue:
		return c.consume(p, buf)
	case <-c.done:
		return 0, nil, net.ErrClosed
	default:
	}

	var timeout <-chan time.Time
	if deadline := c.readDeadline.Load(); deadline != 0 {
		wait := time.Duration(deadline - monoNanos())
		if wait <= 0 {
			return 0, nil, os.ErrDeadlineExceeded
		}
		if c.timer == nil {
			c.timer = time.NewTimer(wait)
		} else {
			c.timer.Reset(wait)
		}
		timeout = c.timer.C
		defer c.timer.Stop()
	}

	select {
	case buf := <-c.queue:
		return c.consume(p, buf)
	case <-c.done:
		return 0, nil, net.ErrClosed
	case <-timeout:
		return 0, nil, os.ErrDeadlineExceeded
	}
}

func (c *udpSession) consume(p []byte, buf *[]byte) (int, net.Addr, error) {
	n := copy(p, *buf)
	putBuffer(buf)
	return n, c.local, nil
}

// WriteTo sends p to the app. The address argument is ignored: a session
// always answers from its original destination to its original source.
func (c *udpSession) WriteTo(p []byte, _ net.Addr) (int, error) {
	select {
	case <-c.done:
		return 0, net.ErrClosed
	default:
	}
	if err := c.table.s.writeUDP(c.key.dst, c.key.src, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *udpSession) Close() error {
	c.closeOnce.Do(func() {
		close(c.done)
		c.table.remove(c)
	})
	return nil
}

func (c *udpSession) LocalAddr() net.Addr { return c.local }

func (c *udpSession) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }

func (c *udpSession) SetReadDeadline(t time.Time) error {
	if t.IsZero() {
		c.readDeadline.Store(0)
	} else {
		c.readDeadline.Store(monoOf(t))
	}
	return nil
}

// SetWriteDeadline is a no-op: writes go straight to the device ring and
// never block for long.
func (c *udpSession) SetWriteDeadline(time.Time) error { return nil }
