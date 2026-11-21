package stack

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"beam-tun"
	"beam-tun/internal/packet"
)

const (
	// NAT ports are handed out round-robin over the whole range so a port
	// comes back only long after the kernel's TIME_WAIT on the listener side
	// (2 minutes on Windows) has expired.
	natPortMin = 1024
	natPortMax = 65535

	// tcpLinger keeps a mapping after the handler finished so the FIN/ACK
	// exchange between the two kernel sockets can complete.
	tcpLinger = 30 * time.Second
	// tcpAcceptTimeout drops mappings whose SYN never reached the listener
	// (e.g. the app gave up, or a firewall dropped it).
	tcpAcceptTimeout = 30 * time.Second

	acceptErrorBackoff = 20 * time.Millisecond
)

type natSession struct {
	key      flowKey
	port     uint16
	created  int64
	accepted atomic.Bool
	// finished is the unix-nano time the handler returned; 0 while active.
	finished atomic.Int64
}

type natTable struct {
	mu    sync.RWMutex
	flows map[flowKey]*natSession
	ports map[uint16]*natSession
	next  uint16
}

func newNATTable() *natTable {
	return &natTable{
		flows: make(map[flowKey]*natSession),
		ports: make(map[uint16]*natSession),
		next:  natPortMin,
	}
}

func (n *natTable) byPort(port uint16) *natSession {
	n.mu.RLock()
	sess := n.ports[port]
	n.mu.RUnlock()
	return sess
}

// lookup returns the session of a forward segment. Sessions are created only
// by a pure SYN; a SYN on a finished mapping starts a fresh session.
func (n *natTable) lookup(key flowKey, flags uint8) *natSession {
	n.mu.RLock()
	sess := n.flows[key]
	n.mu.RUnlock()

	syn := flags&(packet.TCPSyn|packet.TCPAck) == packet.TCPSyn
	if sess != nil && (!syn || sess.finished.Load() == 0) {
		return sess
	}
	if !syn {
		return nil
	}

	n.mu.Lock()
	defer n.mu.Unlock()
	if sess = n.flows[key]; sess != nil {
		if sess.finished.Load() == 0 {
			return sess
		}
		n.removeLocked(sess)
	}
	port, ok := n.allocLocked()
	if !ok {
		tun.Metrics.TCPPortExhausted.Add(1)
		return nil
	}
	sess = &natSession{key: key, port: port, created: monoNanos()}
	n.flows[key] = sess
	n.ports[port] = sess
	return sess
}

func (n *natTable) allocLocked() (uint16, bool) {
	const span = natPortMax - natPortMin + 1
	for i := 0; i < span; i++ {
		port := n.next
		if n.next == natPortMax {
			n.next = natPortMin
		} else {
			n.next++
		}
		if _, used := n.ports[port]; !used {
			return port, true
		}
	}
	return 0, false
}

func (n *natTable) removeLocked(sess *natSession) {
	if n.flows[sess.key] == sess {
		delete(n.flows, sess.key)
	}
	if n.ports[sess.port] == sess {
		delete(n.ports, sess.port)
	}
}

func (n *natTable) finish(sess *natSession) {
	sess.finished.Store(monoNanos())
}

// sweep drops lingering and never-accepted mappings.
func (n *natTable) sweep(now time.Time) {
	nowNano := monoOf(now)
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, sess := range n.ports {
		if done := sess.finished.Load(); done != 0 {
			if nowNano-done >= int64(tcpLinger) {
				n.removeLocked(sess)
			}
			continue
		}
		if !sess.accepted.Load() && nowNano-sess.created >= int64(tcpAcceptTimeout) {
			n.removeLocked(sess)
		}
	}
}

// handleTCP rewrites one segment in place and writes it back to the device.
func (s *Stack) handleTCP(fam *family, ip packet.IP) {
	seg := ip.Payload
	if !packet.TCPValid(seg) {
		tun.Metrics.Unsupported.Add(1)
		return
	}
	if s.gtcp != nil {
		s.gtcp.inject(ip)
		return
	}
	sport, dport := packet.TCPSrcPort(seg), packet.TCPDstPort(seg)

	// Listener -> NAT client: the reverse leg, back to the app.
	if ip.Src == fam.addr && sport == fam.port {
		if ip.Dst != fam.client {
			return
		}
		sess := fam.nat.byPort(dport)
		if sess == nil {
			return
		}
		packet.RewriteTCP(ip, sess.key.dst, sess.key.src)
		_ = s.write(ip.Packet)
		return
	}

	// App -> destination: the forward leg, into the listener.
	src := netip.AddrPortFrom(ip.Src, sport)
	dst := netip.AddrPortFrom(ip.Dst, dport)
	flags := packet.TCPFlags(seg)
	sess := fam.nat.lookup(flowKey{src: src, dst: dst}, flags)
	if sess == nil {
		// A segment of a connection we do not know (e.g. opened before the
		// tunnel restarted): reset it so the app reconnects immediately
		// instead of hanging until its own timeout.
		if flags&packet.TCPRst == 0 {
			tun.Metrics.TCPUnknownFlow.Add(1)
			s.sendReset(src, dst, seg)
		}
		return
	}
	packet.RewriteTCP(ip, netip.AddrPortFrom(fam.client, sess.port), netip.AddrPortFrom(fam.addr, fam.port))
	_ = s.write(ip.Packet)
}

func (s *Stack) sendReset(src, dst netip.AddrPort, seg []byte) {
	var buf [packet.IPv6HeaderLen + packet.TCPHeaderLen]byte
	n := packet.BuildTCPReset(buf[:], src, dst, seg)
	_ = s.write(buf[:n])
}

// acceptLoop takes connections the kernel terminated on the NAT listener and
// hands them to the handler with the original addresses.
func (s *Stack) acceptLoop(fam *family) {
	defer s.wg.Done()
	defer s.containFatal("tcp accept")
	for {
		conn, err := fam.listener.AcceptTCP()
		if err != nil {
			if s.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(acceptErrorBackoff)
			continue
		}
		remote, ok := conn.RemoteAddr().(*net.TCPAddr)
		if !ok {
			_ = conn.Close()
			continue
		}
		peer := remote.AddrPort()
		if peer.Addr().Unmap() != fam.client.Unmap() {
			_ = conn.Close()
			continue
		}
		sess := fam.nat.byPort(peer.Port())
		if sess == nil || !sess.accepted.CompareAndSwap(false, true) {
			_ = conn.Close()
			continue
		}
		go s.serveTCP(fam, conn, sess)
	}
}

func (s *Stack) serveTCP(fam *family, conn *net.TCPConn, sess *natSession) {
	defer s.contain("tcp flow")
	tun.Metrics.TCPActive.Add(1)
	defer tun.Metrics.TCPActive.Add(-1)
	defer fam.nat.finish(sess)
	defer conn.Close()

	_ = conn.SetNoDelay(true)
	meta := &tun.Metadata{
		Network:     "tcp",
		Source:      sess.key.src,
		Destination: sess.key.dst,
	}
	meta.ProcessPath = s.resolveProcess("tcp", sess.key.src, sess.key.dst)
	s.handler.HandleTCP(conn, meta)
}
