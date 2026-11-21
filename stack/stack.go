// Package stack is the Beam "mixed" packet engine.
//
// TCP is not implemented in userspace at all. Segments read from the TUN
// device are rewritten in place (addresses, ports, incremental checksums) and
// written straight back, so the host kernel terminates the connection on a
// local listener bound to the tunnel address:
//
//	app  S -> D                      becomes  client:natPort -> tun:listenPort
//	tun:listenPort -> client:natPort becomes  D -> S
//
// The accepted socket is handed to the Handler together with the original
// S/D pair. Congestion control, retransmission, windowing and segmentation
// are therefore the kernel's own on both legs, with no userspace TCP state.
//
// UDP is terminated in userspace: every (source, destination) pair is a
// session exposed to the Handler as a net.PacketConn; replies are built and
// written directly from the handler goroutine, without any shared queue on
// the way back. ICMP echo requests are relayed through the physical interface
// where the platform allows it (Windows: IcmpSendEcho2Ex).
package stack

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"beam-tun"
	"beam-tun/internal/packet"
)

const (
	// A single failed read must not take the tunnel down; a persistent
	// failure must not spin either.
	maxDeviceErrors    = 16
	deviceErrorBackoff = 10 * time.Millisecond

	listenRetries  = 50
	listenInterval = 100 * time.Millisecond

	janitorInterval = 10 * time.Second

	// errorReportInterval rate-limits repeated write errors in the log.
	errorReportInterval = 5 * time.Second
)

// Options configures the engine.
type Options struct {
	Device  tun.Device
	Handler tun.Handler
	// Process resolves the owning app of a flow; optional.
	Process tun.ProcessResolver

	// Inet4Address is the tunnel interface address with its prefix
	// (e.g. 172.19.0.1/30). Required: the kernel listener binds to it and
	// the next address in the prefix acts as the NAT client address.
	Inet4Address netip.Prefix
	// Inet6Address enables IPv6 handling when valid.
	Inet6Address netip.Prefix

	// EchoSource returns the IPv4 address of the physical interface. ICMP
	// echo requests are sent from it so they leave the host directly (Xray
	// cannot carry ICMP). Nil or an invalid address disables ping relaying.
	EchoSource func() netip.Addr

	// UDPSessionLimit caps concurrent UDP sessions (default 16384).
	UDPSessionLimit int

	// InboundAllowed tells the stack the caller already lets inbound TCP to
	// the NAT listener through the host firewall (Windows: a WFP hard
	// permit, see firewall.AttachTunnel). Otherwise the stack falls back to
	// a Windows Defender Firewall rule added through netsh.
	InboundAllowed bool

	// UserspaceTCP terminates TCP in a gVisor netstack instead of the host
	// kernel's NAT listener. Required on Android, where the platform routes
	// the listener's replies past the VPN interface; slower elsewhere.
	UserspaceTCP bool

	OnError func(error)
	OnWarn  func(error)
	// Debugf receives developer-mode diagnostics; optional.
	Debugf func(format string, args ...any)
}

// Stack is a running engine. Close stops it and closes the device.
type Stack struct {
	device  tun.Device
	handler tun.Handler
	process tun.ProcessResolver
	opts    Options
	mtu     int

	v4 *family
	v6 *family

	udp *udpTable
	// gtcp is the userspace TCP engine when Options.UserspaceTCP is set;
	// the families then have no kernel listener.
	gtcp *userspaceTCP

	icmpSlots chan struct{}

	ipID atomic.Uint32

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	lastWriteErr atomic.Int64

	closeOnce sync.Once
	closeErr  error
}

// family is the per-IP-version NAT endpoint.
type family struct {
	prefix    netip.Prefix
	addr      netip.Addr // tunnel address, the listener binds here
	client    netip.Addr // NAT client address (next address in the prefix)
	broadcast netip.Addr // IPv4 only
	listener  *net.TCPListener
	port      uint16
	nat       *natTable
}

type flowKey struct {
	src netip.AddrPort
	dst netip.AddrPort
}

// New starts the engine: it opens the kernel listeners and begins reading the
// device. On error nothing is left running and the device is not closed.
func New(opts Options) (*Stack, error) {
	if opts.Device == nil {
		return nil, errors.New("stack: device is required")
	}
	if opts.Handler == nil {
		return nil, errors.New("stack: handler is required")
	}
	if !opts.Inet4Address.IsValid() || !opts.Inet4Address.Addr().Is4() {
		return nil, errors.New("stack: IPv4 tunnel address is required")
	}
	if opts.UDPSessionLimit <= 0 {
		opts.UDPSessionLimit = 16384
	}

	mtu := opts.Device.MTU()
	if mtu <= 0 {
		mtu = tun.DefaultMTU
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := &Stack{
		device:    opts.Device,
		handler:   opts.Handler,
		process:   opts.Process,
		opts:      opts,
		mtu:       mtu,
		icmpSlots: make(chan struct{}, maxConcurrentEchoes),
		ctx:       ctx,
		cancel:    cancel,
	}
	s.udp = newUDPTable(s, opts.UDPSessionLimit)

	if !opts.InboundAllowed && !opts.UserspaceTCP {
		if err := ensureFirewall(); err != nil {
			s.warn(fmt.Errorf("stack: firewall rule for the NAT listener: %w", err))
		}
	}

	v4, err := s.newFamily(opts.Inet4Address)
	if err != nil {
		cancel()
		return nil, err
	}
	s.v4 = v4
	if opts.Inet6Address.IsValid() && opts.Inet6Address.Addr().Is6() {
		v6, err := s.newFamily(opts.Inet6Address)
		if err != nil {
			// IPv6 is optional: keep IPv4 working.
			s.warn(fmt.Errorf("stack: IPv6 disabled: %w", err))
		} else {
			s.v6 = v6
		}
	}

	if opts.UserspaceTCP {
		gtcp, err := newUserspaceTCP(s)
		if err != nil {
			cancel()
			s.wg.Wait()
			return nil, err
		}
		s.gtcp = gtcp
	} else {
		for _, fam := range s.families() {
			s.wg.Add(1)
			go s.acceptLoop(fam)
		}
	}
	s.wg.Add(2)
	go s.readLoop()
	go s.janitor()

	if s.gtcp != nil {
		s.debugf("stack: mixed engine up mtu=%d tcp=gvisor", mtu)
	} else {
		s.debugf("stack: mixed engine up mtu=%d nat4=%s->%s:%d", mtu, v4.client, v4.addr, v4.port)
	}
	return s, nil
}

func (s *Stack) families() []*family {
	if s.v6 != nil {
		return []*family{s.v4, s.v6}
	}
	return []*family{s.v4}
}

func (s *Stack) newFamily(prefix netip.Prefix) (*family, error) {
	addr := prefix.Addr()
	client := addr.Next()
	if !client.IsValid() {
		return nil, fmt.Errorf("stack: no NAT client address after %s", addr)
	}
	fam := &family{
		prefix: prefix.Masked(),
		addr:   addr,
		client: client,
		nat:    newNATTable(),
	}
	if addr.Is4() {
		fam.broadcast = lastAddr(prefix)
	}

	if s.opts.UserspaceTCP {
		// TCP never reaches the host kernel: no listener to open.
		return fam, nil
	}

	network := "tcp4"
	if addr.Is6() {
		network = "tcp6"
	}
	var listener *net.TCPListener
	var err error
	// The adapter address becomes usable asynchronously after configuration.
	for attempt := 0; attempt < listenRetries; attempt++ {
		listener, err = net.ListenTCP(network, net.TCPAddrFromAddrPort(netip.AddrPortFrom(addr, 0)))
		if err == nil {
			break
		}
		select {
		case <-s.ctx.Done():
			return nil, s.ctx.Err()
		case <-time.After(listenInterval):
		}
	}
	if err != nil {
		return nil, fmt.Errorf("stack: listen on %s: %w", addr, err)
	}
	fam.listener = listener
	fam.port = uint16(listener.Addr().(*net.TCPAddr).Port)
	return fam, nil
}

// lastAddr returns the highest address of an IPv4 prefix (its broadcast).
func lastAddr(prefix netip.Prefix) netip.Addr {
	b := prefix.Masked().Addr().As4()
	bits := prefix.Bits()
	for i := 0; i < 4; i++ {
		hostBits := 32 - bits - (3-i)*8
		switch {
		case hostBits >= 8:
			b[i] = 0xff
		case hostBits > 0:
			b[i] |= byte(1<<hostBits) - 1
		}
	}
	return netip.AddrFrom4(b)
}

// Close stops the engine, closes every session and the device.
func (s *Stack) Close() error {
	s.closeOnce.Do(func() {
		s.cancel()
		for _, fam := range s.families() {
			if fam.listener != nil {
				_ = fam.listener.Close()
			}
		}
		s.closeErr = s.device.Close()
		if s.gtcp != nil {
			s.gtcp.close()
		}
		s.udp.closeAll()
		s.wg.Wait()
	})
	return s.closeErr
}

func (s *Stack) readLoop() {
	defer s.wg.Done()
	defer s.containFatal("read loop")
	restore := boostCurrentThread()
	defer restore()

	bufSize := s.mtu + tun.OffsetHeadroom
	if bufSize < 1500+tun.OffsetHeadroom {
		bufSize = 1500 + tun.OffsetHeadroom
	}

	batchReader, batched := s.device.(tun.BatchReader)
	batch := 1
	if batched {
		batch = max(batchReader.BatchSize(), 1)
	}
	bufs := make([][]byte, batch)
	for i := range bufs {
		bufs[i] = make([]byte, bufSize)
	}
	sizes := make([]int, batch)

	failures := 0
	for {
		var n int
		var err error
		if batched {
			n, err = batchReader.ReadBatch(bufs, sizes)
		} else {
			sizes[0], err = s.device.Read(bufs[0])
			if sizes[0] > 0 {
				n = 1
			}
		}
		if n > 0 {
			tun.Metrics.PacketsIn.Add(uint64(n))
			for i := 0; i < n; i++ {
				s.handlePacketContained(bufs[i][:sizes[i]])
			}
		}
		if err == nil {
			failures = 0
			continue
		}
		if s.ctx.Err() != nil || errors.Is(err, os.ErrClosed) || errors.Is(err, net.ErrClosed) {
			return
		}
		failures++
		if failures >= maxDeviceErrors {
			s.fail(fmt.Errorf("stack: device read failed %d times in a row: %w", failures, err))
			return
		}
		time.Sleep(deviceErrorBackoff)
	}
}

// handlePacket dispatches one packet read from the device. It runs on the
// read goroutine: everything here is non-blocking.
func (s *Stack) handlePacket(buf []byte) {
	ip, ok := packet.Parse(buf)
	if !ok {
		tun.Metrics.Unsupported.Add(1)
		return
	}
	var fam *family
	if ip.Version == 4 {
		fam = s.v4
	} else {
		fam = s.v6
	}
	if fam == nil || !fam.routable(ip.Dst) {
		return
	}
	switch ip.Protocol {
	case packet.ProtoTCP:
		s.handleTCP(fam, ip)
	case packet.ProtoUDP:
		s.handleUDP(fam, ip)
	case packet.ProtoICMP:
		if ip.Version == 4 {
			s.handleICMP4(ip)
		}
	default:
		tun.Metrics.Unsupported.Add(1)
	}
}

// routable filters destinations that must never be relayed.
func (f *family) routable(dst netip.Addr) bool {
	if dst.IsUnspecified() || dst.IsMulticast() || dst.IsLoopback() || dst.IsLinkLocalMulticast() {
		return false
	}
	if dst.Is4() {
		if dst == netip.AddrFrom4([4]byte{255, 255, 255, 255}) || dst == f.broadcast {
			return false
		}
	}
	return true
}

func (s *Stack) nextIPID() uint16 {
	return uint16(s.ipID.Add(1))
}

// write hands a packet to the device. Errors are reported, rate-limited.
func (s *Stack) write(pkt []byte) error {
	_, err := s.device.Write(pkt)
	if err != nil && s.ctx.Err() == nil && !errors.Is(err, os.ErrClosed) {
		now := monoNanos()
		last := s.lastWriteErr.Load()
		if now-last >= int64(errorReportInterval) && s.lastWriteErr.CompareAndSwap(last, now) {
			s.warn(fmt.Errorf("stack: device write: %w", err))
		}
	}
	return err
}

func (s *Stack) resolveProcess(network string, src, dst netip.AddrPort) string {
	if s.process == nil {
		return ""
	}
	path, err := s.process.Resolve(network, src, dst)
	if err != nil {
		return ""
	}
	return path
}

func (s *Stack) janitor() {
	defer s.wg.Done()
	defer s.containFatal("janitor")
	ticker := time.NewTicker(janitorInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case now := <-ticker.C:
			for _, fam := range s.families() {
				fam.nat.sweep(now)
			}
		}
	}
}

func (s *Stack) fail(err error) {
	if s.opts.OnError != nil {
		s.opts.OnError(err)
	}
}

func (s *Stack) warn(err error) {
	if s.opts.OnWarn != nil {
		s.opts.OnWarn(err)
	}
}

func (s *Stack) debugf(format string, args ...any) {
	if s.opts.Debugf != nil {
		s.opts.Debugf(format, args...)
	}
}
