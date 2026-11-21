package stack

import (
	"context"
	"fmt"
	"net/netip"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	gstack "gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"

	"beam-tun"
	"beam-tun/internal/packet"
)

// userspaceTCP terminates TCP inside a gVisor netstack instead of the host
// kernel. It is used where the in-place NAT cannot work because the platform
// owns the routing of the tunnel's own replies (Android: the kernel listener's
// SYN-ACKs never come back through the VPN interface). UDP and ICMP stay on
// the regular userspace paths of the mixed engine.
type userspaceTCP struct {
	stack    *gstack.Stack
	endpoint *channel.Endpoint
	cancel   context.CancelFunc
}

const (
	gvisorNIC tcpip.NICID = 1
	// gvisorQueue is the number of outbound packets buffered between the
	// netstack and the device writer; overflow is dropped and retransmitted.
	gvisorQueue = 1024
	// gvisorMaxInFlight caps handshakes in progress (SYN floods from a
	// misbehaving app must not exhaust memory).
	gvisorMaxInFlight = 2048

	gvisorBufMax = 4 << 20
)

func newUserspaceTCP(s *Stack) (*userspaceTCP, error) {
	ep := channel.New(gvisorQueue, uint32(s.mtu), "")
	// Packets come from the local TUN device with valid checksums.
	ep.LinkEPCapabilities |= gstack.CapabilityRXChecksumOffload

	st := gstack.New(gstack.Options{
		NetworkProtocols:   []gstack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []gstack.TransportProtocolFactory{tcp.NewProtocol},
	})
	fail := func(what string, err tcpip.Error) (*userspaceTCP, error) {
		st.Close()
		return nil, fmt.Errorf("stack: gvisor %s: %s", what, err)
	}
	if err := st.CreateNIC(gvisorNIC, ep); err != nil {
		return fail("create nic", err)
	}
	// Accept every destination: the netstack impersonates the whole internet.
	if err := st.SetPromiscuousMode(gvisorNIC, true); err != nil {
		return fail("promiscuous mode", err)
	}
	if err := st.SetSpoofing(gvisorNIC, true); err != nil {
		return fail("spoofing", err)
	}
	st.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: gvisorNIC},
		{Destination: header.IPv6EmptySubnet, NIC: gvisorNIC},
	})

	sack := tcpip.TCPSACKEnabled(true)
	_ = st.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)
	moderate := tcpip.TCPModerateReceiveBufferOption(true)
	_ = st.SetTransportProtocolOption(tcp.ProtocolNumber, &moderate)
	// RACK/TLP stalls connections under load in this netstack.
	recovery := tcpip.TCPRecovery(0)
	_ = st.SetTransportProtocolOption(tcp.ProtocolNumber, &recovery)
	rcv := tcpip.TCPReceiveBufferSizeRangeOption{Min: tcp.MinBufferSize, Default: tcp.DefaultReceiveBufferSize, Max: gvisorBufMax}
	_ = st.SetTransportProtocolOption(tcp.ProtocolNumber, &rcv)
	snd := tcpip.TCPSendBufferSizeRangeOption{Min: tcp.MinBufferSize, Default: tcp.DefaultSendBufferSize, Max: gvisorBufMax}
	_ = st.SetTransportProtocolOption(tcp.ProtocolNumber, &snd)

	forwarder := tcp.NewForwarder(st, 0, gvisorMaxInFlight, func(r *tcp.ForwarderRequest) {
		// Runs on its own goroutine (the forwarder spawns one per SYN).
		defer s.contain("tcp flow")
		id := r.ID()
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			r.Complete(true)
			return
		}
		r.Complete(false)
		conn := gonet.NewTCPConn(&wq, ep)
		src := netip.AddrPortFrom(addrOf(id.RemoteAddress), id.RemotePort)
		dst := netip.AddrPortFrom(addrOf(id.LocalAddress), id.LocalPort)
		s.serveUserspaceTCP(conn, src, dst)
	})
	st.SetTransportProtocolHandler(tcp.ProtocolNumber, forwarder.HandlePacket)

	ctx, cancel := context.WithCancel(s.ctx)
	u := &userspaceTCP{stack: st, endpoint: ep, cancel: cancel}
	s.wg.Add(1)
	go u.writeLoop(ctx, s)
	return u, nil
}

func addrOf(a tcpip.Address) netip.Addr {
	addr, _ := netip.AddrFromSlice(a.AsSlice())
	return addr.Unmap()
}

// inject hands one TCP packet read from the device to the netstack. The read
// buffer is reused by the caller, so the payload is copied.
func (u *userspaceTCP) inject(ip packet.IP) {
	proto := header.IPv4ProtocolNumber
	if ip.Version == 6 {
		proto = header.IPv6ProtocolNumber
	}
	pkt := gstack.NewPacketBuffer(gstack.PacketBufferOptions{
		Payload: buffer.MakeWithData(ip.Packet),
	})
	u.endpoint.InjectInbound(proto, pkt)
	pkt.DecRef()
}

// writeLoop moves packets the netstack emits back to the device.
func (u *userspaceTCP) writeLoop(ctx context.Context, s *Stack) {
	defer s.wg.Done()
	defer s.containFatal("gvisor write loop")
	for {
		pkt := u.endpoint.ReadContext(ctx)
		if pkt == nil {
			return
		}
		view := pkt.ToView()
		pkt.DecRef()
		if s.write(view.AsSlice()) == nil {
			tun.Metrics.PacketsOut.Add(1)
		}
		view.Release()
	}
}

func (u *userspaceTCP) close() {
	u.cancel()
	u.endpoint.Close()
	u.stack.Close()
	u.stack.Wait()
}

func (s *Stack) serveUserspaceTCP(conn *gonet.TCPConn, src, dst netip.AddrPort) {
	tun.Metrics.TCPActive.Add(1)
	defer tun.Metrics.TCPActive.Add(-1)
	defer conn.Close()

	meta := &tun.Metadata{
		Network:     "tcp",
		Source:      src,
		Destination: dst,
	}
	meta.ProcessPath = s.resolveProcess("tcp", src, dst)
	s.handler.HandleTCP(conn, meta)
}
