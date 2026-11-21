// Package dialer opens sockets pinned to the physical network interface, so
// that traffic of bypassed apps (and the engine's own relays) leaves the host
// directly instead of re-entering the tunnel that owns the default route.
package dialer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"
)

// ErrNoInterface is returned while no physical interface is known.
var ErrNoInterface = errors.New("dialer: physical interface is not known")

const (
	defaultDialTimeout = 15 * time.Second
	keepAlive          = 30 * time.Second
)

// Interface is the physical interface sockets are bound to.
type Interface struct {
	Name  string
	Index int
	// Inet4 / Inet6 are the first global unicast addresses of the interface.
	Inet4 netip.Addr
	Inet6 netip.Addr
}

// Direct dials through the physical interface. The zero value is not usable;
// create it with New. Safe for concurrent use; SetInterface may be called at
// any time (network change) and affects new sockets only.
type Direct struct {
	mu    sync.RWMutex
	iface Interface
}

func New() *Direct { return &Direct{} }

// SetInterface resolves name and makes it the binding target. An empty name
// clears the binding (the dialer then reports ErrNoInterface).
func (d *Direct) SetInterface(name string) error {
	if name == "" {
		d.mu.Lock()
		d.iface = Interface{}
		d.mu.Unlock()
		return nil
	}
	iface, err := resolveInterface(name)
	if err != nil {
		return fmt.Errorf("dialer: resolve interface %q: %w", name, err)
	}
	d.mu.Lock()
	d.iface = iface
	d.mu.Unlock()
	return nil
}

// pickAddress records addr as the interface's first usable IPv4/IPv6 address.
func (iface *Interface) pickAddress(addr netip.Addr) {
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() && !addr.IsPrivate() {
		return
	}
	if addr.Is4() && !iface.Inet4.IsValid() {
		iface.Inet4 = addr
	}
	if addr.Is6() && !addr.IsLinkLocalUnicast() && !iface.Inet6.IsValid() {
		iface.Inet6 = addr
	}
}

// Interface returns the current binding target.
func (d *Direct) Interface() Interface {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.iface
}

// Ready reports whether a physical interface is known.
func (d *Direct) Ready() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.iface.Index > 0
}

// Inet4 is the IPv4 source address of the physical interface (used to send
// ICMP echo requests directly).
func (d *Direct) Inet4() netip.Addr {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.iface.Inet4
}

func (d *Direct) control() (func(network, address string, c syscall.RawConn) error, error) {
	iface := d.Interface()
	if iface.Index <= 0 {
		return nil, ErrNoInterface
	}
	return func(network, address string, c syscall.RawConn) error {
		var bindErr error
		if err := c.Control(func(fd uintptr) {
			bindErr = bindToInterface(fd, network, iface)
		}); err != nil {
			return err
		}
		return bindErr
	}, nil
}

// DialContext opens a TCP or UDP connection through the physical interface.
func (d *Direct) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	control, err := d.control()
	if err != nil {
		return nil, err
	}
	dialer := net.Dialer{
		Timeout:   defaultDialTimeout,
		KeepAlive: keepAlive,
		Control:   control,
	}
	return dialer.DialContext(ctx, network, address)
}

// ListenPacket opens an unconnected UDP socket whose datagrams leave through
// the physical interface.
func (d *Direct) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	control, err := d.control()
	if err != nil {
		return nil, err
	}
	config := net.ListenConfig{Control: control}
	return config.ListenPacket(ctx, network, address)
}
