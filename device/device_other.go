//go:build !windows

package device

// device_other.go — TUN adapter for non-Windows platforms on top of
// wireguard-go (wgtun.Device). Windows uses device_windows.go, which owns the
// WinTun session directly and applies bounded backpressure.

import (
	"fmt"
	"sync"

	wgtun "golang.zx2c4.com/wireguard/tun"

	"beam-tun"
)

// wgOffset is the headroom wireguard-go needs in front of every packet: the
// 4-byte AF header on darwin/BSD and the 10-byte virtio-net header on Linux
// with offloads. Packets handed to and returned from the engine start at 0.
const wgOffset = 16

var (
	_ tun.Device      = (*osDevice)(nil)
	_ tun.BatchReader = (*osDevice)(nil)
	_ tun.BatchWriter = (*osDevice)(nil)
)

type osDevice struct {
	device wgtun.Device
	batch  int
	mtu    int
	name   string

	readMu  sync.Mutex
	bufs    [][]byte
	sizes   []int
	pending int
	cursor  int

	writeMu  sync.Mutex
	scratch  [][]byte
	writeBuf [][]byte

	closeOnce sync.Once
}

// Prepare is a no-op: creating a TUN interface here is cheap and it lives
// only as long as its file descriptor.
func Prepare(string) error { return nil }

// Release is a no-op, see Prepare.
func Release() {}

// Open creates the TUN interface.
func Open(name string, mtu int) (tun.Device, error) {
	if name == "" {
		return nil, fmt.Errorf("tun: interface name is required")
	}
	mtu = tun.ClampMTU(mtu)

	// System preconditions (Linux: tun module + CAP_NET_ADMIN) give a clear
	// error instead of a raw errno from the driver. No-op elsewhere.
	if err := preflightTun(); err != nil {
		return nil, err
	}

	dev, err := wgtun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("tun: create interface %q: %w", name, err)
	}

	return wrap(dev, name, mtu), nil
}

// wrap adapts a wireguard-go device to tun.Device with pooled batch buffers.
func wrap(dev wgtun.Device, name string, mtu int) *osDevice {
	actualMTU, err := dev.MTU()
	if err != nil || actualMTU <= 0 || actualMTU > mtu {
		actualMTU = mtu
	}
	actualName, nameErr := dev.Name()
	if nameErr != nil || actualName == "" {
		actualName = name
	}

	batch := dev.BatchSize()
	if batch <= 0 {
		batch = 1
	}

	d := &osDevice{
		device:   dev,
		mtu:      actualMTU,
		name:     actualName,
		batch:    batch,
		bufs:     make([][]byte, batch),
		sizes:    make([]int, batch),
		scratch:  make([][]byte, 0, batch),
		writeBuf: make([][]byte, 0, batch),
	}
	for i := range d.bufs {
		d.bufs[i] = make([]byte, wgOffset+actualMTU+tun.OffsetHeadroom)
	}
	return d
}

func (d *osDevice) Name() string { return d.name }

func (d *osDevice) MTU() int { return d.mtu }

// BatchSize — how many packets the adapter moves per call.
func (d *osDevice) BatchSize() int { return d.batch }

// ReadBatch reads a batch of packets; each lands at bufs[i][:sizes[i]].
func (d *osDevice) ReadBatch(bufs [][]byte, sizes []int) (int, error) {
	d.readMu.Lock()
	defer d.readMu.Unlock()

	// Drain what is left of a batch collected by the single-packet Read.
	if d.cursor < d.pending {
		n := 0
		for d.cursor < d.pending && n < len(bufs) {
			size := d.sizes[d.cursor]
			if size <= len(bufs[n]) {
				sizes[n] = copy(bufs[n], d.bufs[d.cursor][wgOffset:wgOffset+size])
				n++
			}
			d.cursor++
		}
		if n > 0 {
			return n, nil
		}
	}

	for i := range bufs {
		if len(bufs[i]) <= wgOffset {
			return 0, fmt.Errorf("tun: read buffer of %d bytes is too small", len(bufs[i]))
		}
	}
	n, err := d.device.Read(bufs, sizes, wgOffset)
	for i := 0; i < n; i++ {
		copy(bufs[i], bufs[i][wgOffset:wgOffset+sizes[i]])
	}
	return n, err
}

// WriteBatch hands a batch of packets to the adapter in one call.
func (d *osDevice) WriteBatch(bufs [][]byte) error {
	if len(bufs) == 0 {
		return nil
	}
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	if _, err := d.device.Write(d.stage(bufs...), wgOffset); err != nil {
		return err
	}
	tun.Metrics.PacketsOut.Add(uint64(len(bufs)))
	return nil
}

func (d *osDevice) Read(buf []byte) (int, error) {
	d.readMu.Lock()
	defer d.readMu.Unlock()

	for d.cursor >= d.pending {
		n, err := d.device.Read(d.bufs, d.sizes, wgOffset)
		if n == 0 && err != nil {
			return 0, err
		}
		d.pending = n
		d.cursor = 0
	}

	index := d.cursor
	d.cursor++

	size := d.sizes[index]
	if size > len(buf) {
		return 0, fmt.Errorf("tun: packet of %d bytes exceeds buffer of %d", size, len(buf))
	}
	return copy(buf, d.bufs[index][wgOffset:wgOffset+size]), nil
}

func (d *osDevice) Write(buf []byte) (int, error) {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	if _, err := d.device.Write(d.stage(buf), wgOffset); err != nil {
		return 0, err
	}
	tun.Metrics.PacketsOut.Add(1)
	return len(buf), nil
}

// stage copies packets into reusable buffers with wgOffset bytes of headroom:
// wireguard-go writes its own header in front of the packet and may coalesce
// packets in place, so caller buffers are never handed over. Called under
// writeMu.
func (d *osDevice) stage(pkts ...[]byte) [][]byte {
	for len(d.scratch) < len(pkts) {
		d.scratch = append(d.scratch, nil)
	}
	d.writeBuf = d.writeBuf[:0]
	for i, p := range pkts {
		need := wgOffset + len(p)
		if cap(d.scratch[i]) < need {
			d.scratch[i] = make([]byte, need, max(need, wgOffset+d.mtu+tun.OffsetHeadroom))
		}
		b := d.scratch[i][:need]
		copy(b[wgOffset:], p)
		d.writeBuf = append(d.writeBuf, b)
	}
	return d.writeBuf
}

func (d *osDevice) Close() error {
	var err error
	d.closeOnce.Do(func() {
		err = d.device.Close()
	})
	return err
}
