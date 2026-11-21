//go:build windows

package device

// device_windows.go — TUN adapter on top of a WinTun session owned directly.
//
// Reads come from a single engine goroutine (readMu only guards against
// misuse). Writes come concurrently from the engine read loop (TCP NAT
// write-back), UDP/ICMP reply goroutines: WinTun AllocateSendPacket/SendPacket
// are thread-safe, so there is no global write lock and one slow writer never
// holds up the others (no head-of-line blocking between flows).

import (
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"

	"beam-tun"
)

// Bounded backpressure on a full send ring: wait a little (the host drains the
// ring very fast), then drop. Latency-sensitive packets (UDP, ICMP) get a
// longer budget than bulk TCP, which recovers from a loss by itself.
const (
	sendBackoffMin        = 50 * time.Microsecond
	sendBackoffMax        = 500 * time.Microsecond
	sendBackoffBudgetPrio = 3 * time.Millisecond
	sendBackoffBudgetBulk = 500 * time.Microsecond
)

// ringCapacity — WinTun ring size (8 MiB, the maximum useful value).
const ringCapacity = 0x800000

const tunnelType = "Beam"

// readBatchSize — how many packets one ReadBatch drains from the ring.
const readBatchSize = 128

// Adaptive spinning: when the adapter is hot (sustained packet rate), an empty
// ring is polled for a short while before parking on the read event. Waking
// from WaitForSingleObject costs tens of microseconds per wakeup, which under
// load adds straight to latency; when idle, no CPU is burnt at all.
const (
	rateWindow        = 50 * time.Millisecond
	hotPacketsPerRate = 1000 // ~20k packets/s
	spinDuration      = 40 * time.Microsecond
)

var (
	_ tun.Device      = (*osDevice)(nil)
	_ tun.BatchReader = (*osDevice)(nil)
	_ tun.BatchWriter = (*osDevice)(nil)
)

type osDevice struct {
	adapter  *wintun.Adapter
	session  wintun.Session
	readWait windows.Handle

	mtu   int
	name  string
	batch int

	// running counts in-flight reads/writes: Close waits for them before
	// ending the session so nobody touches WinTun after End().
	running sync.WaitGroup

	closeOnce sync.Once
	closed    atomic.Bool

	readMu sync.Mutex

	// Read-side rate estimation (guarded by readMu).
	rateStart time.Time
	rateCount int
	hot       bool
}

// Adapters outlive their sessions. Creating a WinTun adapter is a full PnP
// device install (0.5-2 s plus the wait for the network stack to register
// it), so it is done once per process: Close ends only the session and the
// next Open starts a new one on the same adapter in milliseconds. The
// adapter keeps its interface settings (IPv6 off, MTU) between sessions; the
// network layer removes its address and routes on every disconnect.
var (
	adaptersMu sync.Mutex
	adapters   = map[string]*wintun.Adapter{}
)

// Prepare creates the adapter ahead of the first connect (app start, in the
// background), so pressing Connect only starts a session on it. A leftover
// adapter of a previous run is adopted. No-op when it is already prepared.
func Prepare(name string) error {
	if name == "" {
		return fmt.Errorf("tun: interface name is required")
	}
	adaptersMu.Lock()
	defer adaptersMu.Unlock()
	if adapters[name] != nil {
		return nil
	}
	if existing, err := wintun.OpenAdapter(name); err == nil {
		// Adopted without a session probe: a broken or busy one is sorted
		// out by Open.
		adapters[name] = existing
		return nil
	}
	adapter, err := createAdapter(name)
	if err != nil {
		return err
	}
	adapters[name] = adapter
	return nil
}

// createAdapter creates the adapter under a stable GUID, so Windows does not
// create a new network profile (NLA) on every start.
func createAdapter(name string) (*wintun.Adapter, error) {
	adapter, err := wintun.CreateAdapter(name, tunnelType, deterministicGUID(name))
	if err == nil {
		return adapter, nil
	}
	// A zombie device node holds the stable GUID: retry with a random one.
	guid, guidErr := windows.GenerateGUID()
	if guidErr != nil {
		return nil, fmt.Errorf("tun: create adapter %q: %w", name, err)
	}
	if adapter, err = wintun.CreateAdapter(name, tunnelType, &guid); err != nil {
		return nil, fmt.Errorf("tun: create adapter %q: %w", name, err)
	}
	return adapter, nil
}

// Open creates (or reuses) the WinTun adapter and starts a session on it.
func Open(name string, mtu int) (tun.Device, error) {
	if name == "" {
		return nil, fmt.Errorf("tun: interface name is required")
	}
	mtu = tun.ClampMTU(mtu)
	if mtu > wintun.PacketSizeMax {
		mtu = wintun.PacketSizeMax
	}

	adaptersMu.Lock()
	defer adaptersMu.Unlock()

	if cached := adapters[name]; cached != nil {
		session, err := cached.StartSession(ringCapacity)
		if err == nil {
			return newOSDevice(cached, session, name, mtu), nil
		}
		if errors.Is(err, windows.ERROR_ALREADY_INITIALIZED) {
			return nil, fmt.Errorf("%w: %q", ErrAdapterBusy, name)
		}
		// The adapter broke (removed by the user, driver reset): drop it
		// and build a fresh one below.
		cached.Close()
		delete(adapters, name)
	}

	// A live adapter with this name may be left over from a previous run —
	// reuse it. CreateAdapter over a broken adapter with the same GUID waits
	// ~15s for the device query and fails.
	if existing, openErr := wintun.OpenAdapter(name); openErr == nil {
		session, sessErr := existing.StartSession(ringCapacity)
		if sessErr == nil {
			adapters[name] = existing
			return newOSDevice(existing, session, name, mtu), nil
		}
		existing.Close()
		// A live session means another process (typically a second Beam
		// build with the same adapter name) owns the adapter. Creating a
		// twin with the same name and address would stack two tunnels on
		// the default route: traffic bounces between them, latency
		// multiplies and pings die. Refuse instead.
		if errors.Is(sessErr, windows.ERROR_ALREADY_INITIALIZED) {
			return nil, fmt.Errorf("%w: %q", ErrAdapterBusy, name)
		}
	}

	adapter, err := createAdapter(name)
	if err != nil {
		return nil, err
	}

	session, err := adapter.StartSession(ringCapacity)
	if err != nil {
		adapter.Close()
		return nil, fmt.Errorf("tun: start session: %w", err)
	}
	adapters[name] = adapter
	return newOSDevice(adapter, session, name, mtu), nil
}

func newOSDevice(adapter *wintun.Adapter, session wintun.Session, name string, mtu int) *osDevice {
	return &osDevice{
		adapter:  adapter,
		session:  session,
		readWait: session.ReadWaitEvent(),
		mtu:      mtu,
		name:     name,
		batch:    readBatchSize,
	}
}

func (d *osDevice) Name() string { return d.name }

func (d *osDevice) MTU() int { return d.mtu }

func (d *osDevice) BatchSize() int { return d.batch }

// noteReceived updates the packet-rate estimate. Called under readMu.
func (d *osDevice) noteReceived(now time.Time, packets int) {
	if now.Sub(d.rateStart) >= rateWindow {
		d.hot = d.rateCount >= hotPacketsPerRate
		d.rateStart = now
		d.rateCount = 0
	}
	d.rateCount += packets
}

// ReadBatch drains up to len(bufs) packets. It blocks only while the ring is
// empty and nothing has been collected yet.
func (d *osDevice) ReadBatch(bufs [][]byte, sizes []int) (int, error) {
	d.running.Add(1)
	defer d.running.Done()
	d.readMu.Lock()
	defer d.readMu.Unlock()

	n := 0
	var spinStart time.Time
	for n < len(bufs) {
		if d.closed.Load() {
			if n > 0 {
				return n, nil
			}
			return 0, os.ErrClosed
		}
		packet, err := d.session.ReceivePacket()
		switch {
		case err == nil:
			// A packet larger than the buffer is skipped rather than truncated.
			if len(packet) <= len(bufs[n]) {
				sizes[n] = copy(bufs[n], packet)
				n++
			}
			d.session.ReleaseReceivePacket(packet)
		case errors.Is(err, windows.ERROR_NO_MORE_ITEMS):
			if n > 0 {
				d.noteReceived(time.Now(), n)
				return n, nil
			}
			if d.hot {
				now := time.Now()
				if spinStart.IsZero() {
					spinStart = now
				}
				if now.Sub(spinStart) < spinDuration {
					runtime.Gosched()
					continue
				}
			}
			if _, waitErr := windows.WaitForSingleObject(d.readWait, windows.INFINITE); waitErr != nil {
				return 0, fmt.Errorf("tun: wait read event: %w", waitErr)
			}
			// After a real park the adapter is idle by definition.
			spinStart = time.Time{}
			if time.Since(d.rateStart) >= rateWindow {
				d.hot = false
			}
		case errors.Is(err, windows.ERROR_HANDLE_EOF):
			return n, os.ErrClosed
		case errors.Is(err, windows.ERROR_INVALID_DATA):
			return n, errors.New("tun: receive ring corrupt")
		default:
			if n > 0 {
				return n, nil
			}
			return 0, fmt.Errorf("tun: receive: %w", err)
		}
	}
	d.noteReceived(time.Now(), n)
	return n, nil
}

// Read is the single-packet fallback of the Device interface.
func (d *osDevice) Read(buf []byte) (int, error) {
	bufs := [1][]byte{buf}
	sizes := [1]int{}
	for {
		n, err := d.ReadBatch(bufs[:], sizes[:])
		if n > 0 {
			return sizes[0], nil
		}
		if err != nil {
			return 0, err
		}
	}
}

// WriteBatch hands a batch of packets to the adapter. The ring-full budget is
// shared by the batch so a full ring never turns into a series of sleeps.
func (d *osDevice) WriteBatch(bufs [][]byte) error {
	if len(bufs) == 0 {
		return nil
	}
	d.running.Add(1)
	defer d.running.Done()

	var spent time.Duration
	for _, buf := range bufs {
		if err := d.writeOne(buf, &spent); err != nil {
			return err
		}
	}
	return nil
}

func (d *osDevice) Write(buf []byte) (int, error) {
	d.running.Add(1)
	defer d.running.Done()

	var spent time.Duration
	if err := d.writeOne(buf, &spent); err != nil {
		return 0, err
	}
	return len(buf), nil
}

// writeOne puts one IP packet into the send ring. On a full ring it retries
// with a short exponential backoff within the budget, then drops the packet.
// Non-nil is returned only on fatal states (device closed, allocation error).
func (d *osDevice) writeOne(buf []byte, spent *time.Duration) error {
	if len(buf) == 0 {
		return nil
	}
	if len(buf) > wintun.PacketSizeMax {
		tun.Metrics.Oversized.Add(1)
		return nil
	}

	budget := sendBackoffBudgetBulk
	if isPriorityPacket(buf) {
		budget = sendBackoffBudgetPrio
	}

	backoff := sendBackoffMin
	for {
		if d.closed.Load() {
			return os.ErrClosed
		}
		packet, err := d.session.AllocateSendPacket(len(buf))
		if err == nil {
			copy(packet, buf)
			d.session.SendPacket(packet)
			tun.Metrics.PacketsOut.Add(1)
			return nil
		}
		if !errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			if errors.Is(err, windows.ERROR_HANDLE_EOF) {
				return os.ErrClosed
			}
			return fmt.Errorf("tun: allocate send packet: %w", err)
		}
		remaining := budget - *spent
		if remaining <= 0 {
			tun.Metrics.RingFullDrops.Add(1)
			return nil
		}
		sleep := min(backoff, remaining)
		time.Sleep(sleep)
		*spent += sleep
		backoff = min(backoff*2, sendBackoffMax)
	}
}

// isPriorityPacket — UDP (voice, games, DNS) and ICMP: latency matters more
// than guaranteed delivery; bulk TCP is the opposite.
func isPriorityPacket(buf []byte) bool {
	switch buf[0] >> 4 {
	case 4:
		if len(buf) < 20 {
			return false
		}
		proto := buf[9]
		return proto == 17 || proto == 1
	case 6:
		if len(buf) < 40 {
			return false
		}
		proto := buf[6]
		return proto == 17 || proto == 58
	}
	return false
}

func (d *osDevice) Close() error {
	d.closeOnce.Do(func() {
		d.closed.Store(true)
		// Wake the reader if it is parked on the read event.
		if d.readWait != 0 {
			_ = windows.SetEvent(d.readWait)
		}
		d.running.Wait()
		// Only the session ends: the adapter is reused by the next Open.
		d.session.End()
	})
	return nil
}

// Release removes the adapters this process keeps between sessions. Call it
// on application exit, after the last session has been closed.
func Release() {
	adaptersMu.Lock()
	defer adaptersMu.Unlock()
	for name, adapter := range adapters {
		adapter.Close()
		delete(adapters, name)
	}
}

// deterministicGUID derives a stable adapter GUID from its name.
func deterministicGUID(name string) *windows.GUID {
	sum := md5.Sum([]byte("beam-tun\x00" + name))
	var g windows.GUID
	g.Data1 = binary.LittleEndian.Uint32(sum[0:4])
	g.Data2 = binary.LittleEndian.Uint16(sum[4:6])
	g.Data3 = binary.LittleEndian.Uint16(sum[6:8])
	copy(g.Data4[:], sum[8:16])
	return &g
}
