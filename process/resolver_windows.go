//go:build windows

package process

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strconv"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"beam-tun"
)

var (
	iphlpapi                = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTCPTable = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUDPTable = iphlpapi.NewProc("GetExtendedUdpTable")
)

const (
	tcpTableOwnerPIDAll = 5
	udpTableOwnerPID    = 1

	afInet  = 2
	afInet6 = 23

	pathCacheTTL = 30 * time.Second

	// A burst of new connections (a single page load is easily dozens) used
	// to mean one full connection-table enumeration each. The table barely
	// changes within a few hundred milliseconds, so a short cache removes
	// almost all of those syscalls; a miss still forces a fresh read.
	tableCacheTTL = 250 * time.Millisecond

	// When the owner is not in a table fetched after the flow was seen, the
	// socket may still be settling (TIME_WAIT row of a reused port reports
	// PID 0, QUIC sockets appear a moment late). A few short retries are far
	// cheaper than silently routing the app by the default rules.
	lookupRetries = 4
	lookupBackoff = 15 * time.Millisecond
)

type resolver struct {
	mu     sync.Mutex
	cache  map[uint32]pathCacheEntry
	buf    []byte
	tables map[string]tableCacheEntry
}

type tableCacheEntry struct {
	rows    []tableRow
	expires time.Time
	fetched time.Time
}

type pathCacheEntry struct {
	path    string
	expires time.Time
}

// NewResolver returns a resolver backed by the IP Helper connection tables.
func NewResolver() tun.ProcessResolver {
	return &resolver{
		cache:  make(map[uint32]pathCacheEntry),
		tables: make(map[string]tableCacheEntry),
	}
}

func (r *resolver) Resolve(network string, source, destination netip.AddrPort) (string, error) {
	family := uint32(afInet)
	if source.Addr().Is6() && !source.Addr().Is4In6() {
		family = afInet6
	}

	pid, err := r.findOwner(network, family, source)
	if err != nil {
		return "", err
	}
	return r.pathOf(pid)
}

func (r *resolver) findOwner(network string, family uint32, addr netip.AddrPort) (uint32, error) {
	// The flow already exists, so its socket is in every table fetched from
	// now on. A cached snapshot is trusted only for an exact owner match;
	// a wildcard fallback from it may belong to an older socket.
	seen := time.Now()
	if pid, exact, err := r.lookup(network, family, addr, time.Time{}); err == nil && exact {
		return pid, nil
	}

	var lastErr error = ErrNotFound
	for attempt := 0; attempt < lookupRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * lookupBackoff)
		}
		pid, _, err := r.lookup(network, family, addr, seen)
		if err == nil {
			return pid, nil
		}
		lastErr = err
		if !errors.Is(err, ErrNotFound) {
			return 0, err
		}
		// Later attempts must see a table newer than the previous one.
		seen = time.Now()
	}
	return 0, lastErr
}

// lookup finds the owner of addr in a table fetched no earlier than
// notBefore (zero accepts the short-lived cache). exact reports whether
// the match was on the exact local address rather than a wildcard bind.
func (r *resolver) lookup(network string, family uint32, addr netip.AddrPort, notBefore time.Time) (uint32, bool, error) {
	table, err := r.queryTable(network, family, notBefore)
	if err != nil {
		return 0, false, err
	}

	port := addr.Port()
	ip := addr.Addr().Unmap()

	// Exact local address first; a socket bound to the wildcard address
	// (typical for UDP: games, voice) is the only acceptable fallback. Any
	// other address with the same port belongs to a different socket, and
	// attributing the flow to it would route the wrong app.
	var fallback uint32
	var haveFallback bool
	for _, row := range table {
		// PID 0 is a TIME_WAIT leftover of a closed socket on a reused
		// port; it never owns a live flow.
		if row.port != port || row.pid == 0 {
			continue
		}
		if row.addr == ip {
			return row.pid, true, nil
		}
		if !haveFallback && row.addr.IsUnspecified() {
			fallback = row.pid
			haveFallback = true
		}
	}
	if haveFallback {
		return fallback, false, nil
	}
	return 0, false, ErrNotFound
}

type tableRow struct {
	addr netip.Addr
	port uint16
	pid  uint32
}

func (r *resolver) queryTable(network string, family uint32, notBefore time.Time) ([]tableRow, error) {
	proc := procGetExtendedTCPTable
	class := uintptr(tcpTableOwnerPIDAll)
	if network == "udp" {
		proc = procGetExtendedUDPTable
		class = uintptr(udpTableOwnerPID)
	}

	key := network + ":" + strconv.FormatUint(uint64(family), 10)
	now := time.Now()

	r.mu.Lock()
	defer r.mu.Unlock()

	if entry, ok := r.tables[key]; ok {
		if notBefore.IsZero() && entry.expires.After(now) {
			return entry.rows, nil
		}
		// A table fetched (by a concurrent lookup) after this flow was
		// seen already contains it: collapses bursts into one syscall.
		if !notBefore.IsZero() && !entry.fetched.Before(notBefore) {
			return entry.rows, nil
		}
	}
	now = time.Now()

	if len(r.buf) == 0 {
		r.buf = make([]byte, 32*1024)
	}

	for attempt := 0; attempt < 4; attempt++ {
		size := uint32(len(r.buf))
		ret, _, _ := proc.Call(
			uintptr(unsafe.Pointer(&r.buf[0])),
			uintptr(unsafe.Pointer(&size)),
			0,
			uintptr(family),
			class,
			0,
		)
		switch ret {
		case 0:
			rows := decodeTable(r.buf[:size], network, family)
			if r.tables == nil {
				r.tables = make(map[string]tableCacheEntry)
			}
			r.tables[key] = tableCacheEntry{rows: rows, expires: now.Add(tableCacheTTL), fetched: now}
			return rows, nil
		case uintptr(windows.ERROR_INSUFFICIENT_BUFFER):
			r.buf = make([]byte, size+4096)
		default:
			return nil, windows.Errno(ret)
		}
	}
	return nil, errors.New("tun: connection table kept growing")
}

func decodeTable(buf []byte, network string, family uint32) []tableRow {
	if len(buf) < 4 {
		return nil
	}
	count := binary.LittleEndian.Uint32(buf[:4])
	body := buf[4:]

	var stride, addrOffset, addrLen, portOffset, pidOffset int
	switch {
	case network == "tcp" && family == afInet:
		stride, addrOffset, addrLen, portOffset, pidOffset = 24, 4, 4, 8, 20
	case network == "tcp" && family == afInet6:
		stride, addrOffset, addrLen, portOffset, pidOffset = 56, 0, 16, 20, 52
	case network == "udp" && family == afInet:
		stride, addrOffset, addrLen, portOffset, pidOffset = 12, 0, 4, 4, 8
	default:
		stride, addrOffset, addrLen, portOffset, pidOffset = 28, 0, 16, 20, 24
	}

	rows := make([]tableRow, 0, count)
	for i := 0; i < int(count); i++ {
		start := i * stride
		if start+stride > len(body) {
			break
		}
		row := body[start : start+stride]

		addr, ok := netip.AddrFromSlice(row[addrOffset : addrOffset+addrLen])
		if !ok {
			continue
		}
		rows = append(rows, tableRow{
			addr: addr.Unmap(),
			port: binary.BigEndian.Uint16(row[portOffset : portOffset+2]),
			pid:  binary.LittleEndian.Uint32(row[pidOffset : pidOffset+4]),
		})
	}
	return rows
}

func (r *resolver) pathOf(pid uint32) (string, error) {
	now := time.Now()

	r.mu.Lock()
	if entry, ok := r.cache[pid]; ok && entry.expires.After(now) {
		r.mu.Unlock()
		return entry.path, nil
	}
	r.mu.Unlock()

	path, err := queryProcessPath(pid)
	if err != nil {
		return "", err
	}

	r.mu.Lock()
	r.cache[pid] = pathCacheEntry{path: path, expires: now.Add(pathCacheTTL)}
	if len(r.cache) > 512 {
		r.cache = make(map[uint32]pathCacheEntry)
	}
	r.mu.Unlock()

	return path, nil
}

func queryProcessPath(pid uint32) (string, error) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(handle)

	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(handle, 0, &buf[0], &size); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:size]), nil
}
