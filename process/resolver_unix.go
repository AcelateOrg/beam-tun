//go:build (linux && !android) || darwin

package process

import (
	"errors"
	"net/netip"
	"sync"
	"time"

	"beam-tun"
)

const (
	pathCacheTTL  = 30 * time.Second
	tableCacheTTL = 250 * time.Millisecond

	// Same reasoning as on Windows: a freshly opened socket can show up in
	// the kernel tables a moment after its first packet reached the TUN.
	lookupRetries = 4
	lookupBackoff = 15 * time.Millisecond
)

// tableRow is one local socket. owner is platform specific: the socket
// inode on Linux, the owning PID on macOS.
type tableRow struct {
	addr  netip.Addr
	port  uint16
	owner uint64
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

type resolver struct {
	mu     sync.Mutex
	tables map[string]tableCacheEntry
	paths  map[uint32]pathCacheEntry
	sys    sysState
}

// NewResolver returns a resolver backed by the kernel socket tables.
func NewResolver() tun.ProcessResolver {
	return &resolver{
		tables: make(map[string]tableCacheEntry),
		paths:  make(map[uint32]pathCacheEntry),
	}
}

func (r *resolver) Resolve(network string, source, _ netip.AddrPort) (string, error) {
	if network != "tcp" && network != "udp" {
		return "", ErrNotFound
	}
	seen := time.Now()
	owner, err := r.findOwner(network, source)
	if err != nil {
		return "", err
	}
	pid, err := r.pidOf(owner, seen)
	if err != nil {
		return "", err
	}
	return r.pathOf(pid)
}

func (r *resolver) findOwner(network string, addr netip.AddrPort) (uint64, error) {
	seen := time.Now()
	if owner, exact, err := r.lookup(network, addr, time.Time{}); err == nil && exact {
		return owner, nil
	}

	var lastErr error = ErrNotFound
	for attempt := 0; attempt < lookupRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * lookupBackoff)
		}
		owner, _, err := r.lookup(network, addr, seen)
		if err == nil {
			return owner, nil
		}
		lastErr = err
		if !errors.Is(err, ErrNotFound) {
			return 0, err
		}
		seen = time.Now()
	}
	return 0, lastErr
}

// lookup prefers the exact local address; a wildcard bind (typical for
// UDP) is the only acceptable fallback, a v4 one first for v4 flows.
func (r *resolver) lookup(network string, addr netip.AddrPort, notBefore time.Time) (uint64, bool, error) {
	table, err := r.queryTable(network, notBefore)
	if err != nil {
		return 0, false, err
	}

	port := addr.Port()
	ip := addr.Addr().Unmap()

	var fallback uint64
	fallbackRank := 0
	for _, row := range table {
		if row.port != port || row.owner == 0 {
			continue
		}
		if row.addr == ip {
			return row.owner, true, nil
		}
		if !row.addr.IsUnspecified() {
			continue
		}
		rank := 1
		if row.addr.Is4() == ip.Is4() {
			rank = 2
		}
		if rank > fallbackRank {
			fallback, fallbackRank = row.owner, rank
		}
	}
	if fallbackRank > 0 {
		return fallback, false, nil
	}
	return 0, false, ErrNotFound
}

func (r *resolver) queryTable(network string, notBefore time.Time) ([]tableRow, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	if entry, ok := r.tables[network]; ok {
		if notBefore.IsZero() && entry.expires.After(now) {
			return entry.rows, nil
		}
		if !notBefore.IsZero() && !entry.fetched.Before(notBefore) {
			return entry.rows, nil
		}
	}

	fetched := time.Now()
	rows, err := fetchTable(network)
	if err != nil {
		return nil, err
	}
	r.tables[network] = tableCacheEntry{rows: rows, expires: fetched.Add(tableCacheTTL), fetched: fetched}
	return rows, nil
}

func (r *resolver) pathOf(pid uint32) (string, error) {
	now := time.Now()

	r.mu.Lock()
	if entry, ok := r.paths[pid]; ok && entry.expires.After(now) {
		r.mu.Unlock()
		return entry.path, nil
	}
	r.mu.Unlock()

	path, err := queryProcessPath(pid)
	if err != nil {
		return "", err
	}
	if path == "" {
		return "", ErrNotFound
	}

	r.mu.Lock()
	if len(r.paths) > 512 {
		r.paths = make(map[uint32]pathCacheEntry)
	}
	r.paths[pid] = pathCacheEntry{path: path, expires: now.Add(pathCacheTTL)}
	r.mu.Unlock()

	return path, nil
}
