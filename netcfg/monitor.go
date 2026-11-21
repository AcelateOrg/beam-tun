package netcfg

import (
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

const monitorInterval = 4 * time.Second

// Monitor watches the host interfaces and reports when the underlying
// network changes, for example when the machine moves between Wi-Fi and
// Ethernet or a link goes down. The tunnel routes and DNS entries are
// volatile in that situation and have to be installed again.
type Monitor struct {
	exclude       string
	excludePrefix netip.Prefix
	onChange      func(prev, curr string)

	stopOnce sync.Once
	stop     chan struct{}
	done     chan struct{}
}

// NewMonitor starts watching for network changes. The tunnel itself is
// ignored so that it coming up - or being reconfigured by a reapply - does
// not look like a network change and trigger another reapply. It is matched
// both by name and by excludePrefix: the name the adapter is created with is
// not always the name the OS reports back, and missing the tunnel here turns
// reapply into a self-feeding loop. Callbacks are serialized on a single
// goroutine, so onChange may block.
func NewMonitor(exclude string, excludePrefix netip.Prefix, onChange func(prev, curr string)) *Monitor {
	m := &Monitor{
		exclude:       strings.ToLower(exclude),
		excludePrefix: excludePrefix,
		onChange:      onChange,
		stop:          make(chan struct{}),
		done:          make(chan struct{}),
	}
	go m.run()
	return m
}

func (m *Monitor) Close() {
	if m == nil {
		return
	}
	m.stopOnce.Do(func() { close(m.stop) })
	<-m.done
}

func (m *Monitor) run() {
	defer close(m.done)

	ticker := time.NewTicker(monitorInterval)
	defer ticker.Stop()

	previous := m.fingerprint()
	for {
		select {
		case <-m.stop:
			return
		case <-ticker.C:
		}

		current := m.fingerprint()
		if current == previous || current == "" {
			continue
		}
		changedFrom := previous
		previous = current

		select {
		case <-m.stop:
			return
		default:
		}
		m.notify(changedFrom, current)
	}
}

// notify runs the callback; a panic in it costs this one notification, not
// the monitor (and not the process the tunnel lives in).
func (m *Monitor) notify(prev, curr string) {
	if m.onChange == nil {
		return
	}
	defer func() { _ = recover() }()
	m.onChange(prev, curr)
}

// fingerprint describes the usable non-tunnel interfaces and their
// addresses. An empty result means the interfaces could not be read and is
// treated as "no change" to avoid pointless reconfiguration.
func (m *Monitor) fingerprint() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}

	entries := make([]string, 0, len(interfaces))
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		lowerName := strings.ToLower(iface.Name)
		if m.exclude != "" && lowerName == m.exclude {
			continue
		}
		// Переходные IPv6-интерфейсы (Teredo/ISATAP/6to4) флапают при подъёме
		// туннеля и провоцируют ложные «network changed» -> лишний reapply
		// маршрутов/DNS посреди сессии. Они туннель не несут — игнорируем.
		if isTransitionInterface(lowerName) {
			continue
		}
		addrs, addrErr := iface.Addrs()
		if addrErr != nil {
			continue
		}
		if m.holdsExcludedPrefix(addrs) {
			continue
		}
		values := make([]string, 0, len(addrs))
		for _, addr := range addrs {
			values = append(values, addr.String())
		}
		sort.Strings(values)
		entries = append(entries, iface.Name+"="+strings.Join(values, ","))
	}
	sort.Strings(entries)
	return strings.Join(entries, "|")
}

// isTransitionInterface reports whether the interface is an IPv6 transition
// tunnel (Teredo/ISATAP/6to4) rather than a real network interface.
func isTransitionInterface(lowerName string) bool {
	return strings.Contains(lowerName, "teredo") ||
		strings.Contains(lowerName, "isatap") ||
		strings.Contains(lowerName, "6to4")
}

// holdsExcludedPrefix reports whether these addresses belong to the tunnel.
func (m *Monitor) holdsExcludedPrefix(addrs []net.Addr) bool {
	if !m.excludePrefix.IsValid() {
		return false
	}
	for _, addr := range addrs {
		prefix, err := netip.ParsePrefix(addr.String())
		if err != nil {
			continue
		}
		if m.excludePrefix.Contains(prefix.Addr()) {
			return true
		}
	}
	return false
}
