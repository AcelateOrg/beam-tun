package netcfg

// configure_windows.go — конфигурация адаптера на Windows через нативный
// IP Helper API (iphlpapi.dll): ни одного процесса netsh/PowerShell ни на
// подключении, ни на отключении.
//
// Что это дало относительно эпохи netsh:
//   - нет гонки «адаптер ещё не зарегистрирован» — API возвращает точные
//     коды (ERROR_NOT_FOUND / ERROR_OBJECT_ALREADY_EXISTS), а не текст,
//     который приходилось разбирать строками;
//   - нет спавнов процессов: подключение и отключение — микросекунды
//     ядерных вызовов вместо сотен миллисекунд на каждый netsh;
//   - IPv6 на адаптере глушится нативно (disableIPv6: без link-local, RD и
//     адресов), а IPv6 всего хоста (включая Teredo/6to4/ISATAP) режет WFP на
//     время сессии (firewall.AttachTunnel) — ни PowerShell, ни netsh, ни
//     системных настроек, переживающих Beam.

import (
	"fmt"
	"net/netip"
	"sync"
	"time"

	"beam-tun"
)

type windowsNetwork struct {
	mu      sync.Mutex
	name    string
	luid    uint64
	address netip.Prefix
	dns     netip.Addr
	mtu     int

	gateway     netip.Addr
	gatewayLuid uint64
	bypass      map[string]struct{}
	closed      bool
}

// Configure assigns the address, MTU, DNS and routes to the adapter.
func Configure(cfg Config) (Network, error) {
	if cfg.Name == "" || !cfg.Address.IsValid() {
		return nil, fmt.Errorf("tun: incomplete network configuration")
	}

	mtu := tun.ClampMTU(cfg.MTU)

	n := &windowsNetwork{
		name:    cfg.Name,
		address: cfg.Address,
		dns:     cfg.DNS,
		mtu:     mtu,
		bypass:  make(map[string]struct{}),
	}
	if err := n.setupLocked(bypassPrefixes(cfg.Bypass)); err != nil {
		// Лучшее усилие по откату: не оставляем систему в полунастроенном
		// состоянии, если адрес/маршруты встали частично.
		_ = n.closeLocked()
		return nil, err
	}
	return n, nil
}

// LUID returns the adapter LUID: the firewall uses it to tell traffic through
// the tunnel apart from traffic around it.
func (n *windowsNetwork) LUID() uint64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.luid
}

// setupLocked устанавливает адрес, MTU, DNS, split-маршруты и bypass-маршруты
// нативными вызовами IP Helper API. Повторные попытки идемпотентны: delete
// несуществующего и create существующего доброкачественны.
func (n *windowsNetwork) setupLocked(prefixes []string) error {
	// Адаптер регистрируется в сетевом стеке асинхронно относительно
	// создания wintun-устройства — ждём появления LUID.
	luid, err := waitForAdapterLuid(n.name, 5*time.Second)
	if err != nil {
		return err
	}
	n.luid = luid

	var setupErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(300 * time.Millisecond)
		}
		if setupErr = n.applyLocked(prefixes); setupErr != nil {
			continue
		}
		if setupErr = verifyAddress(n.luid, n.address.Addr()); setupErr != nil {
			continue
		}
		return nil
	}
	return setupErr
}

func (n *windowsNetwork) applyLocked(prefixes []string) error {
	if err := setAddress4(n.luid, n.address); err != nil {
		return fmt.Errorf("tun: set address: %w", err)
	}
	if err := setMTU4(n.luid, n.mtu); err != nil {
		return fmt.Errorf("tun: set mtu: %w", err)
	}

	// IPv6 туннель не везёт: глушим его на адаптере нативно. Ошибка не
	// фатальна — IPv6 всё равно заблокирован WFP на время сессии.
	_ = disableIPv6(n.luid)

	if n.dns.IsValid() {
		if err := setDNS4(n.luid, n.dns); err != nil {
			return fmt.Errorf("tun: set dns: %w", err)
		}
	}

	// Split routes must be installed on-link. Passing the interface's own
	// address as the next hop is rejected on a point-to-point adapter.
	for _, prefix := range splitRoutes {
		parsed, err := netip.ParsePrefix(prefix)
		if err != nil {
			continue
		}
		_ = deleteRoute4(n.luid, parsed) // сталое — доброкачественно
		if err := addRoute4(n.luid, parsed, netip.Addr{}, 5); err != nil {
			return fmt.Errorf("tun: add split route %s: %w", prefix, err)
		}
	}

	if len(prefixes) > 0 {
		gateway, gatewayLuid, err := defaultRoute4(n.luid)
		if err != nil {
			return err
		}
		n.gateway = gateway
		n.gatewayLuid = gatewayLuid
		for _, prefix := range prefixes {
			parsed, err := netip.ParsePrefix(prefix)
			if err != nil {
				continue
			}
			// A stale copy of this route - left by a crash, or pointing into
			// the tunnel itself - makes the add below a no-op and sends the
			// core's own connection to its server back through the tunnel.
			_ = deleteRoute4(n.luid, parsed)
			_ = deleteRoute4(gatewayLuid, parsed)
			if err := addRoute4(gatewayLuid, parsed, gateway, 1); err != nil {
				return fmt.Errorf("tun: add bypass route %s: %w", prefix, err)
			}
		}
	}

	if len(prefixes) > 0 {
		n.bypass = make(map[string]struct{}, len(prefixes))
		for _, prefix := range prefixes {
			n.bypass[prefix] = struct{}{}
		}
		if err := n.verifyBypassLocked(); err != nil {
			return err
		}
	}
	return nil
}

// Reapply переустанавливает конфигурацию после смены сети хоста
// (Wi-Fi <-> Ethernet и т.п.). Идемпотентно; одноразовые системные твики
// пропускаются.
func (n *windowsNetwork) Reapply() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return nil
	}
	return n.setupLocked(n.bypassPrefixesLocked())
}

// UpdateBypass приводит bypass-маршруты к новому списку серверов БЕЗ
// переустановки адреса/DNS/MTU/split-маршрутов: смена ноды или профиля на
// живом подключении — горстка нативных вызовов вместо полного цикла
// cleanup+setup.
func (n *windowsNetwork) UpdateBypass(addrs []netip.Addr) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return fmt.Errorf("tun: network is closed")
	}

	want := make(map[string]struct{}, len(addrs))
	for _, ip := range addrs {
		if ip.Is4() {
			want[ip.String()+"/32"] = struct{}{}
		}
	}

	for prefix := range n.bypass {
		if _, keep := want[prefix]; keep {
			continue
		}
		if parsed, err := netip.ParsePrefix(prefix); err == nil {
			_ = deleteRoute4(n.luid, parsed)
			_ = deleteRoute4(n.gatewayLuid, parsed)
		}
	}

	var missing []string
	for prefix := range want {
		if _, exists := n.bypass[prefix]; !exists {
			missing = append(missing, prefix)
		}
	}
	if len(missing) > 0 {
		// Шлюз перечитываем каждый раз: сеть хоста могла поменяться.
		gateway, gatewayLuid, err := defaultRoute4(n.luid)
		if err != nil {
			return err
		}
		n.gateway = gateway
		n.gatewayLuid = gatewayLuid
		for _, prefix := range missing {
			parsed, err := netip.ParsePrefix(prefix)
			if err != nil {
				continue
			}
			_ = deleteRoute4(n.luid, parsed)
			_ = deleteRoute4(gatewayLuid, parsed)
			if err := addRoute4(gatewayLuid, parsed, gateway, 1); err != nil {
				return fmt.Errorf("tun: add bypass route %s: %w", prefix, err)
			}
		}
	}

	n.bypass = want
	return n.verifyBypassLocked()
}

func (n *windowsNetwork) Close() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.closeLocked()
}

// closeLocked откатывает сеть нативными вызовами: bypass-маршруты на
// физическом интерфейсе, split-маршруты и адрес туннеля. Адаптер
// переиспользуется между сессиями (см. device.Open), поэтому его маршруты
// нельзя оставлять: иначе 0.0.0.0/1 и 128.0.0.0/1 смотрели бы в мёртвый
// интерфейс. Ни netsh, ни PowerShell — микросекунды.
func (n *windowsNetwork) closeLocked() error {
	if n.closed {
		return nil
	}
	n.closed = true

	for prefix := range n.bypass {
		if parsed, err := netip.ParsePrefix(prefix); err == nil {
			_ = deleteRoute4(n.gatewayLuid, parsed)
			_ = deleteRoute4(n.luid, parsed)
		}
	}
	if n.luid != 0 {
		for _, prefix := range splitRoutes {
			if parsed, err := netip.ParsePrefix(prefix); err == nil {
				_ = deleteRoute4(n.luid, parsed)
			}
		}
		_ = deleteAddress4(n.luid, n.address)
	}
	// DNS сбрасываем в DHCP дёшево и нативно — на случай, если тот же
	// именованный адаптер переиспользуется между запусками без полной
	// переконфигурации.
	if n.dns.IsValid() && n.luid != 0 {
		_ = resetDNS4(n.luid)
	}
	return nil
}

func (n *windowsNetwork) bypassPrefixesLocked() []string {
	prefixes := make([]string, 0, len(n.bypass))
	for prefix := range n.bypass {
		prefixes = append(prefixes, prefix)
	}
	return prefixes
}

// verifyBypassLocked проверяет ВСЕ bypass-маршруты по одному нативному
// снимку таблицы маршрутов.
func (n *windowsNetwork) verifyBypassLocked() error {
	if len(n.bypass) == 0 {
		return nil
	}
	routes, err := routeTable4()
	if err != nil {
		return err
	}
	for prefix := range n.bypass {
		parsed, err := netip.ParsePrefix(prefix)
		if err != nil {
			continue
		}
		if err := verifyBypassRouteIn(routes, parsed, n.gatewayLuid, n.luid); err != nil {
			return err
		}
	}
	return nil
}

func bypassPrefixes(addrs []netip.Addr) []string {
	seen := make(map[string]struct{})
	var prefixes []string
	for _, ip := range addrs {
		if !ip.Is4() {
			continue
		}
		prefix := ip.String() + "/32"
		if _, dup := seen[prefix]; dup {
			continue
		}
		seen[prefix] = struct{}{}
		prefixes = append(prefixes, prefix)
	}
	return prefixes
}
