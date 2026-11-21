package netcfg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"beam-tun/internal/winip"
)

// iphlpapi_windows.go - thin wrappers over the IP Helper API (addresses,
// MTU, DNS, routes) used by the Windows configurator.

var (
	modIphlpapi = windows.NewLazySystemDLL("iphlpapi.dll")

	procConvertInterfaceAliasToLuid = modIphlpapi.NewProc("ConvertInterfaceAliasToLuid")
	procConvertInterfaceLuidToGuid  = modIphlpapi.NewProc("ConvertInterfaceLuidToGuid")
	procCreateUnicastIpAddressEntry = modIphlpapi.NewProc("CreateUnicastIpAddressEntry")
	procDeleteUnicastIpAddressEntry = modIphlpapi.NewProc("DeleteUnicastIpAddressEntry")
	procInitializeIpForwardEntry    = modIphlpapi.NewProc("InitializeIpForwardEntry")
	procCreateIpForwardEntry2       = modIphlpapi.NewProc("CreateIpForwardEntry2")
	procDeleteIpForwardEntry2       = modIphlpapi.NewProc("DeleteIpForwardEntry2")
	procSetIpInterfaceEntry         = modIphlpapi.NewProc("SetIpInterfaceEntry")
	procGetIpForwardTable2          = modIphlpapi.NewProc("GetIpForwardTable2")
	procFreeMibTable                = modIphlpapi.NewProc("FreeMibTable")
	procGetIpInterfaceEntry         = modIphlpapi.NewProc("GetIpInterfaceEntry")
	procConvertInterfaceLuidToIndex = modIphlpapi.NewProc("ConvertInterfaceLuidToIndex")
	procGetUnicastIpAddressTable    = modIphlpapi.NewProc("GetUnicastIpAddressTable")
	// SetInterfaceDnsSettings появилась в Win10 1903. На более старых
	// системах (не наша целевая аудитория, но всё же) — фолбэк на netsh.
	procSetInterfaceDnsSettings = modIphlpapi.NewProc("SetInterfaceDnsSettings")
)

const (
	errnoNotFound      = windows.Errno(1168) // ERROR_NOT_FOUND
	errnoAlreadyExists = windows.Errno(5010) // ERROR_OBJECT_ALREADY_EXISTS

	dnsInterfaceSettingsVersion1 = 1
	dnsSettingNameserver         = 0x1

	infiniteLifetime  = 0xFFFFFFFF
	dadStatePreferred = 2 // NL_DAD_STATE::IpDadStatePreferred — адрес сразу usable
)

// benignNetioErr — «уже применено»/«уже удалено» в терминах IP Helper API.
func benignNetioErr(err error) bool {
	return errors.Is(err, errnoNotFound) ||
		errors.Is(err, errnoAlreadyExists) ||
		errors.Is(err, windows.ERROR_FILE_NOT_FOUND)
}

// errnoOf достаёт код ошибки из ВОЗВРАЩАЕМОГО значения netio-функции.
// Брать getLastError у этих API нельзя: он может быть сталым/нулевым —
// отсюда был парадоксальный «The operation completed successfully».
func errnoOf(r1 uintptr) error {
	if r1 == 0 {
		return nil
	}
	return windows.Errno(r1)
}

// waitForAdapterLuid ждёт регистрации адаптера в сетевом стеке Windows после
// создания TUN-устройства и возвращает его LUID. Опрос без процессов.
func waitForAdapterLuid(name string, timeout time.Duration) (uint64, error) {
	deadline := time.Now().Add(timeout)
	for {
		luid, err := interfaceLuid(name)
		if err == nil {
			return luid, nil
		}
		if time.Now().After(deadline) {
			return 0, fmt.Errorf("tun: interface %q did not register within %s", name, timeout)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func interfaceLuid(name string) (uint64, error) {
	alias, err := windows.UTF16PtrFromString(strings.TrimSpace(name))
	if err != nil {
		return 0, err
	}
	var luid uint64
	r1, _, _ := procConvertInterfaceAliasToLuid.Call(
		uintptr(unsafe.Pointer(alias)),
		uintptr(unsafe.Pointer(&luid)),
	)
	if err := errnoOf(r1); err != nil {
		return 0, err
	}
	return luid, nil
}

func getIpInterfaceEntry(row *windows.MibIpInterfaceRow) error {
	r1, _, _ := procGetIpInterfaceEntry.Call(uintptr(unsafe.Pointer(row)))
	return errnoOf(r1)
}

func interfaceIndexFromLuid(luid uint64) (int, error) {
	var index uint32
	r1, _, _ := procConvertInterfaceLuidToIndex.Call(
		uintptr(unsafe.Pointer(&luid)), uintptr(unsafe.Pointer(&index)))
	if err := errnoOf(r1); err != nil {
		return 0, err
	}
	return int(index), nil
}

func rawSockaddrInet4(ip netip.Addr) windows.RawSockaddrInet {
	var sa windows.RawSockaddrInet
	sa.Family = windows.AF_INET
	b := ip.As4()
	sa.Data[0] = binary.LittleEndian.Uint32(b[:])
	return sa
}

func ipAddressPrefix4(prefix netip.Prefix) windows.IpAddressPrefix {
	return windows.IpAddressPrefix{
		Prefix:       rawSockaddrInet4(prefix.Addr()),
		PrefixLength: uint8(prefix.Bits()),
	}
}

func setAddress4(luid uint64, prefix netip.Prefix) error {
	var row windows.MibUnicastIpAddressRow
	row.InterfaceLuid = luid
	// SOCKADDR_INET — union: для IPv4 адрес лежит сразу за Family+Port,
	// т.е. в поле Flowinfo у RawSockaddrInet6. Льём готовый union из
	// rawSockaddrInet4 — тот же расклад, что у маршрутов. Ошибка «The
	// parameter is incorrect» была ровно отсюда: адрес уходил 0.0.0.0.
	sa := rawSockaddrInet4(prefix.Addr())
	row.Address = *(*windows.RawSockaddrInet6)(unsafe.Pointer(&sa))
	row.OnLinkPrefixLength = uint8(prefix.Bits())
	row.ValidLifetime = infiniteLifetime
	row.PreferredLifetime = infiniteLifetime
	row.DadState = dadStatePreferred
	// Сталое значение того же адреса (прошлый запуск, краш без cleanup)
	// вернёт ERROR_OBJECT_ALREADY_EXISTS — доброкачественно, адрес и так
	// уже тот, что нужен.
	r1, _, _ := procCreateUnicastIpAddressEntry.Call(uintptr(unsafe.Pointer(&row)))
	if err := errnoOf(r1); err != nil && !benignNetioErr(err) {
		return err
	}
	return nil
}

func setMTU4(luid uint64, mtu int) error {
	row := windows.MibIpInterfaceRow{
		Family:        windows.AF_INET,
		InterfaceLuid: luid,
	}
	if err := getIpInterfaceEntry(&row); err != nil {
		return err
	}
	if row.NlMtu == uint32(mtu) {
		return nil
	}
	row.NlMtu = uint32(mtu)
	row.SitePrefixLength = 0 // не трогаем: API требует 0 при Set
	r1, _, _ := procSetIpInterfaceEntry.Call(uintptr(unsafe.Pointer(&row)))
	return errnoOf(r1)
}

// dnsInterfaceSettings — DNS_INTERFACE_SETTINGS из netioapi.h (Win10 1903+).
type dnsInterfaceSettings struct {
	Version    uint32
	Flags      uint64
	Domain     *uint16
	NameServer *uint16
	SearchList *uint16
}

func setDNS4(luid uint64, dns netip.Addr) error {
	if err := procSetInterfaceDnsSettings.Find(); err != nil {
		// Система старше Win10 1903 — единственный фолбэк на netsh.
		return runCommand([]string{"netsh", "interface", "ipv4", "set", "dnsservers",
			"interface=" + strconv.FormatUint(luid, 10), "static", dns.String(), "primary", "validate=no"})
	}
	var guid windows.GUID
	r1, _, _ := procConvertInterfaceLuidToGuid.Call(
		uintptr(unsafe.Pointer(&luid)), uintptr(unsafe.Pointer(&guid)))
	if err := errnoOf(r1); err != nil {
		return err
	}
	nameServer, err := windows.UTF16PtrFromString(dns.String())
	if err != nil {
		return err
	}
	settings := dnsInterfaceSettings{
		Version:    dnsInterfaceSettingsVersion1,
		Flags:      dnsSettingNameserver,
		NameServer: nameServer,
	}
	r1, _, _ = procSetInterfaceDnsSettings.Call(
		uintptr(unsafe.Pointer(&guid)), uintptr(unsafe.Pointer(&settings)))
	return errnoOf(r1)
}

// resetDNS4 возвращает DNS интерфейса в DHCP (Flags=0, без полей).
func resetDNS4(luid uint64) error {
	if err := procSetInterfaceDnsSettings.Find(); err != nil {
		return nil // см. setDNS4: на древних системах адаптер всё равно удаляется
	}
	var guid windows.GUID
	r1, _, _ := procConvertInterfaceLuidToGuid.Call(
		uintptr(unsafe.Pointer(&luid)), uintptr(unsafe.Pointer(&guid)))
	if err := errnoOf(r1); err != nil {
		return err
	}
	settings := dnsInterfaceSettings{Version: dnsInterfaceSettingsVersion1}
	r1, _, _ = procSetInterfaceDnsSettings.Call(
		uintptr(unsafe.Pointer(&guid)), uintptr(unsafe.Pointer(&settings)))
	return errnoOf(r1)
}

func addRoute4(luid uint64, prefix netip.Prefix, nextHop netip.Addr, metric uint32) error {
	var row windows.MibIpForwardRow2
	procInitializeIpForwardEntry.Call(uintptr(unsafe.Pointer(&row)))
	row.InterfaceLuid = luid
	row.DestinationPrefix = ipAddressPrefix4(prefix)
	if nextHop.IsValid() {
		row.NextHop = rawSockaddrInet4(nextHop)
	} else {
		row.NextHop = rawSockaddrInet4(netip.IPv4Unspecified())
	}
	row.Metric = metric
	row.Protocol = windows.MIB_IPPROTO_NETMGMT
	row.ValidLifetime = infiniteLifetime
	row.PreferredLifetime = infiniteLifetime
	r1, _, _ := procCreateIpForwardEntry2.Call(uintptr(unsafe.Pointer(&row)))
	if err := errnoOf(r1); err != nil && !benignNetioErr(err) {
		return err
	}
	return nil
}

// deleteRoute4 удаляет ВСЕ строки (prefix, luid) из таблицы — со сталыми
// nexthop'ами включительно: ключ DeleteIpForwardEntry2 содержит next hop,
// а мы не всегда знаем, с каким шлюзом маршрут был установлен в прошлый раз.
func deleteRoute4(luid uint64, prefix netip.Prefix) error {
	routes, err := routeTable4()
	if err != nil {
		return err
	}
	for _, route := range routes {
		if route.luid != luid || route.prefix != prefix {
			continue
		}
		var row windows.MibIpForwardRow2
		procInitializeIpForwardEntry.Call(uintptr(unsafe.Pointer(&row)))
		row.InterfaceLuid = luid
		row.DestinationPrefix = ipAddressPrefix4(prefix)
		row.NextHop = rawSockaddrInet4(route.nextHop)
		r1, _, _ := procDeleteIpForwardEntry2.Call(uintptr(unsafe.Pointer(&row)))
		if err := errnoOf(r1); err != nil && !benignNetioErr(err) {
			return err
		}
	}
	return nil
}

type routeEntry4 struct {
	prefix  netip.Prefix
	luid    uint64
	nextHop netip.Addr
	metric  uint32
}

func routeTable4() ([]routeEntry4, error) {
	var table *windows.MibIpForwardTable2
	r1, _, _ := procGetIpForwardTable2.Call(
		uintptr(windows.AF_INET), uintptr(unsafe.Pointer(&table)))
	if err := errnoOf(r1); err != nil {
		return nil, err
	}
	if table == nil {
		return nil, nil
	}
	defer procFreeMibTable.Call(uintptr(unsafe.Pointer(table)))

	rows := table.Rows()
	entries := make([]routeEntry4, 0, len(rows))
	for _, row := range rows {
		if row.DestinationPrefix.Prefix.Family != windows.AF_INET {
			continue
		}
		prefixAddr := rawInet4ToAddr(row.DestinationPrefix.Prefix)
		nextHop := rawInet4ToAddr(row.NextHop)
		entries = append(entries, routeEntry4{
			prefix:  netip.PrefixFrom(prefixAddr, int(row.DestinationPrefix.PrefixLength)),
			luid:    row.InterfaceLuid,
			nextHop: nextHop,
			metric:  row.Metric,
		})
	}
	return entries, nil
}

func rawInet4ToAddr(sa windows.RawSockaddrInet) netip.Addr {
	if sa.Family != windows.AF_INET {
		return netip.Addr{}
	}
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], sa.Data[0])
	return netip.AddrFrom4(b)
}

// defaultRoute4 возвращает шлюз и LUID физического default-маршрута хоста.
// Собственный default-маршрут туннеля исключён: его выбор направил бы все
// bypass-маршруты через сам туннель — ровно ту петлю, ради разрыва которой
// bypass и существует.
func defaultRoute4(excludeLuid uint64) (netip.Addr, uint64, error) {
	routes, err := routeTable4()
	if err != nil {
		return netip.Addr{}, 0, err
	}

	var (
		best       *routeEntry4
		bestMetric uint32
	)
	for i := range routes {
		route := &routes[i]
		if route.prefix.Bits() != 0 || !route.prefix.Addr().Is4() || route.prefix.Addr().As4() != [4]byte{} {
			continue
		}
		if route.luid == excludeLuid {
			continue
		}
		if !route.nextHop.IsValid() || route.nextHop.IsUnspecified() {
			continue
		}
		if best != nil && route.metric >= bestMetric {
			continue
		}
		best = route
		bestMetric = route.metric
	}
	if best == nil {
		return netip.Addr{}, 0, fmt.Errorf("tun: no default route to bypass through")
	}
	return best.nextHop, best.luid, nil
}

// verifyBypassRouteIn убеждается, что bypass-маршрут стоит на физическом
// интерфейсе и не указывает в туннель (иначе ядро дозванивается до сервера
// через само себя, и не работает вообще ничего, включая DNS).
func verifyBypassRouteIn(routes []routeEntry4, prefix netip.Prefix, wantLuid, tunLuid uint64) error {
	found := false
	for _, route := range routes {
		if route.prefix != prefix {
			continue
		}
		found = true
		if route.luid == tunLuid {
			return fmt.Errorf("tun: bypass route %s points into the tunnel", prefix)
		}
		if route.luid == wantLuid {
			return nil
		}
	}
	if !found {
		return fmt.Errorf("tun: bypass route %s was not installed", prefix)
	}
	return fmt.Errorf("tun: bypass route %s is not on the physical interface", prefix)
}

// NL_ROUTER_DISCOVERY_BEHAVIOR / NL_LINK_LOCAL_ADDRESS_BEHAVIOR.
const (
	routerDiscoveryDisabled = 0
	linkLocalAlwaysOff      = 0
)

// disableIPv6 глушит IPv6 на адаптере туннеля нативно, без отвязки tcpip6
// через PowerShell/NetCfg: Router Discovery и link-local выключаются, DAD
// не нужен, а уже назначенные IPv6-адреса и маршруты снимаются. Без единого
// IPv6-адреса Windows не может ни выбрать туннель для IPv6, ни слать с него
// RS/MLD, ни регистрировать его в DNS. Настройки живут на интерфейсе, а
// адаптер переиспользуется между сессиями, так что повторный вызов почти
// всегда no-op. Остальной IPv6 хоста режет WFP (firewall.AttachTunnel).
func disableIPv6(luid uint64) error {
	row := windows.MibIpInterfaceRow{Family: windows.AF_INET6, InterfaceLuid: luid}
	var setErr error
	switch err := getIpInterfaceEntry(&row); {
	case err != nil && benignNetioErr(err):
		// tcpip6 на адаптере не привязан вовсе — глушить нечего.
		return nil
	case err != nil:
		setErr = err
	case row.RouterDiscoveryBehavior != routerDiscoveryDisabled ||
		row.LinkLocalAddressBehavior != linkLocalAlwaysOff ||
		row.DadTransmits != 0:
		row.RouterDiscoveryBehavior = routerDiscoveryDisabled
		row.LinkLocalAddressBehavior = linkLocalAlwaysOff
		row.DadTransmits = 0
		row.SitePrefixLength = 0 // API требует 0 при Set
		r1, _, _ := procSetIpInterfaceEntry.Call(uintptr(unsafe.Pointer(&row)))
		setErr = errnoOf(r1)
	}

	if err := deleteAddresses6(luid); err != nil && setErr == nil {
		setErr = err
	}
	if err := deleteRoutes6(luid); err != nil && setErr == nil {
		setErr = err
	}
	return setErr
}

// mibUnicastIpAddressTable — MIB_UNICASTIPADDRESS_TABLE (строки выровнены
// по 8 байт, как и у MIB_IPFORWARD_TABLE2).
type mibUnicastIpAddressTable struct {
	NumEntries uint32
	Table      [1]windows.MibUnicastIpAddressRow
}

func deleteAddresses6(luid uint64) error {
	var table *mibUnicastIpAddressTable
	r1, _, _ := procGetUnicastIpAddressTable.Call(
		uintptr(windows.AF_INET6), uintptr(unsafe.Pointer(&table)))
	if err := errnoOf(r1); err != nil {
		if benignNetioErr(err) {
			return nil
		}
		return err
	}
	if table == nil {
		return nil
	}
	defer procFreeMibTable.Call(uintptr(unsafe.Pointer(table)))

	var firstErr error
	for _, entry := range unsafe.Slice(&table.Table[0], table.NumEntries) {
		if entry.InterfaceLuid != luid {
			continue
		}
		row := entry
		r1, _, _ := procDeleteUnicastIpAddressEntry.Call(uintptr(unsafe.Pointer(&row)))
		if err := errnoOf(r1); err != nil && !benignNetioErr(err) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func deleteRoutes6(luid uint64) error {
	var table *windows.MibIpForwardTable2
	r1, _, _ := procGetIpForwardTable2.Call(
		uintptr(windows.AF_INET6), uintptr(unsafe.Pointer(&table)))
	if err := errnoOf(r1); err != nil {
		if benignNetioErr(err) {
			return nil
		}
		return err
	}
	if table == nil {
		return nil
	}
	defer procFreeMibTable.Call(uintptr(unsafe.Pointer(table)))

	var firstErr error
	for _, entry := range table.Rows() {
		if entry.InterfaceLuid != luid {
			continue
		}
		row := entry
		r1, _, _ := procDeleteIpForwardEntry2.Call(uintptr(unsafe.Pointer(&row)))
		if err := errnoOf(r1); err != nil && !benignNetioErr(err) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// deleteAddress4 снимает адрес туннеля: адаптер переживает сессию, и
// оставленный адрес на «мёртвом» интерфейсе мешал бы проверке конфликтов.
func deleteAddress4(luid uint64, prefix netip.Prefix) error {
	var row windows.MibUnicastIpAddressRow
	row.InterfaceLuid = luid
	sa := rawSockaddrInet4(prefix.Addr())
	row.Address = *(*windows.RawSockaddrInet6)(unsafe.Pointer(&sa))
	row.OnLinkPrefixLength = uint8(prefix.Bits())
	r1, _, _ := procDeleteUnicastIpAddressEntry.Call(uintptr(unsafe.Pointer(&row)))
	if err := errnoOf(r1); err != nil && !benignNetioErr(err) {
		return err
	}
	return nil
}

// verifyAddress убеждается, что адаптер получил адрес туннеля: одна
// таблица unicast-адресов ядра вместо GetAdaptersAddresses (net.Interface
// дёргал её дважды за проверку, по сотне мс на машинах с кучей адаптеров).
// Адрес может появиться с задержкой — опрашиваем часто, до 3 секунд.
func verifyAddress(luid uint64, want netip.Addr) error {
	deadline := time.Now().Add(3 * time.Second)
	var lastErr error
	for {
		entries, err := winip.Addresses()
		if err != nil {
			lastErr = fmt.Errorf("tun: read addresses: %w", err)
		} else {
			for _, entry := range entries {
				if entry.Luid == luid && entry.Prefix.Addr() == want {
					return nil
				}
			}
			lastErr = fmt.Errorf("tun: address %s was not installed on the tunnel", want)
		}
		if time.Now().After(deadline) {
			return lastErr
		}
		time.Sleep(20 * time.Millisecond)
	}
}
