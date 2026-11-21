//go:build windows

package firewall

// firewall_windows.go — the kill switch on the Windows Filtering Platform.
//
// All filters live in one sublayer of a dynamic WFP session: Windows deletes
// the session with everything in it as soon as the process exits, crashes or
// is killed, so the kill switch can never outlive Beam and strand the machine
// offline. Within the sublayer the highest-weight matching filter decides,
// which is how the sets are ordered: permits for Beam and loopback on top,
// the catch-all block at the bottom.
//
// Filters sit at the ALE authorization layers (connect / receive-accept),
// i.e. they are evaluated once per flow, not per packet: no cost on the data
// path.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modFwpuclnt = windows.NewLazySystemDLL("fwpuclnt.dll")

	procFwpmEngineOpen0           = modFwpuclnt.NewProc("FwpmEngineOpen0")
	procFwpmEngineClose0          = modFwpuclnt.NewProc("FwpmEngineClose0")
	procFwpmTransactionBegin0     = modFwpuclnt.NewProc("FwpmTransactionBegin0")
	procFwpmTransactionCommit0    = modFwpuclnt.NewProc("FwpmTransactionCommit0")
	procFwpmTransactionAbort0     = modFwpuclnt.NewProc("FwpmTransactionAbort0")
	procFwpmSubLayerAdd0          = modFwpuclnt.NewProc("FwpmSubLayerAdd0")
	procFwpmFilterAdd0            = modFwpuclnt.NewProc("FwpmFilterAdd0")
	procFwpmFilterDeleteById0     = modFwpuclnt.NewProc("FwpmFilterDeleteById0")
	procFwpmGetAppIdFromFileName0 = modFwpuclnt.NewProc("FwpmGetAppIdFromFileName0")
	procFwpmFreeMemory0           = modFwpuclnt.NewProc("FwpmFreeMemory0")
)

const (
	rpcCAuthnDefault       = 0xffffffff
	fwpmSessionFlagDynamic = 0x00000001

	fwpEFilterNotFound = 0x80320003
	fwpEAlreadyExists  = 0x80320009
	errAccessDenied    = 0x80070005

	fwpActionFlagTerminating = 0x00001000

	// FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT: a "hard" permit that filters of
	// lower-weight sublayers (Windows Defender Firewall) cannot override.
	fwpmFilterFlagClearActionRight = 0x00000008
	actionBlock                    = 0x00000001 | fwpActionFlagTerminating
	actionPermit                   = 0x00000002 | fwpActionFlagTerminating

	// FWP_DATA_TYPE
	fwpUint8        = 1
	fwpUint16       = 2
	fwpUint32       = 3
	fwpUint64       = 4
	fwpByteBlobType = 12
	fwpV4AddrMask   = 0x100
	fwpV6AddrMask   = 0x101

	// FWP_MATCH_TYPE
	fwpMatchEqual       = 0
	fwpMatchFlagsAllSet = 6

	fwpConditionFlagIsLoopback = 0x00000001

	ipProtoUDP = 17
	dnsPort    = 53
)

// Layer and condition keys (fwpmu.h).
var (
	layerConnectV4    = windows.GUID{Data1: 0xc38d57d1, Data2: 0x05a7, Data3: 0x4c33, Data4: [8]byte{0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82}}
	layerConnectV6    = windows.GUID{Data1: 0x4a72393b, Data2: 0x319f, Data3: 0x44bc, Data4: [8]byte{0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4}}
	layerRecvAcceptV4 = windows.GUID{Data1: 0xe1cd9fe7, Data2: 0xf4b5, Data3: 0x4273, Data4: [8]byte{0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50}}
	layerRecvAcceptV6 = windows.GUID{Data1: 0xa3b42c97, Data2: 0x9f04, Data3: 0x4672, Data4: [8]byte{0xb8, 0x7e, 0xce, 0xe9, 0xc4, 0x83, 0x25, 0x7f}}

	condAppID          = windows.GUID{Data1: 0xd78e1e87, Data2: 0x8644, Data3: 0x4ea5, Data4: [8]byte{0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71}}
	condRemoteAddress  = windows.GUID{Data1: 0xb235ae9a, Data2: 0x1d64, Data3: 0x49b8, Data4: [8]byte{0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45}}
	condRemotePort     = windows.GUID{Data1: 0xc35a604d, Data2: 0xd22b, Data3: 0x4e1a, Data4: [8]byte{0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b}}
	condLocalPort      = windows.GUID{Data1: 0x0c1ba1af, Data2: 0x5765, Data3: 0x453f, Data4: [8]byte{0xaf, 0x22, 0xa8, 0xf7, 0x91, 0xac, 0x77, 0x5b}}
	condProtocol       = windows.GUID{Data1: 0x3971ef2b, Data2: 0x623e, Data3: 0x4f9a, Data4: [8]byte{0x8c, 0xb1, 0x6e, 0x79, 0xb8, 0x06, 0xb9, 0xa7}}
	condLocalInterface = windows.GUID{Data1: 0x4cd62a49, Data2: 0x59c3, Data3: 0x4969, Data4: [8]byte{0xb7, 0xf3, 0xbd, 0xa5, 0xd3, 0x28, 0x90, 0xa4}}
	condFlags          = windows.GUID{Data1: 0x632ce23b, Data2: 0x5167, Data3: 0x435c, Data4: [8]byte{0x86, 0xd7, 0xe9, 0x03, 0x68, 0x4a, 0xa8, 0x0c}}

	// sublayerKey is Beam's own sublayer.
	sublayerKey = windows.GUID{Data1: 0x6e2b4c1a, Data2: 0x83d5, Data3: 0x4f0e, Data4: [8]byte{0xa7, 0x19, 0x5b, 0xe2, 0x0c, 0x94, 0x3d, 0x61}}
)

// The local network: private ranges, link-local, multicast and broadcast.
var (
	lanV4 = mustPrefixes("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32")
	lanV6 = mustPrefixes("fe80::/10", "fc00::/7", "ff00::/8")
)

// --- WFP structures (fwptypes.h / fwpmtypes.h), 64-bit layout ---

type fwpmDisplayData0 struct {
	name        *uint16
	description *uint16
}

type fwpmSession0 struct {
	sessionKey           windows.GUID
	displayData          fwpmDisplayData0
	flags                uint32
	txnWaitTimeoutInMSec uint32
	processID            uint32
	sid                  *windows.SID
	username             *uint16
	kernelMode           int32
}

type fwpByteBlob struct {
	size uint32
	data *uint8
}

type fwpmSublayer0 struct {
	subLayerKey  windows.GUID
	displayData  fwpmDisplayData0
	flags        uint32
	providerKey  *windows.GUID
	providerData fwpByteBlob
	weight       uint16
}

// fwpValue0 is FWP_VALUE0 and FWP_CONDITION_VALUE0: a type tag and a
// pointer-sized union (small integers inline, everything else by pointer).
type fwpValue0 struct {
	typ   uint32
	value uintptr
}

type fwpmFilterCondition0 struct {
	fieldKey  windows.GUID
	matchType uint32
	value     fwpValue0
}

type fwpmAction0 struct {
	typ uint32
	key windows.GUID
}

type fwpmFilter0 struct {
	filterKey           windows.GUID
	displayData         fwpmDisplayData0
	flags               uint32
	providerKey         *windows.GUID
	providerData        fwpByteBlob
	layerKey            windows.GUID
	subLayerKey         windows.GUID
	weight              fwpValue0
	numFilterConditions uint32
	filterCondition     *fwpmFilterCondition0
	action              fwpmAction0
	// union { UINT64 rawContext; GUID providerContextKey; } — 8-aligned.
	providerContext [2]uint64
	reserved        *windows.GUID
	filterID        uint64
	effectiveWeight fwpValue0
}

type fwpV4AddrAndMask struct {
	addr uint32
	mask uint32
}

type fwpV6AddrAndMask struct {
	addr         [16]byte
	prefixLength uint8
}

// fwpError is a WFP / Win32 result code.
type fwpError uint32

func (e fwpError) Error() string {
	switch uint32(e) {
	case errAccessDenied, uint32(windows.ERROR_ACCESS_DENIED):
		return "access denied: Beam must run as administrator"
	}
	return fmt.Sprintf("WFP error 0x%08X", uint32(e))
}

func call(proc *windows.LazyProc, args ...uintptr) error {
	if err := proc.Find(); err != nil {
		return err
	}
	r1, _, _ := proc.Call(args...)
	if r1 != 0 {
		return fwpError(uint32(r1))
	}
	return nil
}

func isCode(err error, code uint32) bool {
	var e fwpError
	return errors.As(err, &e) && uint32(e) == code
}

// --- Firewall ---

// Firewall owns the WFP session. The session is opened on the first filter
// and closed (dropping everything) once both sets are gone.
type Firewall struct {
	mu     sync.Mutex
	engine windows.Handle
	appID  *fwpByteBlob

	lockdown    []uint64
	dnsHole     []uint64
	protect     []uint64
	protectLUID uint64

	tunnel     []uint64
	tunnelLUID uint64
}

var defaultFirewall = &Firewall{}

// Supported reports whether the kill switch works on this platform.
func Supported() bool { return modFwpuclnt.Load() == nil }

// Lockdown engages the kill switch: only Beam, loopback, the local network
// and DHCP may talk. Idempotent.
func (f *Firewall) Lockdown() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.lockdown) > 0 {
		return nil
	}
	ids, err := f.installLocked(lockdownRules)
	if err != nil {
		f.closeIfIdleLocked()
		return fmt.Errorf("kill switch: %w", err)
	}
	f.lockdown = ids
	return nil
}

// AllowDNS opens (or closes again) plain DNS while the kill switch is
// engaged: a reconnect resolves the server name through the system resolver,
// which runs outside Beam. No-op without a lockdown.
func (f *Firewall) AllowDNS(allow bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !allow {
		err := f.removeLocked(f.dnsHole)
		if err == nil {
			f.dnsHole = nil
		}
		return err
	}
	if len(f.lockdown) == 0 || len(f.dnsHole) > 0 {
		return nil
	}
	ids, err := f.installLocked(dnsHoleRules)
	if err != nil {
		return fmt.Errorf("kill switch: allow DNS: %w", err)
	}
	f.dnsHole = ids
	return nil
}

// Unlock releases the kill switch. If the filters cannot be removed one by
// one the whole session is dropped: getting the internet back wins.
func (f *Firewall) Unlock() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.lockdown) == 0 && len(f.dnsHole) == 0 {
		return nil
	}
	ids := append(append([]uint64(nil), f.dnsHole...), f.lockdown...)
	if err := f.removeLocked(ids); err != nil {
		f.closeLocked()
		return fmt.Errorf("kill switch: release: %w", err)
	}
	f.lockdown, f.dnsHole = nil, nil
	f.closeIfIdleLocked()
	return nil
}

// Locked reports whether the kill switch is engaged.
func (f *Firewall) Locked() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.lockdown) > 0
}

// Protect blocks leaks around the tunnel with the given adapter LUID: DNS
// outside the tunnel and IPv6, for everyone but Beam.
func (f *Firewall) Protect(luid uint64) error {
	if luid == 0 {
		return errors.New("leak protection: unknown tunnel interface")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.protect) > 0 && f.protectLUID == luid {
		return nil
	}
	if err := f.removeLocked(f.protect); err != nil {
		return fmt.Errorf("leak protection: %w", err)
	}
	f.protect, f.protectLUID = nil, 0
	ids, err := f.installLocked(func(b *builder) { protectRules(b, luid) })
	if err != nil {
		f.closeIfIdleLocked()
		return fmt.Errorf("leak protection: %w", err)
	}
	f.protect, f.protectLUID = ids, luid
	return nil
}

// Unprotect removes the leak protection.
func (f *Firewall) Unprotect() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.protect) == 0 {
		return nil
	}
	if err := f.removeLocked(f.protect); err != nil {
		return fmt.Errorf("leak protection: release: %w", err)
	}
	f.protect, f.protectLUID = nil, 0
	f.closeIfIdleLocked()
	return nil
}

// AttachTunnel installs the rules every live tunnel needs, whatever the
// settings:
//   - inbound to Beam on the tunnel adapter is a hard permit. The NAT
//     listener receives every TCP flow there and Windows Defender Firewall
//     would drop the SYNs; this replaces a netsh advfirewall rule (two
//     netsh processes on the connect path) with one WFP transaction;
//   - IPv6 is cut for everyone but Beam, loopback and the local network.
//     The tunnel is IPv4-only, so any IPv6 (native, Teredo, 6to4, ISATAP)
//     would bypass it - this replaces the system-wide netsh switches and
//     ends with the session instead of outliving Beam.
func (f *Firewall) AttachTunnel(luid uint64) error {
	if luid == 0 {
		return errors.New("tunnel rules: unknown tunnel interface")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.tunnel) > 0 && f.tunnelLUID == luid {
		return nil
	}
	if err := f.removeLocked(f.tunnel); err != nil {
		return fmt.Errorf("tunnel rules: %w", err)
	}
	f.tunnel, f.tunnelLUID = nil, 0
	ids, err := f.installLocked(func(b *builder) { tunnelRules(b, luid) })
	if err != nil {
		f.closeIfIdleLocked()
		return fmt.Errorf("tunnel rules: %w", err)
	}
	f.tunnel, f.tunnelLUID = ids, luid
	return nil
}

// DetachTunnel removes the rules of AttachTunnel.
func (f *Firewall) DetachTunnel() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.tunnel) == 0 {
		return nil
	}
	if err := f.removeLocked(f.tunnel); err != nil {
		return fmt.Errorf("tunnel rules: release: %w", err)
	}
	f.tunnel, f.tunnelLUID = nil, 0
	f.closeIfIdleLocked()
	return nil
}

// Protected reports whether the leak protection is active.
func (f *Firewall) Protected() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.protect) > 0
}

func (f *Firewall) openLocked() error {
	if f.engine != 0 {
		return nil
	}
	sessionName, _ := windows.UTF16PtrFromString("Beam kill switch")
	session := fwpmSession0{
		displayData: fwpmDisplayData0{name: sessionName},
		flags:       fwpmSessionFlagDynamic,
	}
	var engine windows.Handle
	if err := call(procFwpmEngineOpen0, 0, rpcCAuthnDefault, 0,
		uintptr(unsafe.Pointer(&session)), uintptr(unsafe.Pointer(&engine))); err != nil {
		return fmt.Errorf("open WFP engine: %w", err)
	}
	runtime.KeepAlive(sessionName)

	exe, err := os.Executable()
	if err != nil {
		_, _, _ = procFwpmEngineClose0.Call(uintptr(engine))
		return fmt.Errorf("locate executable: %w", err)
	}
	exePtr, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		_, _, _ = procFwpmEngineClose0.Call(uintptr(engine))
		return err
	}
	var appID *fwpByteBlob
	if err := call(procFwpmGetAppIdFromFileName0,
		uintptr(unsafe.Pointer(exePtr)), uintptr(unsafe.Pointer(&appID))); err != nil {
		_, _, _ = procFwpmEngineClose0.Call(uintptr(engine))
		return fmt.Errorf("resolve app id: %w", err)
	}
	runtime.KeepAlive(exePtr)

	sublayerName, _ := windows.UTF16PtrFromString("Beam")
	sublayer := fwpmSublayer0{
		subLayerKey: sublayerKey,
		displayData: fwpmDisplayData0{name: sublayerName},
		weight:      0xffff,
	}
	if err := call(procFwpmSubLayerAdd0, uintptr(engine),
		uintptr(unsafe.Pointer(&sublayer)), 0); err != nil && !isCode(err, fwpEAlreadyExists) {
		freeWFP(unsafe.Pointer(appID))
		_, _, _ = procFwpmEngineClose0.Call(uintptr(engine))
		return fmt.Errorf("add sublayer: %w", err)
	}
	runtime.KeepAlive(sublayerName)

	f.engine, f.appID = engine, appID
	return nil
}

// closeLocked drops the session: Windows removes every filter in it.
func (f *Firewall) closeLocked() {
	if f.engine != 0 {
		_, _, _ = procFwpmEngineClose0.Call(uintptr(f.engine))
		f.engine = 0
	}
	if f.appID != nil {
		freeWFP(unsafe.Pointer(f.appID))
		f.appID = nil
	}
	f.lockdown, f.dnsHole, f.protect, f.protectLUID = nil, nil, nil, 0
	f.tunnel, f.tunnelLUID = nil, 0
}

func (f *Firewall) closeIfIdleLocked() {
	if len(f.lockdown)+len(f.dnsHole)+len(f.protect)+len(f.tunnel) == 0 {
		f.closeLocked()
	}
}

func freeWFP(p unsafe.Pointer) {
	if p == nil {
		return
	}
	_, _, _ = procFwpmFreeMemory0.Call(uintptr(unsafe.Pointer(&p)))
}

// installLocked adds one filter set atomically: all of it or nothing.
func (f *Firewall) installLocked(build func(*builder)) ([]uint64, error) {
	if err := f.openLocked(); err != nil {
		return nil, err
	}
	b := &builder{appID: f.appID}
	build(b)

	if err := call(procFwpmTransactionBegin0, uintptr(f.engine), 0); err != nil {
		return nil, fmt.Errorf("begin transaction: %w", err)
	}
	ids := make([]uint64, 0, len(b.rules))
	for i := range b.rules {
		id, err := f.addFilterLocked(&b.rules[i])
		if err != nil {
			_, _, _ = procFwpmTransactionAbort0.Call(uintptr(f.engine))
			return nil, fmt.Errorf("add filter %q: %w", b.rules[i].name, err)
		}
		ids = append(ids, id)
	}
	if err := call(procFwpmTransactionCommit0, uintptr(f.engine)); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	runtime.KeepAlive(b)
	return ids, nil
}

func (f *Firewall) addFilterLocked(r *rule) (uint64, error) {
	name, _ := windows.UTF16PtrFromString(r.name)
	filter := fwpmFilter0{
		displayData: fwpmDisplayData0{name: name},
		layerKey:    r.layer,
		flags:       r.flags,
		subLayerKey: sublayerKey,
		weight:      fwpValue0{typ: fwpUint8, value: uintptr(r.weight)},
		action:      fwpmAction0{typ: r.action},
	}
	if len(r.conds) > 0 {
		filter.numFilterConditions = uint32(len(r.conds))
		filter.filterCondition = &r.conds[0]
	}
	var id uint64
	err := call(procFwpmFilterAdd0, uintptr(f.engine),
		uintptr(unsafe.Pointer(&filter)), 0, uintptr(unsafe.Pointer(&id)))
	runtime.KeepAlive(name)
	runtime.KeepAlive(r)
	return id, err
}

// removeLocked deletes filters atomically; already missing ones are fine.
func (f *Firewall) removeLocked(ids []uint64) error {
	if len(ids) == 0 || f.engine == 0 {
		return nil
	}
	if err := call(procFwpmTransactionBegin0, uintptr(f.engine), 0); err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	for _, id := range ids {
		if err := call(procFwpmFilterDeleteById0, uintptr(f.engine), uintptr(id)); err != nil && !isCode(err, fwpEFilterNotFound) {
			_, _, _ = procFwpmTransactionAbort0.Call(uintptr(f.engine))
			return fmt.Errorf("delete filter: %w", err)
		}
	}
	if err := call(procFwpmTransactionCommit0, uintptr(f.engine)); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// --- filter sets ---

const (
	weightBeam     = 15
	weightLoopback = 14
	weightTunnel   = 14
	weightDHCP     = 13
	weightDNSHole  = 12
	weightDNSBlock = 11
	weightLAN      = 10
	weightBlockAll = 0
)

type layerInfo struct {
	key     windows.GUID
	v6      bool
	connect bool
}

var allLayers = []layerInfo{
	{layerConnectV4, false, true},
	{layerRecvAcceptV4, false, false},
	{layerConnectV6, true, true},
	{layerRecvAcceptV6, true, false},
}

// lockdownRules: the kill switch. Inbound and outbound, both families.
func lockdownRules(b *builder) {
	for _, l := range allLayers {
		b.add("Beam: allow Beam", l.key, actionPermit, weightBeam, b.app())
		b.add("Beam: allow loopback", l.key, actionPermit, weightLoopback, loopback())
		b.add("Beam: allow DHCP", l.key, actionPermit, weightDHCP, dhcp(l.v6)...)
		if l.connect {
			// Above the local network: a router's resolver forwards the
			// names to the ISP all the same.
			b.add("Beam: block DNS", l.key, actionBlock, weightDNSBlock, remotePort(dnsPort))
		}
		b.add("Beam: allow local network", l.key, actionPermit, weightLAN, b.lan(l.v6)...)
		b.add("Beam: kill switch", l.key, actionBlock, weightBlockAll)
	}
}

// dnsHoleRules: plain DNS for a reconnect attempt under the kill switch.
func dnsHoleRules(b *builder) {
	b.add("Beam: allow DNS for reconnect", layerConnectV4, actionPermit, weightDNSHole, remotePort(dnsPort))
	b.add("Beam: allow DNS for reconnect", layerConnectV6, actionPermit, weightDNSHole, remotePort(dnsPort))
}

// protectRules: leak protection while the tunnel is up. IPv4 goes through
// the tunnel by its routes, only DNS asked outside it is cut (Windows sends
// queries to the resolvers of every interface). The tunnel carries no IPv6,
// so IPv6 is cut entirely except for the local network.
func protectRules(b *builder, luid uint64) {
	b.add("Beam: allow Beam", layerConnectV4, actionPermit, weightBeam, b.app())
	b.add("Beam: allow loopback", layerConnectV4, actionPermit, weightLoopback, loopback())
	b.add("Beam: allow tunnel", layerConnectV4, actionPermit, weightTunnel, b.iface(luid))
	b.add("Beam: block DNS leaks", layerConnectV4, actionBlock, weightDNSBlock, remotePort(dnsPort))

	b.add("Beam: allow Beam", layerConnectV6, actionPermit, weightBeam, b.app())
	b.add("Beam: allow loopback", layerConnectV6, actionPermit, weightLoopback, loopback())
	b.add("Beam: allow tunnel", layerConnectV6, actionPermit, weightTunnel, b.iface(luid))
	b.add("Beam: allow DHCPv6", layerConnectV6, actionPermit, weightDHCP, dhcp(true)...)
	b.add("Beam: block DNS leaks", layerConnectV6, actionBlock, weightDNSBlock, remotePort(dnsPort))
	b.add("Beam: allow local network", layerConnectV6, actionPermit, weightLAN, b.lan(true)...)
	b.add("Beam: block IPv6 leaks", layerConnectV6, actionBlock, weightBlockAll)
}

// tunnelRules: see AttachTunnel.
func tunnelRules(b *builder, luid uint64) {
	b.rules = append(b.rules, rule{
		name:   "Beam: allow tunnel inbound",
		layer:  layerRecvAcceptV4,
		action: actionPermit,
		weight: weightBeam,
		flags:  fwpmFilterFlagClearActionRight,
		conds:  []fwpmFilterCondition0{b.app(), b.iface(luid)},
	})

	b.add("Beam: allow Beam", layerConnectV6, actionPermit, weightBeam, b.app())
	b.add("Beam: allow loopback", layerConnectV6, actionPermit, weightLoopback, loopback())
	b.add("Beam: allow DHCPv6", layerConnectV6, actionPermit, weightDHCP, dhcp(true)...)
	b.add("Beam: allow local network", layerConnectV6, actionPermit, weightLAN, b.lan(true)...)
	b.add("Beam: block IPv6 around the tunnel", layerConnectV6, actionBlock, weightBlockAll)
}

// --- builder ---

type rule struct {
	name   string
	layer  windows.GUID
	action uint32
	weight uint8
	flags  uint32
	conds  []fwpmFilterCondition0
}

// builder collects the rules of one set and keeps the condition values they
// point to alive (and on the heap) until the set is committed.
type builder struct {
	appID *fwpByteBlob
	rules []rule
	keep  []any
}

func (b *builder) add(name string, layer windows.GUID, action uint32, weight uint8, conds ...fwpmFilterCondition0) {
	b.rules = append(b.rules, rule{name: name, layer: layer, action: action, weight: weight, conds: conds})
}

// app matches Beam itself (the core runs in-process).
func (b *builder) app() fwpmFilterCondition0 {
	return fwpmFilterCondition0{
		fieldKey:  condAppID,
		matchType: fwpMatchEqual,
		value:     fwpValue0{typ: fwpByteBlobType, value: uintptr(unsafe.Pointer(b.appID))},
	}
}

func (b *builder) iface(luid uint64) fwpmFilterCondition0 {
	p := new(uint64)
	*p = luid
	b.keep = append(b.keep, p)
	return fwpmFilterCondition0{
		fieldKey:  condLocalInterface,
		matchType: fwpMatchEqual,
		value:     fwpValue0{typ: fwpUint64, value: uintptr(unsafe.Pointer(p))},
	}
}

// lan returns one condition per local range; conditions on the same field
// are OR-ed by WFP.
func (b *builder) lan(v6 bool) []fwpmFilterCondition0 {
	prefixes := lanV4
	if v6 {
		prefixes = lanV6
	}
	conds := make([]fwpmFilterCondition0, 0, len(prefixes))
	for _, prefix := range prefixes {
		conds = append(conds, b.remote(prefix))
	}
	return conds
}

func (b *builder) remote(prefix netip.Prefix) fwpmFilterCondition0 {
	if prefix.Addr().Is4() {
		m := new(fwpV4AddrAndMask)
		a := prefix.Addr().As4()
		m.addr = binary.BigEndian.Uint32(a[:])
		if bits := prefix.Bits(); bits > 0 {
			m.mask = ^uint32(0) << (32 - bits)
		}
		b.keep = append(b.keep, m)
		return fwpmFilterCondition0{
			fieldKey:  condRemoteAddress,
			matchType: fwpMatchEqual,
			value:     fwpValue0{typ: fwpV4AddrMask, value: uintptr(unsafe.Pointer(m))},
		}
	}
	m := new(fwpV6AddrAndMask)
	m.addr = prefix.Addr().As16()
	m.prefixLength = uint8(prefix.Bits())
	b.keep = append(b.keep, m)
	return fwpmFilterCondition0{
		fieldKey:  condRemoteAddress,
		matchType: fwpMatchEqual,
		value:     fwpValue0{typ: fwpV6AddrMask, value: uintptr(unsafe.Pointer(m))},
	}
}

func loopback() fwpmFilterCondition0 {
	return fwpmFilterCondition0{
		fieldKey:  condFlags,
		matchType: fwpMatchFlagsAllSet,
		value:     fwpValue0{typ: fwpUint32, value: fwpConditionFlagIsLoopback},
	}
}

func remotePort(port uint16) fwpmFilterCondition0 {
	return fwpmFilterCondition0{
		fieldKey:  condRemotePort,
		matchType: fwpMatchEqual,
		value:     fwpValue0{typ: fwpUint16, value: uintptr(port)},
	}
}

func localPort(port uint16) fwpmFilterCondition0 {
	return fwpmFilterCondition0{
		fieldKey:  condLocalPort,
		matchType: fwpMatchEqual,
		value:     fwpValue0{typ: fwpUint16, value: uintptr(port)},
	}
}

func protocol(proto uint8) fwpmFilterCondition0 {
	return fwpmFilterCondition0{
		fieldKey:  condProtocol,
		matchType: fwpMatchEqual,
		value:     fwpValue0{typ: fwpUint8, value: uintptr(proto)},
	}
}

// dhcp matches the client side of DHCP (v4: 68 -> 67, v6: 546 -> 547).
func dhcp(v6 bool) []fwpmFilterCondition0 {
	if v6 {
		return []fwpmFilterCondition0{protocol(ipProtoUDP), localPort(546), remotePort(547)}
	}
	return []fwpmFilterCondition0{protocol(ipProtoUDP), localPort(68), remotePort(67)}
}

func mustPrefixes(values ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(values))
	for _, v := range values {
		out = append(out, netip.MustParsePrefix(v))
	}
	return out
}
