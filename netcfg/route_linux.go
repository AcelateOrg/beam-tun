//go:build linux && !android

package netcfg

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// hostRoute is a default route of the host: the gateway and the interface
// that carries it.
type hostRoute struct {
	gateway netip.Addr
	iface   string
}

// DefaultInterface returns the interface holding the IPv4 default route,
// the tunnel excluded. Read from /proc: no process spawn, and the split /1
// routes of the tunnel never look like a default route there.
func DefaultInterface(exclude string) (string, error) {
	route, err := defaultRoute4(exclude)
	if err != nil {
		return "", err
	}
	return route.iface, nil
}

// defaultRoute4 parses /proc/net/route:
//
//	Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
//	eth0  00000000    0101A8C0 0003 0 0 100 00000000 0 0 0
//
// Addresses are the raw in_addr words printed in host byte order.
func defaultRoute4(exclude string) (hostRoute, error) {
	file, err := os.Open("/proc/net/route")
	if err != nil {
		return hostRoute{}, err
	}
	defer file.Close()

	best := hostRoute{}
	bestMetric := uint64(math.MaxUint64)
	scanner := bufio.NewScanner(file)
	scanner.Scan() // header
	for scanner.Scan() {
		f := strings.Fields(scanner.Text())
		if len(f) < 8 || f[1] != "00000000" || f[7] != "00000000" {
			continue
		}
		if f[0] == exclude {
			continue
		}
		flags, _ := strconv.ParseUint(f[3], 16, 32)
		const rtfUp, rtfGateway = 0x1, 0x2
		if flags&rtfUp == 0 {
			continue
		}
		metric, _ := strconv.ParseUint(f[6], 10, 64)
		if metric >= bestMetric {
			continue
		}
		gw := netip.Addr{}
		if flags&rtfGateway != 0 {
			raw, err := strconv.ParseUint(f[2], 16, 32)
			if err != nil {
				continue
			}
			var b [4]byte
			binary.NativeEndian.PutUint32(b[:], uint32(raw))
			gw = netip.AddrFrom4(b)
		}
		best = hostRoute{gateway: gw, iface: f[0]}
		bestMetric = metric
	}
	if best.iface == "" {
		return hostRoute{}, fmt.Errorf("tun: no default route to bypass through")
	}
	return best, nil
}

// defaultRoute6 parses /proc/net/ipv6_route:
//
//	dest(32) dlen src(32) slen nexthop(32) metric refcnt use flags iface
//
// ok is false when the host has no IPv6 default route (no IPv6 uplink).
func defaultRoute6(exclude string) (hostRoute, bool) {
	file, err := os.Open("/proc/net/ipv6_route")
	if err != nil {
		return hostRoute{}, false
	}
	defer file.Close()

	const zero = "00000000000000000000000000000000"
	best := hostRoute{}
	bestMetric := uint64(math.MaxUint64)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		f := strings.Fields(scanner.Text())
		if len(f) < 10 || f[0] != zero || f[1] != "00" {
			continue
		}
		iface := f[9]
		if iface == "lo" || iface == exclude {
			continue
		}
		flags, _ := strconv.ParseUint(f[8], 16, 32)
		const rtfUp, rtfReject = 0x1, 0x200
		if flags&rtfUp == 0 || flags&rtfReject != 0 {
			continue
		}
		metric, _ := strconv.ParseUint(f[5], 16, 64)
		if metric >= bestMetric {
			continue
		}
		raw, err := hex.DecodeString(f[4])
		if err != nil || len(raw) != 16 {
			continue
		}
		best = hostRoute{gateway: netip.AddrFrom16([16]byte(raw)), iface: iface}
		bestMetric = metric
	}
	return best, best.iface != ""
}
