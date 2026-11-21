//go:build darwin

package process

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"time"

	"golang.org/x/sys/unix"
)

// sysState is unused on macOS: the PCB list already carries the PID.
type sysState struct{}

const (
	xsoSocket = 0x001
	xsoInpcb  = 0x010

	inpIPv4 = 0x1
	inpIPv6 = 0x2
)

func fetchTable(network string) ([]tableRow, error) {
	buf, err := unix.SysctlRaw("net.inet." + network + ".pcblist_n")
	if err != nil {
		return nil, err
	}
	return parsePCBList(buf), nil
}

// parsePCBList walks the pcblist_n records: an xinpgen header, then per
// socket a run of 8-byte aligned records (xinpcb_n, xsocket_n, buffers,
// stats, tcpcb) each starting with {u32 len, u32 kind}.
func parsePCBList(buf []byte) []tableRow {
	if len(buf) < 4 {
		return nil
	}
	header := int(binary.NativeEndian.Uint32(buf))
	if header <= 0 || header > len(buf) {
		return nil
	}

	var rows []tableRow
	var pending tableRow
	havePending := false
	for off := roundup8(header); off+8 <= len(buf); {
		size := int(binary.NativeEndian.Uint32(buf[off:]))
		kind := binary.NativeEndian.Uint32(buf[off+4:])
		if size < 8 || off+size > len(buf) {
			break
		}
		rec := buf[off : off+size]
		switch kind {
		case xsoInpcb:
			havePending = false
			if len(rec) < 80 {
				break
			}
			port := binary.BigEndian.Uint16(rec[18:20])
			flag := rec[44]
			var addr netip.Addr
			switch {
			case flag&inpIPv4 != 0:
				addr = netip.AddrFrom4([4]byte(rec[76:80]))
			case flag&inpIPv6 != 0:
				addr = netip.AddrFrom16([16]byte(rec[64:80])).Unmap()
			default:
				break
			}
			if addr.IsValid() {
				pending = tableRow{addr: addr, port: port}
				havePending = true
			}
		case xsoSocket:
			if !havePending || len(rec) < 72 {
				break
			}
			pid := binary.NativeEndian.Uint32(rec[68:72])
			// so_e_pid is the effective (delegated) owner, e.g. the app
			// behind a system networking daemon.
			if len(rec) >= 76 {
				if epid := binary.NativeEndian.Uint32(rec[72:76]); epid != 0 {
					pid = epid
				}
			}
			if pid != 0 {
				pending.owner = uint64(pid)
				rows = append(rows, pending)
			}
			havePending = false
		}
		off += roundup8(size)
	}
	return rows
}

func roundup8(n int) int { return (n + 7) &^ 7 }

func (r *resolver) pidOf(owner uint64, _ time.Time) (uint32, error) {
	if owner == 0 {
		return 0, ErrNotFound
	}
	return uint32(owner), nil
}

// queryProcessPath reads the executable path from kern.procargs2:
// int32 argc followed by the NUL-terminated exec path.
func queryProcessPath(pid uint32) (string, error) {
	buf, err := unix.SysctlRaw("kern.procargs2", int(pid))
	if err != nil {
		return "", err
	}
	if len(buf) <= 4 {
		return "", ErrNotFound
	}
	buf = buf[4:]
	if i := bytes.IndexByte(buf, 0); i >= 0 {
		buf = buf[:i]
	}
	return string(buf), nil
}
