//go:build linux && !android

package process

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

// sysState maps socket inodes to PIDs. Building it means walking every
// /proc/<pid>/fd, so it is rebuilt only when a flow's inode is missing
// from a map taken before that flow was seen.
type sysState struct {
	inodes  map[uint64]uint32
	scanned time.Time
}

func fetchTable(network string) ([]tableRow, error) {
	var rows []tableRow
	var firstErr error
	ok := false
	for _, name := range []string{network, network + "6"} {
		data, err := os.ReadFile("/proc/net/" + name)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		ok = true
		rows = parseProcNet(data, rows)
	}
	if !ok {
		return nil, firstErr
	}
	return rows, nil
}

// parseProcNet reads /proc/net/{tcp,udp}[6]: field 1 is the local
// "ADDR:PORT" (address words in host byte order, port big-endian hex),
// field 9 the socket inode.
func parseProcNet(data []byte, rows []tableRow) []tableRow {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}
		host, portHex, found := strings.Cut(fields[1], ":")
		if !found {
			continue
		}
		port, err := strconv.ParseUint(portHex, 16, 16)
		if err != nil {
			continue
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil || inode == 0 {
			continue
		}
		raw, err := hex.DecodeString(host)
		if err != nil || (len(raw) != 4 && len(raw) != 16) {
			continue
		}
		// Each 32-bit word was printed as a host-order integer.
		for i := 0; i+4 <= len(raw); i += 4 {
			word := binary.BigEndian.Uint32(raw[i:])
			binary.NativeEndian.PutUint32(raw[i:], word)
		}
		addr, ok := netip.AddrFromSlice(raw)
		if !ok {
			continue
		}
		row := tableRow{addr: addr.Unmap(), port: uint16(port), owner: inode}
		rows = append(rows, row)
	}
	return rows
}

func (r *resolver) pidOf(inode uint64, seen time.Time) (uint32, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if pid, ok := r.sys.inodes[inode]; ok {
		return pid, nil
	}
	if !r.sys.scanned.IsZero() && !r.sys.scanned.Before(seen) {
		return 0, ErrNotFound
	}
	started := time.Now()
	r.sys.inodes = scanSocketInodes()
	r.sys.scanned = started
	if pid, ok := r.sys.inodes[inode]; ok {
		return pid, nil
	}
	return 0, ErrNotFound
}

func scanSocketInodes() map[uint64]uint32 {
	inodes := make(map[uint64]uint32, 1024)
	proc, err := os.Open("/proc")
	if err != nil {
		return inodes
	}
	names, _ := proc.Readdirnames(-1)
	proc.Close()

	self := os.Getpid()
	for _, name := range names {
		pid, err := strconv.ParseUint(name, 10, 32)
		if err != nil || int(pid) == self {
			continue
		}
		dir := "/proc/" + name + "/fd/"
		fd, err := os.Open(dir)
		if err != nil {
			continue
		}
		fds, _ := fd.Readdirnames(-1)
		fd.Close()
		for _, f := range fds {
			link, err := os.Readlink(dir + f)
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			inode, err := strconv.ParseUint(strings.TrimSuffix(link[len("socket:["):], "]"), 10, 64)
			if err != nil {
				continue
			}
			if _, dup := inodes[inode]; !dup {
				inodes[inode] = uint32(pid)
			}
		}
	}
	return inodes
}

func queryProcessPath(pid uint32) (string, error) {
	path, err := os.Readlink("/proc/" + strconv.FormatUint(uint64(pid), 10) + "/exe")
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(path, " (deleted)"), nil
}
