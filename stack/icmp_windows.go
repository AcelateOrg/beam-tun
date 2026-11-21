//go:build windows

package stack

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Echo requests are sent with IcmpSendEcho2Ex and an explicit source address
// of the physical interface. Windows uses the strong host model for sending,
// so the request leaves through the interface owning that address even
// though the tunnel holds the default route.

const echoSupported = true

var (
	icmpDLL             = windows.NewLazySystemDLL("iphlpapi.dll")
	procIcmpCreateFile  = icmpDLL.NewProc("IcmpCreateFile")
	procIcmpCloseHandle = icmpDLL.NewProc("IcmpCloseHandle")
	procIcmpSendEcho2Ex = icmpDLL.NewProc("IcmpSendEcho2Ex")
)

// IP_STATUS values (ipexport.h).
const (
	ipSuccess              = 0
	ipDestNetUnreachable   = 11002
	ipDestHostUnreachable  = 11003
	ipDestProtUnreachable  = 11004
	ipDestPortUnreachable  = 11005
	ipReqTimedOut          = 11010
	ipTTLExpiredTransit    = 11013
	ipTTLExpiredReassembly = 11014
)

// ipOptionInformation mirrors IP_OPTION_INFORMATION.
type ipOptionInformation struct {
	TTL         uint8
	TOS         uint8
	Flags       uint8
	OptionsSize uint8
	OptionsData uintptr
}

// icmpEchoReply mirrors ICMP_ECHO_REPLY for the native pointer size.
type icmpEchoReply struct {
	Address       uint32
	Status        uint32
	RoundTripTime uint32
	DataSize      uint16
	Reserved      uint16
	Data          uintptr
	Options       ipOptionInformation
}

// ioStatusBlockSize — IcmpSendEcho2Ex needs room for an IO_STATUS_BLOCK.
const ioStatusBlockSize = 16

func sendEcho4(source, destination netip.Addr, ttl uint8, data []byte, timeout time.Duration) (echoResult, error) {
	handle, _, callErr := procIcmpCreateFile.Call()
	if windows.Handle(handle) == windows.InvalidHandle {
		return echoResult{}, fmt.Errorf("IcmpCreateFile: %w", callErr)
	}
	defer procIcmpCloseHandle.Call(handle)

	if ttl == 0 {
		ttl = 128
	}
	options := ipOptionInformation{TTL: ttl}

	replySize := int(unsafe.Sizeof(icmpEchoReply{})) + len(data) + 8 + ioStatusBlockSize
	reply := make([]byte, replySize)

	var dataPtr unsafe.Pointer
	if len(data) > 0 {
		dataPtr = unsafe.Pointer(&data[0])
	}
	src4, dst4 := source.As4(), destination.As4()

	count, _, callErr := procIcmpSendEcho2Ex.Call(
		handle,
		0, 0, 0, // synchronous: no event, no APC
		uintptr(binary.LittleEndian.Uint32(src4[:])),
		uintptr(binary.LittleEndian.Uint32(dst4[:])),
		uintptr(dataPtr),
		uintptr(len(data)),
		uintptr(unsafe.Pointer(&options)),
		uintptr(unsafe.Pointer(&reply[0])),
		uintptr(replySize),
		uintptr(timeout.Milliseconds()),
	)
	runtime.KeepAlive(data)
	runtime.KeepAlive(&options)

	var status uint32
	var from netip.Addr
	var replyTTL uint8
	if count == 0 {
		var errno windows.Errno
		if !errors.As(callErr, &errno) {
			return echoResult{}, callErr
		}
		status = uint32(errno)
		// Errors like TTL-expired can still carry the reporting router.
		rep := (*icmpEchoReply)(unsafe.Pointer(&reply[0]))
		if rep.Status == status && rep.Address != 0 {
			from = addrFromIPAddr(rep.Address)
		}
	} else {
		rep := (*icmpEchoReply)(unsafe.Pointer(&reply[0]))
		status = rep.Status
		from = addrFromIPAddr(rep.Address)
		replyTTL = rep.Options.TTL
	}

	switch status {
	case ipSuccess:
		if replyTTL == 0 {
			replyTTL = 64
		}
		return echoResult{kind: echoReply, from: from, ttl: replyTTL}, nil
	case ipTTLExpiredTransit, ipTTLExpiredReassembly:
		code := uint8(0)
		if status == ipTTLExpiredReassembly {
			code = 1
		}
		return echoResult{kind: echoTimeExceeded, from: from, code: code}, nil
	case ipDestNetUnreachable:
		return echoResult{kind: echoUnreachable, from: from, code: 0}, nil
	case ipDestHostUnreachable:
		return echoResult{kind: echoUnreachable, from: from, code: 1}, nil
	case ipDestProtUnreachable:
		return echoResult{kind: echoUnreachable, from: from, code: 2}, nil
	case ipDestPortUnreachable:
		return echoResult{kind: echoUnreachable, from: from, code: 3}, nil
	case ipReqTimedOut:
		return echoResult{kind: echoNone}, nil
	}
	return echoResult{kind: echoNone}, nil
}

// addrFromIPAddr converts an IPAddr (network byte order in memory).
func addrFromIPAddr(v uint32) netip.Addr {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}
