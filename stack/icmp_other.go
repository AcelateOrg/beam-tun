//go:build !windows && !darwin && (!linux || android)

package stack

import (
	"errors"
	"net/netip"
	"time"
)

// Ping relaying is implemented for Windows, Linux and macOS.
const echoSupported = false

func sendEcho4(netip.Addr, netip.Addr, uint8, []byte, time.Duration) (echoResult, error) {
	return echoResult{}, errors.New("stack: ICMP relaying is not supported on this platform")
}
