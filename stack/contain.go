package stack

import (
	"fmt"
	"runtime/debug"
)

// The engine runs inside the app process: a panic left unrecovered on any of
// its goroutines would end the process, taking the window and the kill switch
// with it. Flow goroutines contain panics to the flow; the long-lived loops
// report the engine as failed so the owner can rebuild the tunnel.

// contain recovers a panic on a per-flow goroutine and reports it as a
// warning. Defer it directly.
func (s *Stack) contain(where string) {
	if r := recover(); r != nil {
		s.warn(fmt.Errorf("stack: panic in %s (contained): %v\n%s", where, r, debug.Stack()))
	}
}

// containFatal recovers a panic on one of the engine loops. The loop is gone,
// so the engine is reported as failed. Defer it directly.
func (s *Stack) containFatal(where string) {
	if r := recover(); r != nil {
		err := fmt.Errorf("stack: panic in %s: %v\n%s", where, r, debug.Stack())
		s.warn(err)
		if s.ctx.Err() == nil {
			s.fail(err)
		}
	}
}

// handlePacketContained drops a packet whose handling panicked instead of
// losing the read loop.
func (s *Stack) handlePacketContained(buf []byte) {
	defer s.contain("packet")
	s.handlePacket(buf)
}
