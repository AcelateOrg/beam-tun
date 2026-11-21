//go:build !linux

package tun

// SocketMarkUsable is false: only Linux marks Beam's sockets.
func SocketMarkUsable() bool { return false }
