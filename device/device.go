// Package device opens the OS TUN adapter and exposes it as a tun.Device
// (with batch read/write where the platform supports it).
//
// Windows owns a WinTun session directly (device_windows.go); other platforms
// go through wireguard-go (device_other.go).
package device

import "errors"

// ErrAdapterBusy is returned by Open when the adapter with the requested name
// is held by a live session of another process.
var ErrAdapterBusy = errors.New("tun: adapter is in use by another process (another Beam or VPN client is connected)")
