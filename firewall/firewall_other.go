//go:build !windows && !darwin && (!linux || android)

package firewall

// Firewall is a stub on platforms without a backend: nothing is filtered.
type Firewall struct{}

var defaultFirewall = &Firewall{}

// Supported reports whether the kill switch works on this platform.
func Supported() bool { return false }

func (f *Firewall) Lockdown() error           { return ErrUnsupported }
func (f *Firewall) AllowDNS(bool) error       { return nil }
func (f *Firewall) Unlock() error             { return nil }
func (f *Firewall) Locked() bool              { return false }
func (f *Firewall) Protect(uint64) error      { return ErrUnsupported }
func (f *Firewall) Unprotect() error          { return nil }
func (f *Firewall) Protected() bool           { return false }
func (f *Firewall) AttachTunnel(uint64) error { return ErrUnsupported }
func (f *Firewall) DetachTunnel() error       { return nil }
func (f *Firewall) SetTunnelInterface(string) {}
func (f *Firewall) Recover()                  {}
