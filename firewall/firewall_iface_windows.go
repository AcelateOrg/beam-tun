//go:build windows

package firewall

// SetTunnelInterface is a no-op on Windows: the filters are bound to the
// adapter LUID passed to Protect / AttachTunnel.
func (f *Firewall) SetTunnelInterface(string) {}

// Recover is a no-op on Windows: WFP dynamic sessions die with the process,
// so a crash never leaves filters behind.
func (f *Firewall) Recover() {}
