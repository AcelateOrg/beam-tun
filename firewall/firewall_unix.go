//go:build (linux && !android) || darwin

package firewall

import "sync"

// Firewall keeps the kill switch / leak protection state and renders it into
// one rule set of the platform backend (nftables on Linux, a pf anchor on
// macOS). Every change rewrites the whole set atomically, so the host never
// sees a half-applied state.
//
// Unlike WFP's dynamic sessions these rules outlive the process. A crashed
// Beam therefore leaves them behind; Recover clears them at the next start
// (and a kill switch that should hold after the crash is engaged again by
// the VPN manager right after).
type Firewall struct {
	mu        sync.Mutex
	locked    bool
	dns       bool
	protected bool
	tunnel    string
	active    bool
}

var defaultFirewall = &Firewall{}

// Supported reports whether the kill switch works on this platform.
func Supported() bool { return backendAvailable() }

// ruleState is what the backend renders.
type ruleState struct {
	locked    bool
	dns       bool
	protected bool
	tunnel    string
}

func (f *Firewall) commitLocked() error {
	state := ruleState{locked: f.locked, dns: f.dns, protected: f.protected, tunnel: f.tunnel}
	if !state.locked && !state.protected {
		if !f.active {
			return nil
		}
		err := backendRemove()
		if err == nil {
			f.active = false
		}
		return err
	}
	if err := backendApply(state); err != nil {
		return err
	}
	f.active = true
	return nil
}

// Lockdown cuts everything but Beam, loopback, the local network and DHCP.
func (f *Firewall) Lockdown() error {
	if !Supported() {
		return ErrUnsupported
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.locked, f.dns = true, false
	return f.commitLocked()
}

// AllowDNS opens plain DNS while the lockdown holds (reconnect attempts).
func (f *Firewall) AllowDNS(allow bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.locked || f.dns == allow {
		return nil
	}
	f.dns = allow
	return f.commitLocked()
}

// Unlock releases the lockdown.
func (f *Firewall) Unlock() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.locked {
		return nil
	}
	f.locked, f.dns = false, false
	return f.commitLocked()
}

func (f *Firewall) Locked() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.locked
}

// Protect blocks DNS outside the tunnel and all IPv6 for everything but
// Beam. The argument (the adapter LUID on Windows) is unused here: the
// tunnel is identified by its interface name, see SetTunnelInterface.
func (f *Firewall) Protect(uint64) error {
	if !Supported() {
		return ErrUnsupported
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.protected = true
	return f.commitLocked()
}

func (f *Firewall) Unprotect() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.protected {
		return nil
	}
	f.protected = false
	return f.commitLocked()
}

func (f *Firewall) Protected() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.protected
}

// SetTunnelInterface names the tunnel interface whose traffic is allowed
// while the leak protection is on.
func (f *Firewall) SetTunnelInterface(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.tunnel == name {
		return
	}
	f.tunnel = name
	if f.protected {
		_ = f.commitLocked()
	}
}

// AttachTunnel is the WFP inbound/IPv6 filter of Windows. Here the stack
// needs no inbound rule and the IPv6 cut-off is a routing matter (netcfg).
func (f *Firewall) AttachTunnel(uint64) error { return ErrUnsupported }
func (f *Firewall) DetachTunnel() error       { return nil }

// Recover removes rules a crashed run left behind. It never touches a state
// this process has already set up.
func (f *Firewall) Recover() {
	if !Supported() {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.locked || f.protected {
		return
	}
	_ = backendRemove()
	f.active = false
}

// Local destinations stay reachable during the lockdown, like on Windows:
// printers, NAS, the router's admin page and DHCP.
var (
	localNets4 = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32"}
	localNets6 = []string{"fe80::/10", "fc00::/7", "ff00::/8"}
	// Link-local and multicast keep neighbour discovery working while all
	// other IPv6 is blocked.
	linkNets6 = []string{"fe80::/10", "ff00::/8"}
)
