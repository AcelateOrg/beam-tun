//go:build darwin

package netcfg

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"

	"beam-tun/internal/sysexec"
)

// macOS resolves through mDNSResponder, which follows the DNS of the primary
// network service in the System Configuration dynamic store. While the tunnel
// is up that entry (State:/Network/Service/<id>/DNS) points at the tunnel
// resolver; the original is kept in memory and in a backup file and written
// back on close. The dynamic store does not survive a reboot, and /var/run is
// cleared at boot too, so a backup left by a crash can only ever describe the
// current boot; RecoverStale restores it at the next start.

const dnsBackupFile = "/var/run/beam-dns-backup.json"

type dnsState struct {
	Service       string   `json:"service"`
	Present       bool     `json:"present"`
	Servers       []string `json:"servers,omitempty"`
	SearchDomains []string `json:"search,omitempty"`
	DomainName    string   `json:"domain,omitempty"`
}

type dnsOverride struct {
	mu     sync.Mutex
	dns    netip.Addr
	backup *dnsState
}

func (d *dnsOverride) apply() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	service, err := primaryService()
	if err != nil {
		return err
	}
	// The primary service changed (Wi-Fi -> Ethernet): give the old one its
	// resolver back before taking over the new one.
	if d.backup != nil && d.backup.Service != service {
		_ = writeDNS(*d.backup)
		d.backup = nil
	}

	current := readDNS(service)
	if d.backup == nil || !isOurs(current, d.dns) {
		// Never back up our own override (a Reapply on an unchanged network).
		if !isOurs(current, d.dns) {
			d.backup = &current
			saveDNSBackup(current)
		}
	}

	override := dnsState{Service: service, Present: true, Servers: []string{d.dns.String()}}
	if d.backup != nil {
		override.SearchDomains = d.backup.SearchDomains
		override.DomainName = d.backup.DomainName
	}
	if err := writeDNS(override); err != nil {
		return fmt.Errorf("tun: set dns: %w", err)
	}
	flushDNSCache()
	return nil
}

func (d *dnsOverride) release() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.backup == nil {
		return
	}
	_ = writeDNS(*d.backup)
	d.backup = nil
	_ = os.Remove(dnsBackupFile)
	flushDNSCache()
}

func isOurs(s dnsState, dns netip.Addr) bool {
	return s.Present && len(s.Servers) == 1 && s.Servers[0] == dns.String()
}

func restoreStaleDNS() {
	raw, err := os.ReadFile(dnsBackupFile)
	if err != nil {
		return
	}
	var s dnsState
	if json.Unmarshal(raw, &s) == nil && s.Service != "" {
		_ = writeDNS(s)
		flushDNSCache()
	}
	_ = os.Remove(dnsBackupFile)
}

func saveDNSBackup(s dnsState) {
	if raw, err := json.Marshal(s); err == nil {
		_ = os.WriteFile(dnsBackupFile, raw, 0o600)
	}
}

func scutil(script string) (string, error) {
	return sysexec.OutputInput([]string{"scutil"}, script)
}

func primaryService() (string, error) {
	out, err := scutil("show State:/Network/Global/IPv4\n")
	if err != nil {
		return "", fmt.Errorf("tun: read primary service: %w", err)
	}
	if v := parseDict(out).scalar["PrimaryService"]; v != "" {
		return v, nil
	}
	return "", fmt.Errorf("tun: no primary network service")
}

func readDNS(service string) dnsState {
	s := dnsState{Service: service}
	out, err := scutil("show State:/Network/Service/" + service + "/DNS\n")
	if err != nil || strings.Contains(out, "No such key") {
		return s
	}
	d := parseDict(out)
	s.Present = true
	s.Servers = d.arrays["ServerAddresses"]
	s.SearchDomains = d.arrays["SearchDomains"]
	s.DomainName = d.scalar["DomainName"]
	return s
}

func writeDNS(s dnsState) error {
	key := "State:/Network/Service/" + s.Service + "/DNS"
	if !s.Present {
		_, err := scutil("remove " + key + "\n")
		return err
	}
	var b strings.Builder
	b.WriteString("d.init\n")
	if len(s.Servers) > 0 {
		b.WriteString("d.add ServerAddresses * " + strings.Join(s.Servers, " ") + "\n")
	}
	if len(s.SearchDomains) > 0 {
		b.WriteString("d.add SearchDomains * " + strings.Join(s.SearchDomains, " ") + "\n")
	}
	if s.DomainName != "" {
		b.WriteString("d.add DomainName " + s.DomainName + "\n")
	}
	b.WriteString("set " + key + "\n")
	_, err := scutil(b.String())
	return err
}

func flushDNSCache() {
	_ = sysexec.Run([]string{"dscacheutil", "-flushcache"}, "")
	_ = sysexec.Run([]string{"killall", "-HUP", "mDNSResponder"}, "")
}

type scDict struct {
	scalar map[string]string
	arrays map[string][]string
}

// parseDict reads the top level of scutil's "show" output:
//
//	<dictionary> {
//	  PrimaryService : 1A2B...
//	  ServerAddresses : <array> {
//	    0 : 192.168.1.1
//	  }
//	}
func parseDict(out string) scDict {
	d := scDict{scalar: map[string]string{}, arrays: map[string][]string{}}
	var array string
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "}" {
			array = ""
			continue
		}
		key, value, ok := strings.Cut(line, " : ")
		if !ok {
			continue
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if array != "" {
			d.arrays[array] = append(d.arrays[array], value)
			continue
		}
		if strings.HasPrefix(value, "<array>") {
			array = key
			continue
		}
		if strings.HasPrefix(value, "<dictionary>") {
			continue
		}
		d.scalar[key] = value
	}
	return d
}
