//go:build darwin

package firewall

import (
	"fmt"
	"strings"
	"sync"

	"beam-tun/internal/sysexec"
)

// pf backend: the rules live in an anchor under com.apple/, which the stock
// /etc/pf.conf already evaluates (anchor "com.apple/*"), so the system
// ruleset is never edited. pf itself is enabled with a reference token
// (pfctl -E) and released with it (pfctl -X), leaving pf exactly as enabled
// or disabled as it was for everyone else.
//
// Beam runs as root on macOS (see the desktop's privilege handling), and pf
// can match the owning user of a TCP/UDP socket, so "Beam" here is "user
// root". Regular apps run as the logged-in user and are filtered.

const pfAnchor = "com.apple/250.BeamGuard"

var (
	pfMu    sync.Mutex
	pfToken string
)

func backendAvailable() bool { return sysexec.Available("pfctl") }

func backendApply(s ruleState) error {
	if err := sysexec.Run([]string{"pfctl", "-a", pfAnchor, "-f", "-"}, pfRules(s)); err != nil {
		return fmt.Errorf("firewall: %w", err)
	}
	return enablePF()
}

func backendRemove() error {
	err := sysexec.Run([]string{"pfctl", "-a", pfAnchor, "-F", "all"}, "")
	releasePF()
	if err != nil {
		return fmt.Errorf("firewall: %w", err)
	}
	return nil
}

func enablePF() error {
	pfMu.Lock()
	defer pfMu.Unlock()
	if pfToken != "" {
		return nil
	}
	out, err := sysexec.Combined([]string{"pfctl", "-E"}, "")
	if err != nil {
		return fmt.Errorf("firewall: enable pf: %w", err)
	}
	for _, line := range strings.Split(out, "\n") {
		if _, token, ok := strings.Cut(line, "Token : "); ok {
			pfToken = strings.TrimSpace(token)
		}
	}
	return nil
}

func releasePF() {
	pfMu.Lock()
	defer pfMu.Unlock()
	if pfToken == "" {
		return
	}
	_ = sysexec.Run([]string{"pfctl", "-X", pfToken}, "")
	pfToken = ""
}

func pfRules(s ruleState) string {
	var r []string
	r = append(r, "pass quick on lo0 all")
	r = append(r, "pass out quick proto { tcp udp } from any to any user root")
	if s.locked {
		r = append(r, "pass out quick inet proto udp from any port 68 to any port 67")
		r = append(r, "pass out quick inet from any to { "+strings.Join(localNets4, " ")+" }")
		r = append(r, "pass out quick inet6 from any to { "+strings.Join(localNets6, " ")+" }")
		if s.dns {
			r = append(r, "pass out quick proto { tcp udp } from any to any port 53")
		}
		r = append(r, "block drop out quick all")
	} else {
		if s.tunnel != "" {
			r = append(r, "pass out quick on "+s.tunnel+" all")
			r = append(r, "block drop out quick proto { tcp udp } from any to any port 53")
		}
		r = append(r, "pass out quick inet6 from any to { "+strings.Join(linkNets6, " ")+" }")
		r = append(r, "block drop out quick inet6 all")
	}
	return strings.Join(r, "\n") + "\n"
}
