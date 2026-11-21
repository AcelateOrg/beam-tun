//go:build linux && !android

package firewall

import (
	"fmt"
	"strings"
	"sync"

	tun "beam-tun"
	"beam-tun/internal/sysexec"
)

// nftables backend: one table of its own (inet = IPv4 and IPv6 together),
// rewritten atomically by a single `nft -f -` transaction. The table is
// declared before it is deleted, so the same script works whether or not
// it exists yet.
//
// Linux cannot match the owning process of a packet the way WFP does, so
// "Beam" means packets carrying tun.SocketMark: the core's outbounds, the
// direct dialer and relayed pings set it on their sockets.

const nftTable = "beam_guard"

var (
	nftOnce sync.Once
	nftOK   bool
)

func backendAvailable() bool {
	nftOnce.Do(func() { nftOK = sysexec.Available("nft") })
	return nftOK
}

func backendRemove() error {
	script := fmt.Sprintf("table inet %[1]s\ndelete table inet %[1]s\n", nftTable)
	if err := sysexec.Run([]string{"nft", "-f", "-"}, script); err != nil {
		return fmt.Errorf("firewall: %w", err)
	}
	return nil
}

func backendApply(s ruleState) error {
	if err := sysexec.Run([]string{"nft", "-f", "-"}, nftScript(s)); err != nil {
		return fmt.Errorf("firewall: %w", err)
	}
	return nil
}

func nftScript(s ruleState) string {
	var r []string
	rule := func(format string, args ...any) { r = append(r, fmt.Sprintf(format, args...)) }

	rule(`oifname "lo" accept`)
	rule(`meta mark 0x%x accept`, tun.SocketMark)

	if s.locked {
		rule(`udp sport 68 udp dport 67 accept`)
		rule(`udp dport 547 accept`)
		rule(`ip daddr { %s } accept`, strings.Join(localNets4, ", "))
		rule(`ip6 daddr { %s } accept`, strings.Join(localNets6, ", "))
		if s.dns {
			rule(`udp dport 53 accept`)
			rule(`tcp dport 53 accept`)
		}
		rule(`drop`)
	} else {
		if s.tunnel != "" {
			rule(`oifname %q accept`, s.tunnel)
			// DNS may only go through the tunnel. Without a known tunnel
			// interface this would cut the tunnel resolver too.
			rule(`udp dport 53 drop`)
			rule(`tcp dport 53 drop`)
		}
		rule(`ip6 daddr { %s } accept`, strings.Join(linkNets6, ", "))
		rule(`meta nfproto ipv6 drop`)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "table inet %[1]s\ndelete table inet %[1]s\n", nftTable)
	fmt.Fprintf(&b, "table inet %s {\n\tchain output {\n\t\ttype filter hook output priority 0; policy accept;\n", nftTable)
	for _, line := range r {
		b.WriteString("\t\t" + line + "\n")
	}
	b.WriteString("\t}\n}\n")
	return b.String()
}
