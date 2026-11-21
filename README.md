# Beam TUN

TUN layer of the **Beam** VPN client: captures system traffic on a virtual
adapter and hands TCP/UDP flows to the proxy core.

Windows, Linux and macOS.

## Packages

| Package    | What it does |
|------------|--------------|
| `device`   | Virtual adapter: Wintun on Windows, `/dev/net/tun` on Linux, `utun` on macOS |
| `stack`    | Userspace TCP/UDP stack, ICMP echo relay (ping / traceroute) |
| `netcfg`   | Address, routes, DNS, bypass routes for proxy servers, IPv6 leak guard, network change monitor |
| `firewall` | Kill switch and DNS/IPv6 leak protection: WFP / nftables / pf |
| `process`  | Finds the app that owns a flow, for per-app routing |
| `dialer`   | Sockets pinned to the physical interface (direct traffic) |

## Usage

Beam TUN is a library, consumed by `beam-bridge`:

```go
require beam-tun v0.0.0
replace beam-tun => ../beam-tun
```

Creating the adapter and changing routes needs administrator rights
(Windows), root or `CAP_NET_ADMIN` (Linux), root (macOS).

## License

[Mozilla Public License 2.0](LICENSE). © AcelateOrg.

Uses [Wintun](https://www.wintun.net/) and
[wireguard-go](https://git.zx2c4.com/wireguard-go) TUN drivers (MIT).
