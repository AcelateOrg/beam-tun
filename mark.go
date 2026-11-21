package tun

// SocketMark is the fwmark (SO_MARK) Beam puts on its own sockets on Linux:
// the core's outbounds, the direct dialer and relayed pings. Linux cannot
// filter by process the way WFP does, so the kill switch and the leak
// protection (nftables, see firewall) let marked packets through instead.
// Nothing routes by this mark; it only identifies Beam's traffic.
const SocketMark = 0x0be4a
