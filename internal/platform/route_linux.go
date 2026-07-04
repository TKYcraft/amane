//go:build linux

package platform

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
)

// ConfigureTUN assigns the tunnel address, sets the MTU, and brings the
// interface up. Kernel state tied to the interface (address, routes)
// disappears with it when the TUN fd closes, so no cleanup is needed.
func ConfigureTUN(ifname string, addr netip.Prefix, mtu int) error {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return fmt.Errorf("tun %s: %w", ifname, err)
	}
	nlAddr, err := netlink.ParseAddr(addr.String())
	if err != nil {
		return err
	}
	if err := netlink.AddrAdd(link, nlAddr); err != nil {
		return fmt.Errorf("addr add %s: %w", addr, err)
	}
	if err := netlink.LinkSetMTU(link, mtu); err != nil {
		return fmt.Errorf("set mtu: %w", err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("link up: %w", err)
	}
	return nil
}

// AddRoutes points prefixes at the TUN interface. A default route is
// installed as two /1 halves so it takes precedence over the existing
// default without replacing it (the WireGuard convention).
func AddRoutes(ifname string, routes []netip.Prefix) error {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}
	for _, p := range splitDefaults(routes) {
		rt := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst: &net.IPNet{
				IP:   p.Addr().AsSlice(),
				Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen()),
			},
		}
		if err := netlink.RouteAdd(rt); err != nil {
			return fmt.Errorf("route add %s: %w", p, err)
		}
	}
	return nil
}

// splitDefaults replaces 0.0.0.0/0 and ::/0 with two /1 routes each.
func splitDefaults(routes []netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range routes {
		if p.Bits() == 0 {
			if p.Addr().Is4() {
				out = append(out,
					netip.MustParsePrefix("0.0.0.0/1"),
					netip.MustParsePrefix("128.0.0.0/1"))
			} else {
				out = append(out,
					netip.MustParsePrefix("::/1"),
					netip.MustParsePrefix("8000::/1"))
			}
			continue
		}
		out = append(out, p)
	}
	return out
}
