//go:build darwin

package platform

import (
	"fmt"
	"net/netip"
	"os/exec"
)

// ConfigureTUN assigns the tunnel address (point-to-point form, as utun
// requires), sets the MTU, and brings the interface up. macOS has no
// netlink equivalent, so this shells out like wireguard-tools does. utun
// interfaces and their routes vanish when the fd closes.
func ConfigureTUN(ifname string, addr netip.Prefix, mtu int) error {
	// utun is point-to-point: use our own address as the peer and rely on
	// an explicit route for the tunnel subnet.
	a := addr.Addr().String()
	if out, err := exec.Command("ifconfig", ifname, "inet", a, a, "mtu", fmt.Sprint(mtu), "up").CombinedOutput(); err != nil {
		return fmt.Errorf("ifconfig %s: %v: %s", ifname, err, out)
	}
	subnet := addr.Masked().String()
	if out, err := exec.Command("route", "-q", "-n", "add", "-inet", subnet, "-interface", ifname).CombinedOutput(); err != nil {
		return fmt.Errorf("route add %s: %v: %s", subnet, err, out)
	}
	return nil
}

// AddRoutes points prefixes at the TUN interface, splitting default
// routes into /1 halves (the WireGuard convention).
func AddRoutes(ifname string, routes []netip.Prefix) error {
	for _, p := range splitDefaultsDarwin(routes) {
		inet := "-inet"
		if !p.Addr().Is4() {
			inet = "-inet6"
		}
		if out, err := exec.Command("route", "-q", "-n", "add", inet, p.String(), "-interface", ifname).CombinedOutput(); err != nil {
			return fmt.Errorf("route add %s: %v: %s", p, err, out)
		}
	}
	return nil
}

func splitDefaultsDarwin(routes []netip.Prefix) []netip.Prefix {
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
