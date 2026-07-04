package platform

import (
	"net"
	"net/netip"
	"path"
)

// IfEvent signals that the set of usable interfaces may have changed.
// Consumers re-enumerate with UsableInterfaces rather than tracking
// deltas, which keeps the OS-specific watchers trivial.
type IfEvent struct{}

// UsableInterfaces lists interfaces that are up, non-loopback, carry a
// global unicast (or private) IPv4 address, and don't match any exclude
// glob. names in exclude use path.Match syntax (e.g. "utun*").
func UsableInterfaces(exclude []string) ([]string, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, ifi := range ifs {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 || ifi.Flags&net.FlagPointToPoint != 0 {
			continue
		}
		if matchesAny(ifi.Name, exclude) {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			addr, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			addr = addr.Unmap()
			if addr.Is4() && (addr.IsGlobalUnicast() || addr.IsPrivate()) && !addr.IsLinkLocalUnicast() {
				out = append(out, ifi.Name)
				break
			}
		}
	}
	return out, nil
}

// HasUsableAddr reports whether the named interface currently qualifies.
func HasUsableAddr(ifname string) bool {
	names, err := UsableInterfaces(nil)
	if err != nil {
		return false
	}
	for _, n := range names {
		if n == ifname {
			return true
		}
	}
	return false
}

func matchesAny(name string, globs []string) bool {
	for _, g := range globs {
		if ok, _ := path.Match(g, name); ok {
			return true
		}
	}
	return false
}
