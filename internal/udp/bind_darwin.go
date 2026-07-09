//go:build darwin

package udp

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// bindToInterface pins the socket to a physical interface via
// IP_BOUND_IF / IPV6_BOUND_IF.
func bindToInterface(c syscall.RawConn, ifname string, v4 bool) error {
	ifi, err := net.InterfaceByName(ifname)
	if err != nil {
		return err
	}
	var serr error
	cerr := c.Control(func(fd uintptr) {
		if v4 {
			serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, ifi.Index)
		} else {
			serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, ifi.Index)
		}
	})
	if cerr != nil {
		return cerr
	}
	return serr
}

// setDontFragment enables DF on outgoing packets so amane's per-path
// MTU discovery sees real path behavior. Best-effort: options for the
// non-matching address family are ignored.
func setDontFragment(c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_DONTFRAG, 1)
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_DONTFRAG, 1)
	})
}
