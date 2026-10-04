//go:build darwin

package ipinfo

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// bindToInterface pins a TCP socket to ifname via IP_BOUND_IF /
// IPV6_BOUND_IF so the HTTP request leaves through that specific link.
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
