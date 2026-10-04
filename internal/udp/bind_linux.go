//go:build linux

package udp

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// bindToInterface pins the socket to a physical interface so packets
// leave through it regardless of the main routing table.
func bindToInterface(c syscall.RawConn, ifname string, _ bool) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		serr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, ifname)
	})
	if err != nil {
		return err
	}
	return serr
}

// setDontFragment enables DF on outgoing packets and disables the
// kernel's cached-route PMTU handling (PMTUDISC_PROBE), so amane's own
// per-path MTU discovery sees real path behavior. Oversized sends fail
// with EMSGSIZE instead of fragmenting. Best-effort: options for the
// non-matching address family are ignored.
func setDontFragment(c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_PROBE)
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_PROBE)
	})
}

// setDSCP marks outgoing packets with the given DSCP code point (0-63).
// Linux puts DSCP in the high 6 bits of the IPv4 ToS / IPv6 Traffic
// Class byte, so the socket value is dscp<<2. Zero (BE) leaves the
// defaults untouched. Best-effort for the non-matching address family.
func setDSCP(c syscall.RawConn, dscp int) error {
	if dscp <= 0 {
		return nil
	}
	tos := dscp << 2
	return c.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TOS, tos)
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_TCLASS, tos)
	})
}
