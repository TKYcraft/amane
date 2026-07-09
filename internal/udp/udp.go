// Package udp creates the outer sockets: per-path client sockets bound to
// a physical interface, and the server's listen socket.
//
// I/O is one datagram per syscall for now; if profiling shows syscall
// pressure, swap in x/net ipv4 ReadBatch/WriteBatch (sendmmsg/recvmmsg)
// behind this package without touching the engine.
package udp

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"syscall"
)

// Resolve resolves "host:port" to an address, preferring IPv4.
func Resolve(hostport string) (netip.AddrPort, error) {
	ua, err := net.ResolveUDPAddr("udp4", hostport)
	if err != nil {
		ua, err = net.ResolveUDPAddr("udp", hostport)
		if err != nil {
			return netip.AddrPort{}, err
		}
	}
	ap := ua.AddrPort()
	// Normalize 4-in-6 so comparisons against packet sources match.
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), nil
}

// InterfaceAddr returns a global unicast address on the interface,
// matching the address family of remote.
func InterfaceAddr(ifname string, remote netip.Addr) (netip.Addr, error) {
	ifi, err := net.InterfaceByName(ifname)
	if err != nil {
		return netip.Addr{}, err
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return netip.Addr{}, err
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
		if addr.Is4() != remote.Is4() {
			continue
		}
		if addr.IsGlobalUnicast() || addr.IsPrivate() {
			return addr, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("no usable %s address on %s", family(remote), ifname)
}

func family(a netip.Addr) string {
	if a.Is4() {
		return "IPv4"
	}
	return "IPv6"
}

// DialBound creates a UDP socket bound to the interface and its current
// address, connected to remote. Connecting pins the route through the
// interface and filters inbound traffic to the server address.
func DialBound(ifname string, remote netip.AddrPort) (*net.UDPConn, netip.Addr, error) {
	local, err := InterfaceAddr(ifname, remote.Addr())
	if err != nil {
		return nil, netip.Addr{}, err
	}
	d := net.Dialer{
		LocalAddr: net.UDPAddrFromAddrPort(netip.AddrPortFrom(local, 0)),
		Control: func(network, address string, c syscall.RawConn) error {
			if err := bindToInterface(c, ifname, remote.Addr().Is4()); err != nil {
				return err
			}
			return setDontFragment(c)
		},
	}
	network := "udp4"
	if !remote.Addr().Is4() {
		network = "udp6"
	}
	conn, err := d.Dial(network, remote.String())
	if err != nil {
		return nil, netip.Addr{}, fmt.Errorf("dial via %s: %w", ifname, err)
	}
	return conn.(*net.UDPConn), local, nil
}

// Listen opens the server's listen socket (DF set for path MTU
// discovery).
func Listen(addr string) (*net.UDPConn, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return setDontFragment(c)
		},
	}
	pc, err := lc.ListenPacket(context.Background(), "udp", addr)
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}
