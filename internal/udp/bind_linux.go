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
