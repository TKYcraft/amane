//go:build linux

package ipinfo

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// bindToInterface pins a TCP socket to ifname via SO_BINDTODEVICE so the
// resulting HTTP request leaves through that specific link regardless
// of the main routing table.
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
