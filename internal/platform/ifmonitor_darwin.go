//go:build darwin

package platform

import (
	"syscall"
	"time"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// WatchInterfaces delivers an IfEvent whenever the PF_ROUTE socket
// reports interface or address changes, with a periodic poll as a
// fallback. The goroutine exits when stop is closed.
func WatchInterfaces(stop <-chan struct{}) (<-chan IfEvent, error) {
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	out := make(chan IfEvent, 1)
	notify := func() {
		select {
		case out <- IfEvent{}:
		default:
		}
	}
	go func() {
		defer unix.Close(fd)
		buf := make([]byte, 4096)
		for {
			n, err := unix.Read(fd, buf)
			if err != nil {
				if err == syscall.EINTR {
					continue
				}
				return
			}
			msgs, err := route.ParseRIB(route.RIBTypeRoute, buf[:n])
			if err != nil {
				continue
			}
			for _, m := range msgs {
				switch m.(type) {
				case *route.InterfaceMessage, *route.InterfaceAddrMessage:
					notify()
				}
			}
		}
	}()
	go func() {
		t := time.NewTicker(pollInterval)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				notify()
			}
		}
	}()
	return out, nil
}

// pollInterval backs up the PF_ROUTE watcher in case messages are missed.
const pollInterval = 5 * time.Second
