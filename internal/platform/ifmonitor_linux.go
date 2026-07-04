//go:build linux

package platform

import (
	"time"

	"github.com/vishvananda/netlink"
)

// WatchInterfaces delivers an IfEvent whenever links or addresses change,
// via netlink subscriptions. Events are coalesced; consumers should
// debounce and re-enumerate. The goroutine exits when stop is closed.
func WatchInterfaces(stop <-chan struct{}) (<-chan IfEvent, error) {
	linkCh := make(chan netlink.LinkUpdate, 16)
	addrCh := make(chan netlink.AddrUpdate, 16)
	done := make(chan struct{})
	if err := netlink.LinkSubscribe(linkCh, done); err != nil {
		return nil, err
	}
	if err := netlink.AddrSubscribe(addrCh, done); err != nil {
		close(done)
		return nil, err
	}
	out := make(chan IfEvent, 1)
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			case <-linkCh:
			case <-addrCh:
			}
			// Coalesce bursts (e.g. DHCP renumbering) into one event.
			select {
			case out <- IfEvent{}:
			default:
			}
		}
	}()
	return out, nil
}

// pollInterval is unused on Linux (netlink is authoritative) but kept for
// API symmetry with darwin.
const pollInterval = 0 * time.Second
