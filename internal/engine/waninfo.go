package engine

import (
	"context"
	"sync"
	"time"

	"github.com/TKYcraft/amane/internal/ipinfo"
	"github.com/TKYcraft/amane/internal/path"
)

const (
	// wanInfoSweep is how often the loop checks for paths that still
	// need a WAN info lookup.
	wanInfoSweep = 15 * time.Second
	// wanInfoTimeout bounds a single HTTPS GET (dial + TLS + body).
	wanInfoTimeout = 5 * time.Second
)

// wanInfoLoop (client role) populates each path's public-IP / ASN info
// the first time the path becomes usable, and when a rebind clears it
// (MTURestart drops the cached entry). No periodic refresh: the info
// only changes when the interface state changes.
func (e *Engine) wanInfoLoop() {
	// Lookups are issued as sub-goroutines; tie their context to e.stop
	// so Stop() aborts in-flight HTTP requests instead of leaving them
	// to run out their 5s timeout.
	fetchCtx, fetchCancel := context.WithCancel(context.Background())
	defer fetchCancel()
	go func() {
		select {
		case <-e.stop:
			fetchCancel()
		case <-fetchCtx.Done():
		}
	}()

	var inflightMu sync.Mutex
	inflight := make(map[byte]bool)

	sweep := func() {
		if e.sess == nil {
			return
		}
		for i := range e.sess.paths {
			p := e.sess.paths[i].Load()
			if p == nil || p.State() == path.Removed || p.State() == path.Down {
				continue
			}
			if p.WANInfo() != nil {
				continue
			}
			inflightMu.Lock()
			if inflight[p.ID] {
				inflightMu.Unlock()
				continue
			}
			inflight[p.ID] = true
			inflightMu.Unlock()
			e.wg.Add(1)
			go func(p *path.Path) {
				defer e.wg.Done()
				defer func() {
					inflightMu.Lock()
					delete(inflight, p.ID)
					inflightMu.Unlock()
				}()
				ctx, cancel := context.WithTimeout(fetchCtx, wanInfoTimeout)
				defer cancel()
				// Pin the lookup to the same address family the tunnel
				// uses, so the reported public IP matches the family of
				// the actual UDP traffic.
				v4 := e.serverAddr.Addr().Is4()
				info, err := ipinfo.Lookup(ctx, p.IfName, e.userAgent, v4)
				if err != nil {
					e.log.Debug("wan info lookup", "if", p.IfName, "err", err)
					return
				}
				p.SetWANInfo(&info)
				e.log.Info("wan info", "if", p.IfName, "ip", info.IP, "asn", info.ASN, "org", info.ASOrg)
			}(p)
		}
	}

	// Fire once immediately so the first lookup lands within the handshake
	// window rather than waiting a full sweep interval.
	sweep()
	t := time.NewTicker(wanInfoSweep)
	defer t.Stop()
	for {
		select {
		case <-e.stop:
			return
		case <-t.C:
			sweep()
		}
	}
}
