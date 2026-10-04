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
	var inflightMu sync.Mutex
	inflight := make(map[byte]bool)
	t := time.NewTicker(wanInfoSweep)
	defer t.Stop()
	for {
		select {
		case <-e.stop:
			return
		case <-t.C:
		}
		if e.sess == nil {
			continue
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
			go func(p *path.Path) {
				defer func() {
					inflightMu.Lock()
					delete(inflight, p.ID)
					inflightMu.Unlock()
				}()
				ctx, cancel := context.WithTimeout(context.Background(), wanInfoTimeout)
				defer cancel()
				info, err := ipinfo.Lookup(ctx, p.IfName, e.userAgent)
				if err != nil {
					e.log.Debug("wan info lookup", "if", p.IfName, "err", err)
					return
				}
				p.SetWANInfo(&info)
				e.log.Info("wan info", "if", p.IfName, "ip", info.IP, "asn", info.ASN, "org", info.ASOrg)
			}(p)
		}
	}
}
