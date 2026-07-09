package engine

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/TKYcraft/amane/internal/config"
	"github.com/TKYcraft/amane/internal/ctl"
	"github.com/TKYcraft/amane/internal/path"
	"github.com/TKYcraft/amane/internal/sched"
)

// Status implements ctl.Daemon.
func (e *Engine) Status() ctl.Status {
	st := ctl.Status{TunName: e.tun.Name()}
	if e.role == RoleClient {
		st.Role = "client"
		st.Sessions = append(st.Sessions, e.sess.status())
	} else {
		st.Role = "server"
		e.peersMu.RLock()
		sessions := make([]*session, 0, len(e.peers))
		for _, s := range e.peers {
			sessions = append(sessions, s)
		}
		e.peersMu.RUnlock()
		sort.Slice(sessions, func(i, j int) bool { return sessions[i].name < sessions[j].name })
		for _, s := range sessions {
			st.Sessions = append(st.Sessions, s.status())
		}
	}
	return st
}

func (s *session) status() ctl.SessionStatus {
	out := ctl.SessionStatus{
		Name:       s.name,
		State:      "connecting",
		Mode:       s.sched.Mode().String(),
		DropNoPath: s.dropNoPath.Load() + s.dropNoEpoch.Load(),
	}
	if ep := s.txEpoch.Load(); ep != nil {
		out.State = "up"
		out.EpochAgeSec = time.Since(ep.CreatedAt()).Seconds()
	}
	if s.eng.role == RoleClient {
		out.Endpoint = s.eng.serverAddr.String()
	}
	rs := s.reorder.Snapshot()
	out.Reorder = ctl.ReorderStatus{
		TimeoutFlush: rs.TimeoutFlush,
		LatePass:     rs.LatePass,
		DupDrop:      rs.DupDrop,
		Held:         rs.Held,
		HeldOldestMs: rs.HeldOldestMs,
	}
	es, ds := s.fecEnc.Stats(), s.fecDec.Stats()
	out.FEC = ctl.FECStatus{
		ParitySent: es.ParitySent,
		Recovered:  ds.Recovered,
		Failed:     ds.Failed,
	}
	for i := range s.paths {
		p := s.paths[i].Load()
		if p == nil {
			continue
		}
		m := p.Metrics()
		tx, rx := p.Rates()
		ps := ctl.PathStatus{
			ID:      p.ID,
			IfName:  p.IfName,
			State:   p.State().String(),
			MTU:     p.AppliedMTU(),
			SRTTMs:  float64(m.SRTT.Microseconds()) / 1000,
			LossPct: m.Loss * 100,
			TxBps:   tx,
			RxBps:   rx,
			Weight:  s.sched.PathWeight(p.ID),
		}
		if ep := p.Endpoint(); ep.IsValid() {
			ps.Endpoint = ep.String()
		}
		out.Paths = append(out.Paths, ps)
	}
	return out
}

// AddLink implements ctl.Daemon (client only).
func (e *Engine) AddLink(ifname string, initialMbps float64) error {
	if e.role != RoleClient {
		return errors.New("links are managed on the client")
	}
	for _, l := range e.ccfg.Links.Link {
		if l.Interface == ifname {
			return fmt.Errorf("link %s already configured", ifname)
		}
	}
	e.ccfg.Links.Link = append(e.ccfg.Links.Link, config.Link{Interface: ifname, InitialMbps: initialMbps})
	e.setupLinks()
	return nil
}

// RemoveLink implements ctl.Daemon (client only).
func (e *Engine) RemoveLink(ifname string) error {
	if e.role != RoleClient {
		return errors.New("links are managed on the client")
	}
	links := e.ccfg.Links.Link
	for i, l := range links {
		if l.Interface == ifname {
			e.ccfg.Links.Link = append(links[:i], links[i+1:]...)
			// Down it immediately even if auto mode would re-add it later;
			// explicit removal wins until the next hotplug event.
			for j := range e.sess.paths {
				if p := e.sess.paths[j].Load(); p != nil && p.IfName == ifname {
					e.markLinkGone(p)
				}
			}
			return nil
		}
	}
	// Not explicitly configured: maybe an auto-detected link.
	for j := range e.sess.paths {
		if p := e.sess.paths[j].Load(); p != nil && p.IfName == ifname && p.State() != path.Removed {
			e.markLinkGone(p)
			return nil
		}
	}
	return fmt.Errorf("no such link %s", ifname)
}

// SetMode implements ctl.Daemon. The server mirrors each client's mode
// automatically (from the duplicate flag on data packets), so manual
// switching is client-only.
func (e *Engine) SetMode(mode string) error {
	if e.role != RoleClient {
		return errors.New("mode is controlled by the client; the server mirrors it per session")
	}
	m, ok := sched.ParseMode(mode)
	if !ok {
		return fmt.Errorf("unknown mode %q", mode)
	}
	e.sess.sched.SetMode(m)
	return nil
}
