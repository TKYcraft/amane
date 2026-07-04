package engine

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/TKYcraft/amane/internal/config"
	"github.com/TKYcraft/amane/internal/noiseio"
	"github.com/TKYcraft/amane/internal/path"
	"github.com/TKYcraft/amane/internal/pktbuf"
	"github.com/TKYcraft/amane/internal/platform"
	"github.com/TKYcraft/amane/internal/tundev"
	"github.com/TKYcraft/amane/internal/udp"
	"github.com/TKYcraft/amane/internal/wire"
)

// handshakeTimeout is the wait for a HandshakeResp before retrying.
const handshakeTimeout = 2 * time.Second

// isClosedErr reports whether a read failed because the socket was closed.
func isClosedErr(err error) bool {
	return errors.Is(err, net.ErrClosed)
}

// StartClient boots the client engine.
func StartClient(cfg *config.Client, log *slog.Logger) (*Engine, error) {
	serverAddr, err := udp.Resolve(cfg.Client.Server)
	if err != nil {
		return nil, fmt.Errorf("resolve server %q: %w", cfg.Client.Server, err)
	}

	tun, err := tundev.Open(cfg.Client.TunName, cfg.Client.MTU)
	if err != nil {
		return nil, fmt.Errorf("create tun: %w", err)
	}
	if err := platform.ConfigureTUN(tun.Name(), cfg.TunnelAddr, cfg.Client.MTU); err != nil {
		tun.Close()
		return nil, err
	}
	if err := platform.AddRoutes(tun.Name(), cfg.RoutePrefix); err != nil {
		tun.Close()
		return nil, err
	}

	e := &Engine{
		log:        log,
		role:       RoleClient,
		tun:        tun,
		mtu:        cfg.Client.MTU,
		tuning:     cfg.Tuning,
		base:       time.Now(),
		tunOut:     make(chan rxPkt, 4096),
		ccfg:       cfg,
		serverAddr: serverAddr,
		hsRespCh:   make(chan hsResp, 4),
		rekeyNow:   make(chan struct{}, 1),
		stop:       make(chan struct{}),
	}
	e.sess = newSession(e, "server", cfg.ServerPubKey, cfg.PSK, cfg.SchedMode)

	e.setupLinks()

	e.goRun("tunReader", e.tunReader)
	e.goRun("tunWriter", e.tunWriter)
	e.goRun("supervisor", e.clientSupervisor)
	e.goRun("linkManager", e.linkManager)
	e.sess.startLoops()
	log.Info("client started", "tun", tun.Name(), "server", serverAddr.String(), "mode", cfg.SchedMode.String())
	return e, nil
}

// desiredLinks resolves the configured link set (explicit + auto).
func (e *Engine) desiredLinks() map[string]float64 {
	want := map[string]float64{} // ifname -> initial_mbps hint
	for _, l := range e.ccfg.Links.Link {
		want[l.Interface] = l.InitialMbps
	}
	if e.ccfg.Links.Auto {
		exclude := append([]string{e.tun.Name(), "lo*"}, e.ccfg.Links.Exclude...)
		names, err := platform.UsableInterfaces(exclude)
		if err != nil {
			e.log.Warn("interface enumeration", "err", err)
		}
		for _, n := range names {
			if _, ok := want[n]; !ok {
				want[n] = 0
			}
		}
	}
	return want
}

// setupLinks reconciles paths and sockets with the desired link set.
// Safe to call repeatedly (linkManager reruns it on interface events).
func (e *Engine) setupLinks() {
	e.linksMu.Lock()
	defer e.linksMu.Unlock()
	s := e.sess
	want := e.desiredLinks()
	nowUs := e.nowUs()

	// Index existing paths by interface.
	byIf := map[string]*path.Path{}
	for i := range s.paths {
		if p := s.paths[i].Load(); p != nil {
			byIf[p.IfName] = p
		}
	}

	// Adds and address changes.
	for ifname, hint := range want {
		p := byIf[ifname]
		conn, local, err := udp.DialBound(ifname, e.serverAddr)
		if err != nil {
			if p != nil && p.State() != path.Down && p.State() != path.Removed {
				e.markLinkGone(p)
			}
			continue
		}
		if p == nil {
			pid, ok := e.freePathID()
			if !ok {
				e.log.Warn("no free path ids", "if", ifname)
				conn.Close()
				continue
			}
			p = path.New(pid, ifname, hint)
			p.SetEndpoint(e.serverAddr)
			p.ResetLiveness(nowUs)
			s.paths[pid].Store(p)
			e.swapConn(p, conn)
			e.log.Info("link added", "if", ifname, "path", pid, "local", local.String())
			e.announcePath(p)
			continue
		}
		// Existing path: recreate the socket only if the local address
		// moved or the socket is gone (DHCP renumber, hotplug return).
		old := s.conns[p.ID].Load()
		cur := netip.Addr{}
		if old != nil {
			if la, ok := old.LocalAddr().(*net.UDPAddr); ok {
				cur = la.AddrPort().Addr().Unmap()
			}
		}
		if old == nil || cur != local {
			e.swapConn(p, conn)
			p.ResetLiveness(nowUs)
			if p.State() == path.Removed {
				p.SetState(path.Probing)
			}
			e.log.Info("link rebound", "if", ifname, "path", p.ID, "local", local.String())
			e.announcePath(p)
		} else {
			conn.Close()
		}
	}

	// Removals.
	for ifname, p := range byIf {
		if _, ok := want[ifname]; !ok {
			e.markLinkGone(p)
		}
	}
}

// markLinkGone downs a path whose interface disappeared.
func (e *Engine) markLinkGone(p *path.Path) {
	if c := e.sess.conns[p.ID].Swap(nil); c != nil {
		c.Close()
	}
	if p.State() != path.Removed {
		p.SetState(path.Removed)
		e.sess.acked[p.ID].Store(false)
		e.sess.sched.RemovePath(p.ID)
		e.log.Warn("link removed", "if", p.IfName, "path", p.ID)
	}
}

// swapConn installs a new socket for a path and starts its reader.
func (e *Engine) swapConn(p *path.Path, conn *net.UDPConn) {
	e.sess.acked[p.ID].Store(false)
	if old := e.sess.conns[p.ID].Swap(conn); old != nil {
		old.Close()
	}
	e.goRun("pathReader", func() { e.pathReader(p, conn) })
}

// announcePath sends an immediate PathInit if a session is up.
func (e *Engine) announcePath(p *path.Path) {
	if ep := e.sess.txEpoch.Load(); ep != nil {
		e.sess.sendPathInit(ep, p.ID)
	}
}

// freePathID picks the lowest unused path ID.
func (e *Engine) freePathID() (byte, bool) {
	for i := 0; i < wire.MaxPaths; i++ {
		if e.sess.paths[i].Load() == nil {
			return byte(i), true
		}
	}
	return 0, false
}

// linkManager reacts to interface hotplug/address events.
func (e *Engine) linkManager() {
	events, err := platform.WatchInterfaces(e.stop)
	if err != nil {
		e.log.Warn("interface watcher unavailable; falling back to polling", "err", err)
		events = nil
	}
	poll := time.NewTicker(5 * time.Second)
	defer poll.Stop()
	debounce := time.NewTimer(0)
	if !debounce.Stop() {
		<-debounce.C
	}
	for {
		select {
		case <-e.stop:
			return
		case <-eventsOrNil(events):
			debounce.Reset(500 * time.Millisecond) // coalesce bursts
		case <-poll.C:
			e.setupLinks()
		case <-debounce.C:
			e.setupLinks()
		}
	}
}

func eventsOrNil(ch <-chan platform.IfEvent) <-chan platform.IfEvent {
	return ch
}

// pathReader receives datagrams on one path's connected socket.
func (e *Engine) pathReader(p *path.Path, conn *net.UDPConn) {
	s := e.sess
	buf := pktbuf.Get()
	for {
		n, err := conn.Read(buf[:])
		if err != nil {
			// Connected UDP sockets surface async ICMP errors (host
			// unreachable during an outage) as read errors; those are
			// transient, keep reading. Only stop when the socket itself
			// is gone (swapped out by setupLinks or engine shutdown).
			if e.sess.conns[p.ID].Load() == conn && !isClosedErr(err) {
				e.log.Debug("path read error (transient)", "path", p.ID, "if", p.IfName, "err", err)
				continue
			}
			e.log.Debug("path reader exit", "path", p.ID, "if", p.IfName, "err", err)
			pktbuf.Put(buf)
			return
		}
		if n < wire.HeaderSize {
			continue
		}
		datagram := buf[:n]
		hdr, err := wire.ParseHeader(datagram)
		if err != nil {
			continue
		}
		if hdr.Type == wire.TypeHandshakeResp {
			msg := make([]byte, n-wire.HeaderSize)
			copy(msg, datagram[wire.HeaderSize:])
			select {
			case e.hsRespCh <- hsResp{rxID: hdr.SessionID, msg: msg}:
			default:
			}
			continue
		}
		ep := s.lookupEpoch(hdr.SessionID)
		if ep == nil {
			continue
		}
		if s.handleDatagram(ep, hdr, datagram, buf, netip.AddrPort{}) {
			buf = pktbuf.Get() // previous buffer now owned by reorder/tunOut
		}
	}
}

// clientSupervisor drives handshakes: initial connection, periodic rekey,
// and recovery when the server signals a session loss.
func (e *Engine) clientSupervisor() {
	rekey := time.NewTicker(e.tuning.RekeyInterval())
	defer rekey.Stop()
	for {
		if err := e.runHandshake(); err != nil {
			e.log.Error("handshake failed", "err", err)
			select {
			case <-e.stop:
				return
			case <-time.After(time.Second):
			}
			continue
		}
		select {
		case <-e.stop:
			return
		case <-rekey.C:
			e.log.Info("rekey: starting new handshake")
		case <-e.rekeyNow:
			e.log.Info("peer requested rekey")
		}
	}
}

// runHandshake performs one full handshake attempt cycle with backoff
// until success or engine stop.
func (e *Engine) runHandshake() error {
	backoff := time.Second
	for attempt := 1; ; attempt++ {
		select {
		case <-e.stop:
			return errors.New("engine stopped")
		default:
		}
		err := e.handshakeOnce()
		if err == nil {
			return nil
		}
		e.log.Warn("handshake attempt failed", "attempt", attempt, "err", err)
		select {
		case <-e.stop:
			return errors.New("engine stopped")
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > 5*time.Second {
			backoff = 5 * time.Second
		}
	}
}

// handshakeOnce sends one HandshakeInit on the best available path and
// waits for the response.
func (e *Engine) handshakeOnce() error {
	s := e.sess
	pid, conn := e.pickHandshakePath()
	if conn == nil {
		return errors.New("no usable link for handshake")
	}
	rxID := randUint32()
	ch, err := noiseio.NewClientHandshake(e.ccfg.PrivateKey, e.ccfg.ServerPubKey, e.ccfg.PSK, rxID)
	if err != nil {
		return err
	}
	msg, err := ch.InitMessage(uint64(time.Now().UnixNano()))
	if err != nil {
		return err
	}
	pkt := make([]byte, wire.HeaderSize+len(msg))
	hdr := wire.Header{Type: wire.TypeHandshakeInit, PathID: pid, SessionID: rxID}
	hdr.Marshal(pkt)
	copy(pkt[wire.HeaderSize:], msg)
	if _, err := conn.Write(pkt); err != nil {
		return err
	}

	deadline := time.NewTimer(handshakeTimeout)
	defer deadline.Stop()
	for {
		select {
		case <-e.stop:
			return errors.New("engine stopped")
		case <-deadline.C:
			return errors.New("timeout waiting for handshake response")
		case resp := <-e.hsRespCh:
			if resp.rxID != rxID {
				continue // stale response from an earlier attempt
			}
			epoch, err := ch.Finish(resp.msg)
			if err != nil {
				return err
			}
			s.registerEpoch(epoch, true)
			e.log.Info("handshake complete", "rx_id", rxID, "tx_id", epoch.TxSessionID())
			// (Re-)announce every path under the new epoch.
			for i := range s.paths {
				if p := s.paths[i].Load(); p != nil && p.State() != path.Removed {
					s.acked[i].Store(false)
					s.sendPathInit(epoch, p.ID)
				}
			}
			return nil
		}
	}
}

// pickHandshakePath prefers an Active path, then any with a socket.
func (e *Engine) pickHandshakePath() (byte, *net.UDPConn) {
	s := e.sess
	var fallbackID byte
	var fallback *net.UDPConn
	for i := range s.paths {
		p := s.paths[i].Load()
		if p == nil || p.State() == path.Removed {
			continue
		}
		conn := s.conns[i].Load()
		if conn == nil {
			continue
		}
		if p.State() == path.Active {
			return p.ID, conn
		}
		if fallback == nil {
			fallbackID, fallback = p.ID, conn
		}
	}
	return fallbackID, fallback
}
