package engine

import (
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/TKYcraft/amane/internal/config"
	"github.com/TKYcraft/amane/internal/keys"
	"github.com/TKYcraft/amane/internal/noiseio"
	"github.com/TKYcraft/amane/internal/pktbuf"
	"github.com/TKYcraft/amane/internal/platform"
	"github.com/TKYcraft/amane/internal/sched"
	"github.com/TKYcraft/amane/internal/tundev"
	"github.com/TKYcraft/amane/internal/udp"
	"github.com/TKYcraft/amane/internal/wire"
)

// StartServer boots the relay server engine.
func StartServer(cfg *config.Server, log *slog.Logger) (*Engine, error) {
	tun, err := tundev.Open(cfg.Server.TunName, cfg.Server.MTU)
	if err != nil {
		return nil, fmt.Errorf("create tun: %w", err)
	}
	if err := platform.ConfigureTUN(tun.Name(), cfg.TunnelAddr, cfg.Server.MTU); err != nil {
		tun.Close()
		return nil, err
	}

	conn, err := udp.Listen(cfg.Server.Listen)
	if err != nil {
		tun.Close()
		return nil, fmt.Errorf("listen %s: %w", cfg.Server.Listen, err)
	}

	e := &Engine{
		log:    log,
		role:   RoleServer,
		tun:    tun,
		mtu:    cfg.Server.MTU,
		tuning: cfg.Tuning,
		fecCfg: cfg.FEC,
		base:   time.Now(),
		tunOut: make(chan rxPkt, 4096),
		scfg:   cfg,
		conn:   conn,
		peers:  make(map[keys.Key]*session),
		byIP:   make(map[netip.Addr]*session),
		byRxID: make(map[uint32]epochRef),
		hsGate: newTokenBucket(20, 10),
		stop:   make(chan struct{}),
	}
	for i := range cfg.Peer {
		p := &cfg.Peer[i]
		s := newSession(e, p.Name, p.PubKey, p.PSK, sched.ModeBonding)
		s.peerIP = p.Addr
		e.peers[p.PubKey] = s
		e.byIP[p.Addr] = s
	}

	if cfg.Server.NAT.Enabled {
		cleanup, err := platform.EnableNAT(cfg.TunnelAddr, cfg.Server.NAT.OutInterface)
		if err != nil {
			conn.Close()
			tun.Close()
			return nil, fmt.Errorf("nat setup: %w", err)
		}
		e.cleanups = append(e.cleanups, cleanup)
		log.Info("nat enabled", "out", cfg.Server.NAT.OutInterface, "net", cfg.TunnelAddr.Masked().String())
	} else {
		log.Info("nat disabled; manual setup:\n" + platform.NATInstructions(cfg.TunnelAddr, cfg.Server.NAT.OutInterface))
	}

	e.goRun("tunReader", e.tunReader)
	e.goRun("tunWriter", e.tunWriter)
	e.goRun("listenReader", e.listenReader)
	log.Info("server started", "tun", tun.Name(), "listen", cfg.Server.Listen, "peers", len(cfg.Peer))
	return e, nil
}

// listenReader demultiplexes every datagram arriving on the listen socket.
func (e *Engine) listenReader() {
	buf := pktbuf.Get()
	for {
		n, src, err := e.conn.ReadFromUDPAddrPort(buf[:])
		if err != nil {
			select {
			case <-e.stop:
				pktbuf.Put(buf)
				return
			default:
				continue
			}
		}
		if n < wire.HeaderSize {
			continue
		}
		datagram := buf[:n]
		hdr, err := wire.ParseHeader(datagram)
		if err != nil {
			continue
		}
		src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())

		if hdr.Type == wire.TypeHandshakeInit {
			e.handleHandshakeInit(hdr, datagram, src)
			continue
		}
		e.peersMu.RLock()
		ref, ok := e.byRxID[hdr.SessionID]
		e.peersMu.RUnlock()
		if !ok {
			continue
		}
		if ref.sess.handleDatagram(ref.epoch, hdr, datagram, buf, src) {
			buf = pktbuf.Get()
		}
	}
}

// handleHandshakeInit authenticates a new handshake and responds.
// Unknown or replayed initiators are dropped without a reply (stealth).
func (e *Engine) handleHandshakeInit(hdr wire.Header, datagram []byte, src netip.AddrPort) {
	if !e.hsGate.allow() {
		return
	}
	sh, err := noiseio.ConsumeInit(e.scfg.PrivateKey, datagram[wire.HeaderSize:])
	if err != nil {
		return
	}
	e.peersMu.RLock()
	s := e.peers[sh.PeerStatic()]
	e.peersMu.RUnlock()
	if s == nil {
		e.log.Debug("handshake from unknown key", "key", sh.PeerStatic().ShortString(), "src", src.String())
		return
	}
	// Reject replayed HandshakeInit messages (timestamp must advance).
	for {
		last := s.lastHsTs.Load()
		if sh.TimestampNs() <= last {
			e.log.Warn("handshake replay rejected", "session", s.name, "src", src.String())
			return
		}
		if s.lastHsTs.CompareAndSwap(last, sh.TimestampNs()) {
			break
		}
	}

	rxID := e.allocRxID()
	respMsg, epoch, err := sh.Respond(s.psk, rxID, hdr.SessionID)
	if err != nil {
		e.log.Warn("handshake respond", "session", s.name, "err", err)
		return
	}

	e.peersMu.Lock()
	e.byRxID[rxID] = epochRef{sess: s, epoch: epoch}
	e.peersMu.Unlock()
	s.epochsMu.Lock()
	s.epochs[rxID] = &epochEntry{epoch: epoch}
	s.epochsMu.Unlock()
	// Await key confirmation before sending data under the new epoch,
	// unless we have nothing at all yet.
	s.pending.Store(epoch)
	if s.txEpoch.Load() == nil {
		s.pending.Store(nil)
		s.registerEpoch(epoch, true)
	}

	// The handshake itself proves this path.
	p := s.paths[hdr.PathID].Load()
	if p == nil {
		p = s.addServerPath(hdr.PathID, src)
	}
	p.SetEndpoint(src)
	p.OnControlReceived(e.nowUs())

	pkt := make([]byte, wire.HeaderSize+len(respMsg))
	respHdr := wire.Header{Type: wire.TypeHandshakeResp, PathID: hdr.PathID, SessionID: hdr.SessionID}
	respHdr.Marshal(pkt)
	copy(pkt[wire.HeaderSize:], respMsg)
	if _, err := e.conn.WriteToUDPAddrPort(pkt, src); err != nil {
		e.log.Warn("handshake response send", "err", err)
		return
	}
	s.startLoops()
	e.log.Info("handshake accepted", "session", s.name, "src", src.String(), "rx_id", rxID)
}

// allocRxID picks an unused random receiver index.
func (e *Engine) allocRxID() uint32 {
	e.peersMu.Lock()
	defer e.peersMu.Unlock()
	for {
		id := randUint32()
		if _, taken := e.byRxID[id]; !taken {
			return id
		}
	}
}

// unindexRxIDs removes pruned epochs from the global receive index.
func (e *Engine) unindexRxIDs(ids []uint32) {
	e.peersMu.Lock()
	for _, id := range ids {
		delete(e.byRxID, id)
	}
	e.peersMu.Unlock()
}
