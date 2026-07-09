package engine

import (
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TKYcraft/amane/internal/fec"
	"github.com/TKYcraft/amane/internal/keys"
	"github.com/TKYcraft/amane/internal/noiseio"
	"github.com/TKYcraft/amane/internal/path"
	"github.com/TKYcraft/amane/internal/pktbuf"
	"github.com/TKYcraft/amane/internal/reorder"
	"github.com/TKYcraft/amane/internal/sched"
	"github.com/TKYcraft/amane/internal/wire"
)

// epochGrace is how long superseded epochs keep accepting receives.
const epochGrace = 90 * time.Second

// session is one logical peer relationship (client: the server; server:
// one authorized client), spanning key epochs and paths.
type session struct {
	eng     *Engine
	name    string
	peerPub keys.Key
	psk     keys.Key
	peerIP  netip.Addr // server: peer's tunnel address

	// txEpoch is the confirmed epoch used for sending. pending (server
	// only) awaits key confirmation: promotion happens on the first
	// authenticated receive under it.
	txEpoch atomic.Pointer[noiseio.Epoch]
	pending atomic.Pointer[noiseio.Epoch]

	epochsMu sync.RWMutex
	epochs   map[uint32]*epochEntry // by our rxID

	globalSeq atomic.Uint64

	paths [wire.MaxPaths]atomic.Pointer[path.Path]
	// conns is client-only: the per-path interface-bound sockets.
	conns [wire.MaxPaths]atomic.Pointer[net.UDPConn]
	// acked is client-only: whether PathInit was acknowledged.
	acked [wire.MaxPaths]atomic.Bool

	sched   *sched.Scheduler
	reorder *reorder.Buffer

	// server: handshake timestamp monotonicity (anti-replay).
	lastHsTs atomic.Uint64

	// server: when a duplicated (redundant-mode) data packet was last
	// received; the server mirrors the client's scheduling mode from it.
	lastDupUs atomic.Int64
	// server: same for FEC-flagged data packets.
	lastFecUs atomic.Int64

	// FEC state (always present; only exercised in ModeFEC).
	fecEnc *fec.Encoder
	fecDec *fec.Decoder

	dropNoPath  atomic.Uint64
	dropNoEpoch atomic.Uint64

	started atomic.Bool // per-session goroutines launched
}

type epochEntry struct {
	epoch      *noiseio.Epoch
	supersedes time.Time // when a newer epoch replaced this one (zero = current)
}

func newSession(e *Engine, name string, pub keys.Key, psk keys.Key, mode sched.Mode) *session {
	s := &session{
		eng:     e,
		name:    name,
		peerPub: pub,
		psk:     psk,
		epochs:  make(map[uint32]*epochEntry),
		sched:   sched.New(sched.DefaultConfig(), mode),
	}
	s.fecEnc = fec.NewEncoder(e.fecCfg.Group, e.fecCfg.Parity, e.fecCfg.FlushAfter(), s.worstActiveLoss)
	s.fecDec = fec.NewDecoder()
	s.reorder = reorder.New(
		func(pkt []byte, buf any) {
			select {
			case e.tunOut <- rxPkt{buf: buf.(*pktbuf.Buf), pkt: pkt}:
			default:
				pktbuf.Put(buf.(*pktbuf.Buf)) // writer overloaded: drop, stay live
			}
		},
		func(_ []byte, buf any) { pktbuf.Put(buf.(*pktbuf.Buf)) },
		s.reorderTimeout,
	)
	return s
}

// reorderTimeout derives the gap timeout from current inter-path RTT
// spread: max(10ms, min(maxReorderDelay, spread + 4*maxRTTVar)).
func (s *session) reorderTimeout() time.Duration {
	var minRTT, maxRTT, maxVar time.Duration
	for i := range s.paths {
		p := s.paths[i].Load()
		if p == nil || p.State() != path.Active {
			continue
		}
		m := p.Metrics()
		if m.SRTT == 0 {
			continue
		}
		if minRTT == 0 || m.SRTT < minRTT {
			minRTT = m.SRTT
		}
		if m.SRTT > maxRTT {
			maxRTT = m.SRTT
		}
		if m.RTTVar > maxVar {
			maxVar = m.RTTVar
		}
	}
	d := (maxRTT - minRTT) + 4*maxVar
	if lo := 10 * time.Millisecond; d < lo {
		d = lo
	}
	if hi := s.eng.tuning.MaxReorderDelay(); d > hi {
		d = hi
	}
	return d
}

// registerEpoch indexes a fresh epoch for receiving and (optionally)
// marks it as the send epoch.
func (s *session) registerEpoch(ep *noiseio.Epoch, makeTx bool) {
	s.epochsMu.Lock()
	if cur := s.txEpoch.Load(); cur != nil && makeTx {
		if old, ok := s.epochs[cur.RxSessionID()]; ok && old.supersedes.IsZero() {
			old.supersedes = time.Now()
		}
	}
	s.epochs[ep.RxSessionID()] = &epochEntry{epoch: ep}
	s.epochsMu.Unlock()
	if makeTx {
		s.txEpoch.Store(ep)
	}
}

// lookupEpoch resolves an incoming header's session_id.
func (s *session) lookupEpoch(rxID uint32) *noiseio.Epoch {
	s.epochsMu.RLock()
	en := s.epochs[rxID]
	s.epochsMu.RUnlock()
	if en == nil {
		return nil
	}
	return en.epoch
}

// pruneEpochs drops receive ability for epochs superseded longer than the
// grace period ago. Returns the pruned rxIDs (server: also unindex them).
func (s *session) pruneEpochs() []uint32 {
	var pruned []uint32
	now := time.Now()
	s.epochsMu.Lock()
	for id, en := range s.epochs {
		if !en.supersedes.IsZero() && now.Sub(en.supersedes) > epochGrace {
			delete(s.epochs, id)
			pruned = append(pruned, id)
		}
	}
	s.epochsMu.Unlock()
	return pruned
}

// --- TX path ---

// sendData encapsulates one inner IP packet (at pktbuf.TunOffset, length
// n, inside owner) and transmits it on the scheduled path(s). owner
// remains usable by the caller afterwards (sends are synchronous).
func (s *session) sendData(owner *pktbuf.Buf, n int, scratch *pktbuf.Buf) {
	ep := s.txEpoch.Load()
	if ep == nil {
		s.dropNoEpoch.Add(1)
		return
	}
	var idbuf [wire.MaxPaths]byte
	targets := s.sched.Assign(n, idbuf[:0])
	if len(targets) == 0 {
		s.dropNoPath.Add(1)
		return
	}
	seq := s.globalSeq.Add(1)
	fecMode := s.sched.Mode() == sched.ModeFEC
	var flags byte
	if len(targets) > 1 {
		flags = wire.FlagDuplicate
	}
	if fecMode {
		flags |= wire.FlagFEC
	}
	const ih = pktbuf.TunOffset - wire.DataHeaderSize // inner header at 24
	wire.PutDataHeader(owner[ih:pktbuf.TunOffset], seq, flags)
	plaintext := owner[ih : pktbuf.TunOffset+n]

	// FEC: copy the inner packet into the current group before sealing
	// destroys the plaintext.
	var group *fec.Group
	if fecMode {
		group = s.fecEnc.Add(seq, owner[pktbuf.TunOffset:pktbuf.TunOffset+n], targets[0], time.Now())
	}

	for _, pid := range targets {
		out := owner
		if len(targets) > 1 {
			// Sealing in place would destroy the plaintext needed for the
			// other paths, so redundant mode seals into the scratch buffer.
			out = scratch
		}
		s.encryptAndSend(ep, pid, plaintext, out, n)
	}
	if group != nil {
		s.sendParities(ep, group)
	}
}

// worstActiveLoss feeds the FEC encoder's adaptive parity count.
func (s *session) worstActiveLoss() float64 {
	worst := 0.0
	for i := range s.paths {
		p := s.paths[i].Load()
		if p == nil {
			continue
		}
		if st := p.State(); st != path.Active && st != path.Degraded {
			continue
		}
		if l := p.Metrics().Loss; l > worst {
			worst = l
		}
	}
	return worst
}

// sendParities transmits a closed FEC group's parity shards, placing
// them on the active paths that carried the fewest of the group's data
// shards (least loss correlation).
func (s *session) sendParities(ep *noiseio.Epoch, g *fec.Group) {
	if ep == nil || len(g.Parities) == 0 {
		return
	}
	type cand struct {
		id  byte
		cnt uint16
	}
	shardLen := len(g.Parities[0].Shard)
	var cands []cand
	for i := range s.paths {
		p := s.paths[i].Load()
		if p == nil || p.State() != path.Active {
			continue
		}
		// PMTUD: a parity packet is the same wire size as a data packet
		// carrying an inner packet of the shard's length.
		if mi := p.MaxInner(); mi != 0 && shardLen > mi {
			continue
		}
		cands = append(cands, cand{id: p.ID, cnt: g.PathCounts[p.ID]})
	}
	if len(cands) == 0 {
		return
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].cnt < cands[j].cnt })
	for i := range g.Parities {
		s.sendFECParity(ep, cands[i%len(cands)].id, &g.Parities[i])
	}
}

// sendFECParity seals and transmits one parity shard.
func (s *session) sendFECParity(ep *noiseio.Epoch, pid byte, par *fec.Parity) {
	p := s.paths[pid].Load()
	if p == nil {
		return
	}
	buf := pktbuf.Get()
	defer pktbuf.Put(buf)
	const ih = pktbuf.TunOffset - wire.FECHeaderSize // FEC header at 24
	const oh = pktbuf.DatagramOffset
	par.Header.Marshal(buf[ih:pktbuf.TunOffset])
	copy(buf[pktbuf.TunOffset:], par.Shard)
	n := wire.FECHeaderSize + len(par.Shard)
	ctr := ep.NextCounter(pid)
	hdr := wire.Header{Type: wire.TypeFEC, PathID: pid, SessionID: ep.TxSessionID(), Counter: ctr}
	hdr.Marshal(buf[oh:ih])
	ct := ep.Seal(pid, ctr, buf[ih:ih], buf[ih:ih+n], buf[oh:ih])
	if s.transmit(p, buf[oh:ih+len(ct)]) {
		p.OnControlSent(n)
	}
}

// injectRecovered pushes FEC-reconstructed packets into the reorder
// buffer as if they had been received (dedup drops any that also arrive
// late on the wire).
func (s *session) injectRecovered(recs []fec.Recovered) {
	for _, r := range recs {
		if len(r.Pkt) > pktbuf.Size-pktbuf.RxIPOffset {
			continue
		}
		buf := pktbuf.Get()
		copy(buf[pktbuf.RxIPOffset:], r.Pkt)
		s.reorder.Push(r.Seq, buf[pktbuf.RxIPOffset:pktbuf.RxIPOffset+len(r.Pkt)], buf)
	}
}

// encryptAndSend seals plaintext (inner header + IP packet) for pid into
// out and transmits. When out backs the plaintext, sealing is in place.
func (s *session) encryptAndSend(ep *noiseio.Epoch, pid byte, plaintext []byte, out *pktbuf.Buf, n int) {
	p := s.paths[pid].Load()
	if p == nil {
		return
	}
	const ih = pktbuf.TunOffset - wire.DataHeaderSize
	const oh = pktbuf.DatagramOffset // outer header at 8
	ctr := ep.NextCounter(pid)
	hdr := wire.Header{Type: wire.TypeData, PathID: pid, SessionID: ep.TxSessionID(), Counter: ctr}
	hdr.Marshal(out[oh:ih])
	ct := ep.Seal(pid, ctr, out[ih:ih], plaintext, out[oh:ih])
	if s.transmit(p, out[oh:ih+len(ct)]) {
		p.OnDataSent(n)
	}
}

// sendControl builds, seals, and transmits a small control packet.
func (s *session) sendControl(ep *noiseio.Epoch, pid byte, typ byte, payload []byte) {
	p := s.paths[pid].Load()
	if p == nil || ep == nil {
		return
	}
	var b [wire.HeaderSize + 256]byte
	ctr := ep.NextCounter(pid)
	hdr := wire.Header{Type: typ, PathID: pid, SessionID: ep.TxSessionID(), Counter: ctr}
	hdr.Marshal(b[:wire.HeaderSize])
	ct := ep.Seal(pid, ctr, b[wire.HeaderSize:wire.HeaderSize], payload, b[:wire.HeaderSize])
	if s.transmit(p, b[:wire.HeaderSize+len(ct)]) {
		p.OnControlSent(len(payload))
	}
}

// transmit sends a finished datagram over a path's socket.
func (s *session) transmit(p *path.Path, datagram []byte) bool {
	if s.eng.role == RoleClient {
		conn := s.conns[p.ID].Load()
		if conn == nil {
			return false
		}
		_, err := conn.Write(datagram)
		return err == nil
	}
	ep := p.Endpoint()
	if !ep.IsValid() {
		return false
	}
	_, err := s.eng.conn.WriteToUDPAddrPort(datagram, ep)
	return err == nil
}

// sendCloseAll notifies the peer on every usable path (shutdown).
func (s *session) sendCloseAll() {
	ep := s.txEpoch.Load()
	if ep == nil {
		return
	}
	var payload [wire.PathInitPayloadSize]byte
	wire.PutPathInitPayload(payload[:], uint64(s.eng.nowUs()))
	for i := range s.paths {
		if p := s.paths[i].Load(); p != nil && p.State() != path.Removed {
			s.sendControl(ep, p.ID, wire.TypeClose, payload[:])
		}
	}
}

func (s *session) closeConns() {
	for i := range s.conns {
		if c := s.conns[i].Swap(nil); c != nil {
			c.Close()
		}
	}
}

// --- RX path ---

// handleDatagram processes an authenticated-candidate datagram whose
// epoch was already resolved. Returns true if buf ownership was consumed
// (handed to the reorder buffer).
func (s *session) handleDatagram(ep *noiseio.Epoch, hdr wire.Header, datagram []byte, buf *pktbuf.Buf, src netip.AddrPort) bool {
	pt, err := ep.Open(hdr.PathID, hdr.Counter, datagram[wire.HeaderSize:wire.HeaderSize], datagram[wire.HeaderSize:], datagram[:wire.HeaderSize])
	if err != nil {
		return false
	}
	if !ep.CheckReplay(hdr.PathID, hdr.Counter) {
		return false
	}
	nowUs := s.eng.nowUs()

	// Key confirmation: first authenticated receive under a pending epoch
	// proves the peer has it; switch sending to it.
	if s.pending.CompareAndSwap(ep, nil) {
		s.registerEpoch(ep, true)
		s.eng.log.Info("epoch confirmed", "session", s.name, "rx_id", ep.RxSessionID())
	}

	p := s.paths[hdr.PathID].Load()
	if p == nil {
		if hdr.Type == wire.TypePathInit && s.eng.role == RoleServer {
			p = s.addServerPath(hdr.PathID, src)
		} else {
			return false
		}
	}
	// Roaming: any authenticated packet fixes the endpoint (server side).
	// The network changed, so the old MTU discovery no longer applies.
	if s.eng.role == RoleServer && src.IsValid() && p.Endpoint() != src {
		p.SetEndpoint(src)
		p.MTURestart()
	}

	switch hdr.Type {
	case wire.TypeData:
		seq, flags, ipPkt, err := wire.ParseDataHeader(pt)
		if err != nil {
			return false
		}
		// The server mirrors the client's scheduling mode for downlink
		// traffic: duplicated packets mean redundant, FEC-flagged mean FEC.
		if flags&wire.FlagDuplicate != 0 && s.eng.role == RoleServer {
			s.lastDupUs.Store(nowUs)
			if s.sched.Mode() != sched.ModeRedundant {
				s.sched.SetMode(sched.ModeRedundant)
				s.eng.log.Info("mirroring client redundant mode", "session", s.name)
			}
		}
		var recovered []fec.Recovered
		if flags&wire.FlagFEC != 0 {
			if s.eng.role == RoleServer {
				s.lastFecUs.Store(nowUs)
				if s.sched.Mode() != sched.ModeFEC {
					s.sched.SetMode(sched.ModeFEC)
					s.eng.log.Info("mirroring client fec mode", "session", s.name)
				}
			}
			// Retain a copy as a data shard before the reorder buffer
			// takes ownership; this may complete a pending group.
			recovered = s.fecDec.AddData(seq, ipPkt)
		}
		p.OnDataReceived(len(ipPkt), nowUs)
		s.reorder.Push(seq, ipPkt, buf)
		s.injectRecovered(recovered)
		return true

	case wire.TypeFEC:
		fh, shard, err := wire.ParseFECHeader(pt)
		if err != nil {
			return false
		}
		p.OnDataReceived(len(pt), nowUs)
		s.injectRecovered(s.fecDec.AddParity(fh, shard))

	case wire.TypeProbe:
		pr, err := wire.ParseProbe(pt)
		if err != nil {
			return false
		}
		if p.OnProbeReceived(pr, nowUs) {
			s.revivePath(p)
		}

	case wire.TypePathInit:
		if s.eng.role == RoleServer && wire.CheckPathInitPayload(pt) {
			p.OnControlReceived(nowUs)
			if p.State() == path.Probing || p.State() == path.Down {
				s.admitPath(p, false)
			}
			var payload [wire.PathInitPayloadSize]byte
			wire.PutPathInitPayload(payload[:], uint64(nowUs))
			if tx := s.txEpoch.Load(); tx != nil {
				s.sendControl(tx, hdr.PathID, wire.TypePathAck, payload[:])
			}
		}

	case wire.TypePathAck:
		if s.eng.role == RoleClient && wire.CheckPathInitPayload(pt) {
			p.OnControlReceived(nowUs)
			if !s.acked[hdr.PathID].Swap(true) || p.State() == path.Probing {
				s.admitPath(p, false)
			}
		}

	case wire.TypeMTUProbe:
		// The probe's arrival at this size is the discovery signal;
		// answer with a small ack. Excluded from loss accounting on
		// both sides (probes are expected to be lost while searching).
		id, size, err := wire.ParseMTUPayload(pt)
		if err != nil {
			return false
		}
		p.TouchAlive(nowUs)
		if tx := s.txEpoch.Load(); tx != nil {
			s.sendMTUAck(tx, hdr.PathID, id, size)
		}

	case wire.TypeMTUAck:
		id, _, err := wire.ParseMTUPayload(pt)
		if err != nil {
			return false
		}
		p.TouchAlive(nowUs)
		p.MTUAck(id)

	case wire.TypeClose:
		s.eng.log.Info("peer sent close", "session", s.name, "path", hdr.PathID)
		if s.eng.role == RoleClient {
			select {
			case s.eng.rekeyNow <- struct{}{}:
			default:
			}
		}
	}
	return false
}

// addServerPath registers a new path learned from an authenticated
// PathInit. The server can't know the true egress interface MTU per
// client path, so discovery uses the 1500 default ceiling.
func (s *session) addServerPath(pid byte, src netip.AddrPort) *path.Path {
	p := path.New(pid, "", 0, 0)
	p.SetEndpoint(src)
	p.ResetLiveness(s.eng.nowUs())
	s.paths[pid].Store(p)
	return p
}

// sendMTUAck answers an MTU probe (uncounted; see TypeMTUProbe case).
func (s *session) sendMTUAck(ep *noiseio.Epoch, pid byte, id uint32, size uint16) {
	p := s.paths[pid].Load()
	if p == nil {
		return
	}
	var b [wire.HeaderSize + wire.MTUPayloadSize + wire.TagSize]byte
	var payload [wire.MTUPayloadSize]byte
	wire.PutMTUPayload(payload[:], id, size)
	ctr := ep.NextCounter(pid)
	hdr := wire.Header{Type: wire.TypeMTUAck, PathID: pid, SessionID: ep.TxSessionID(), Counter: ctr}
	hdr.Marshal(b[:wire.HeaderSize])
	ct := ep.Seal(pid, ctr, b[wire.HeaderSize:wire.HeaderSize], payload[:], b[:wire.HeaderSize])
	s.transmit(p, b[:wire.HeaderSize+len(ct)])
}

// sendMTUProbe transmits one padded discovery probe of the given wire
// size (uncounted in loss accounting). Send failures (EMSGSIZE from the
// local interface) are fed back as immediate probe failures.
func (s *session) sendMTUProbe(ep *noiseio.Epoch, p *path.Path, id uint32, wireMTU int) {
	v4 := true
	if e := p.Endpoint(); e.IsValid() {
		v4 = e.Addr().Is4()
	}
	n := wire.ProbePlaintextLen(wireMTU, v4)
	if n < wire.MTUPayloadSize || n > pktbuf.Size-pktbuf.TunOffset {
		p.MTUSendError(id)
		return
	}
	buf := pktbuf.Get()
	defer pktbuf.Put(buf)
	const oh = pktbuf.DatagramOffset
	const pt = oh + wire.HeaderSize // plaintext start
	plaintext := buf[pt : pt+n]
	wire.PutMTUPayload(plaintext, id, uint16(wireMTU))
	clear(plaintext[wire.MTUPayloadSize:]) // pooled buffer: don't leak old bytes
	ctr := ep.NextCounter(p.ID)
	hdr := wire.Header{Type: wire.TypeMTUProbe, PathID: p.ID, SessionID: ep.TxSessionID(), Counter: ctr}
	hdr.Marshal(buf[oh:pt])
	ct := ep.Seal(p.ID, ctr, buf[pt:pt], plaintext, buf[oh:pt])
	if !s.transmit(p, buf[oh:pt+len(ct)]) {
		p.MTUSendError(id)
	}
}

// applyPathMTU propagates a changed discovery result to the path,
// the scheduler, and the operator (log).
func (s *session) applyPathMTU(p *path.Path, wireMTU int) {
	maxInner := 0
	switch {
	case wireMTU == -1:
		// Even the floor probe fails: keep control traffic, block data.
		maxInner = 1
	case wireMTU > 0:
		v4 := true
		if e := p.Endpoint(); e.IsValid() {
			v4 = e.Addr().Is4()
		}
		maxInner = wire.MaxInnerForWireMTU(wireMTU, v4)
		if maxInner < 1 {
			maxInner = 1
		}
	}
	p.SetMTU(wireMTU, maxInner)
	s.sched.SetPathMTU(p.ID, maxInner)
	switch {
	case wireMTU == -1:
		s.eng.log.Warn("path mtu: dead (even 576B probes fail); data avoids this path",
			"session", s.name, "path", p.ID, "if", p.IfName)
	case maxInner > 0 && maxInner < s.eng.mtu:
		s.eng.log.Warn("path mtu below tunnel mtu; large packets avoid this path",
			"session", s.name, "path", p.ID, "if", p.IfName,
			"wire_mtu", wireMTU, "usable_inner", maxInner, "tunnel_mtu", s.eng.mtu)
	case wireMTU > 0:
		s.eng.log.Info("path mtu discovered",
			"session", s.name, "path", p.ID, "if", p.IfName,
			"wire_mtu", wireMTU, "usable_inner", maxInner)
	}
}

// admitPath moves a path into Active and hands it to the scheduler.
func (s *session) admitPath(p *path.Path, rejoin bool) {
	p.SetState(path.Active)
	s.sched.AddPath(p.ID, p.InitialMbps*1e6/8, rejoin)
	s.eng.log.Info("path active", "session", s.name, "path", p.ID, "if", p.IfName, "rejoin", rejoin)
}

// revivePath returns a Down path to service after consecutive probe
// responses.
func (s *session) revivePath(p *path.Path) {
	if p.State() == path.Down {
		s.admitPath(p, true)
	}
}

// --- per-session housekeeping goroutines ---

// startLoops launches the prober and reorder flusher once.
func (s *session) startLoops() {
	if s.started.Swap(true) {
		return
	}
	s.eng.goRun("prober", s.proberLoop)
	s.eng.goRun("flusher", s.flusherLoop)
}

// flusherLoop expires reorder gaps and partial FEC groups on a
// fine-grained timer.
func (s *session) flusherLoop() {
	t := time.NewTicker(5 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-s.eng.stop:
			return
		case now := <-t.C:
			s.reorder.FlushExpired(now)
			if s.sched.Mode() == sched.ModeFEC {
				if g := s.fecEnc.FlushExpired(now); g != nil {
					s.sendParities(s.txEpoch.Load(), g)
				}
			}
		}
	}
}

// proberLoop drives probes, path state transitions, AIMD metric updates,
// PathInit retries (client), and epoch pruning.
func (s *session) proberLoop() {
	interval := s.eng.tuning.ProbeInterval()
	deadAfter := s.eng.tuning.DeadInterval()
	degradeLoss := s.eng.tuning.DegradeLossPct / 100
	degradeRTT := time.Duration(s.eng.tuning.DegradeRTTMs) * time.Millisecond

	t := time.NewTicker(interval)
	defer t.Stop()
	tick := 0
	prevTx := make([]uint64, wire.MaxPaths)
	prevRx := make([]uint64, wire.MaxPaths)
	prevMTU := make([]int, wire.MaxPaths)
	// badTicks counts consecutive over-threshold quality checks so that
	// the transient loss of AIMD convergence doesn't degrade a path the
	// scheduler is still learning about.
	badTicks := make([]int, wire.MaxPaths)
	const degradeAfterTicks = 15 // 3s at the default 200ms interval
	for {
		select {
		case <-s.eng.stop:
			return
		case <-t.C:
		}
		tick++
		nowUs := s.eng.nowUs()
		ep := s.txEpoch.Load()
		for i := range s.paths {
			p := s.paths[i].Load()
			if p == nil || p.State() == path.Removed {
				continue
			}
			st := p.State()

			// Probe cadence: every tick when up, every 5th when down.
			if ep != nil && (st != path.Down || tick%5 == 0) {
				pr := p.NextProbe(nowUs)
				var payload [wire.ProbeSize]byte
				pr.Marshal(payload[:])
				s.sendControl(ep, p.ID, wire.TypeProbe, payload[:])
			}

			// Client: retry PathInit until acked.
			if s.eng.role == RoleClient && ep != nil && !s.acked[i].Load() && tick%5 == 0 {
				s.sendPathInit(ep, p.ID)
			}

			// Path MTU discovery on live paths.
			if st == path.Active || st == path.Degraded {
				if ep != nil {
					if id, size, ok := p.MTUTick(); ok {
						s.sendMTUProbe(ep, p, id, size)
					}
				}
				if d := p.MTUDiscovered(); d != prevMTU[i] {
					prevMTU[i] = d
					s.applyPathMTU(p, d)
				}
			}

			// Death: probe silence beyond the dead interval.
			if (st == path.Active || st == path.Degraded) && p.SilentFor(nowUs) > deadAfter {
				p.SetState(path.Down)
				s.sched.SetState(p.ID, sched.StateDown)
				s.eng.log.Warn("path down", "session", s.name, "path", p.ID, "if", p.IfName)
				continue
			}

			// Degrade only on persistent badness (transient convergence
			// loss must not trip it); recover with hysteresis.
			m := p.Metrics()
			bad := m.Loss > degradeLoss || (m.SRTT > 0 && m.SRTT > degradeRTT)
			if bad {
				badTicks[i]++
			} else {
				badTicks[i] = 0
			}
			switch st {
			case path.Active:
				if bad && badTicks[i] >= degradeAfterTicks {
					p.SetState(path.Degraded)
					s.sched.SetState(p.ID, sched.StateDegraded)
					s.eng.log.Warn("path degraded", "session", s.name, "path", p.ID, "loss", m.Loss, "srtt", m.SRTT)
				}
			case path.Degraded:
				if m.Loss < degradeLoss/2 && m.SRTT < degradeRTT {
					p.SetState(path.Active)
					s.sched.SetState(p.ID, sched.StateActive)
					s.eng.log.Info("path recovered", "session", s.name, "path", p.ID)
				}
			}
			if st == path.Active || st == path.Degraded {
				s.sched.OnMetrics(p.ID, m)
			}

			// Rate estimation for status output (per second).
			if tick%5 == 0 {
				_, txb := p.TxStats()
				_, rxb := p.RxStats()
				dt := float64(5) * interval.Seconds()
				p.SetRates(float64(txb-prevTx[i])*8/dt, float64(rxb-prevRx[i])*8/dt)
				prevTx[i], prevRx[i] = txb, rxb
			}
		}
		// Server: fall back to bonding when the client's mirrored mode
		// (redundant duplicates / FEC flags) stops appearing.
		if s.eng.role == RoleServer {
			switch s.sched.Mode() {
			case sched.ModeRedundant:
				if last := s.lastDupUs.Load(); last > 0 && nowUs-last > 5e6 {
					s.sched.SetMode(sched.ModeBonding)
					s.eng.log.Info("client redundant mode ended", "session", s.name)
				}
			case sched.ModeFEC:
				if last := s.lastFecUs.Load(); last > 0 && nowUs-last > 5e6 {
					s.sched.SetMode(sched.ModeBonding)
					s.eng.log.Info("client fec mode ended", "session", s.name)
				}
			}
		}

		// Epoch pruning (both roles), rxID unindexing (server).
		if tick%25 == 0 {
			pruned := s.pruneEpochs()
			if s.eng.role == RoleServer && len(pruned) > 0 {
				s.eng.unindexRxIDs(pruned)
			}
		}
	}
}

// sendPathInit announces a path to the server.
func (s *session) sendPathInit(ep *noiseio.Epoch, pid byte) {
	var payload [wire.PathInitPayloadSize]byte
	wire.PutPathInitPayload(payload[:], uint64(s.eng.nowUs()))
	s.sendControl(ep, pid, wire.TypePathInit, payload[:])
}
