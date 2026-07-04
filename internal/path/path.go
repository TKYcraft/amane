// Package path tracks one tunnel path: its liveness state machine and
// probe-derived quality metrics (RTT, loss, delivery rate). It does no
// I/O; the engine owns sockets and calls in.
package path

import (
	"math"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TKYcraft/amane/internal/sched"
	"github.com/TKYcraft/amane/internal/wire"
)

// State is the path liveness state.
type State int32

const (
	// Probing: created, awaiting PathAck.
	Probing State = iota
	// Active: carrying traffic.
	Active
	// Degraded: alive but poor (loss/RTT past thresholds); trickle only.
	Degraded
	// Down: probe silence; excluded from scheduling, still probed.
	Down
	// Removed: interface gone; kept only so the ID's counters stay burned.
	Removed
)

func (s State) String() string {
	switch s {
	case Probing:
		return "probing"
	case Active:
		return "active"
	case Degraded:
		return "degraded"
	case Down:
		return "down"
	case Removed:
		return "removed"
	}
	return "?"
}

const (
	rttAlpha  = 0.2 // EWMA weight for srtt/rttvar
	lossAlpha = 0.3 // EWMA weight for loss
	// minLossSample: skip loss samples over windows with fewer TX packets.
	minLossSample = 20
	// reviveProbes: consecutive probe receipts that revive a Down path.
	reviveProbes = 3
)

// Path is one (client interface, server endpoint) pairing.
type Path struct {
	ID          byte
	IfName      string // client only
	InitialMbps float64

	state    atomic.Int32
	endpoint atomic.Pointer[netip.AddrPort]

	// Cumulative data counters. rx* are reported to the peer in probes;
	// tx* anchor loss calculation. Touched on every data packet.
	rxPackets atomic.Uint64
	rxBytes   atomic.Uint64
	txPackets atomic.Uint64
	txBytes   atomic.Uint64

	// lastAliveUs is the monotonic µs of the last authenticated receive.
	lastAliveUs atomic.Int64

	// Smoothed tx/rx rates in bits/sec for status output (float64 bits).
	rateTxBps atomic.Uint64
	rateRxBps atomic.Uint64

	mu sync.Mutex
	// probe bookkeeping (under mu)
	probeSeq      uint32
	lastPeer      wire.Probe // last probe received from peer
	lastPeerAtUs  int64
	havePeerProbe bool
	// metrics (under mu)
	srtt, rttvar, minRTT time.Duration
	loss                 float64
	deliveryBps          float64
	// loss/delivery anchors (under mu)
	prevPeerRxPackets uint64
	prevPeerRxBytes   uint64
	prevOwnTxPackets  uint64
	prevReportAtUs    int64
	haveReport        bool
	// down-recovery (under mu)
	probesSinceDown int
}

// New creates a path in Probing state.
func New(id byte, ifname string, initialMbps float64) *Path {
	p := &Path{ID: id, IfName: ifname, InitialMbps: initialMbps}
	p.state.Store(int32(Probing))
	return p
}

// State returns the current liveness state.
func (p *Path) State() State { return State(p.state.Load()) }

// SetState transitions the path.
func (p *Path) SetState(s State) { p.state.Store(int32(s)) }

// Endpoint returns the peer address for this path (zero if unknown).
func (p *Path) Endpoint() netip.AddrPort {
	if ep := p.endpoint.Load(); ep != nil {
		return *ep
	}
	return netip.AddrPort{}
}

// SetEndpoint records the peer address (roaming updates included).
func (p *Path) SetEndpoint(ep netip.AddrPort) {
	p.endpoint.Store(&ep)
}

// OnDataSent accounts an outgoing data packet.
func (p *Path) OnDataSent(n int) {
	p.txPackets.Add(1)
	p.txBytes.Add(uint64(n))
}

// OnDataReceived accounts an incoming data packet and refreshes liveness.
func (p *Path) OnDataReceived(n int, nowUs int64) {
	p.rxPackets.Add(1)
	p.rxBytes.Add(uint64(n))
	p.lastAliveUs.Store(nowUs)
}

// TxStats returns cumulative sent data counters.
func (p *Path) TxStats() (packets, bytes uint64) {
	return p.txPackets.Load(), p.txBytes.Load()
}

// RxStats returns cumulative received data counters.
func (p *Path) RxStats() (packets, bytes uint64) {
	return p.rxPackets.Load(), p.rxBytes.Load()
}

// NextProbe builds the next probe to send on this path. nowUs is the
// engine's monotonic clock in µs.
func (p *Path) NextProbe(nowUs int64) wire.Probe {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.probeSeq++
	pr := wire.Probe{
		Seq:       p.probeSeq,
		TSendUs:   uint64(nowUs),
		RxPackets: p.rxPackets.Load(),
		RxBytes:   p.rxBytes.Load(),
	}
	if p.havePeerProbe {
		pr.EchoSeq = p.lastPeer.Seq
		pr.EchoTSend = p.lastPeer.TSendUs
		if d := nowUs - p.lastPeerAtUs; d > 0 {
			pr.EchoDelay = uint32(d)
		}
	}
	return pr
}

// OnProbeReceived ingests a probe from the peer, updating RTT, loss, and
// delivery estimates. Reports whether a Down path has now proven alive
// (reviveProbes consecutive receipts).
func (p *Path) OnProbeReceived(pr wire.Probe, nowUs int64) (revived bool) {
	p.rxPackets.Add(1)
	p.rxBytes.Add(wire.ProbeSize)
	p.lastAliveUs.Store(nowUs)
	p.mu.Lock()
	defer p.mu.Unlock()

	p.lastPeer = pr
	p.lastPeerAtUs = nowUs
	p.havePeerProbe = true

	// RTT from our echoed timestamp.
	if pr.EchoTSend != 0 {
		rtt := time.Duration(nowUs-int64(pr.EchoTSend)-int64(pr.EchoDelay)) * time.Microsecond
		if rtt > 0 && rtt < time.Minute {
			if p.srtt == 0 {
				p.srtt = rtt
				p.rttvar = rtt / 2
			} else {
				d := p.srtt - rtt
				if d < 0 {
					d = -d
				}
				p.rttvar = time.Duration((1-rttAlpha)*float64(p.rttvar) + rttAlpha*float64(d))
				p.srtt = time.Duration((1-rttAlpha)*float64(p.srtt) + rttAlpha*float64(rtt))
			}
			if p.minRTT == 0 || rtt < p.minRTT {
				p.minRTT = rtt
			}
		}
	}

	// Loss and delivery from the peer's cumulative receive report. The
	// counters include probes and control packets, so loss stays fresh
	// even when no data flows (a stale loss estimate would otherwise pin
	// an idle path in Degraded forever). Anchors only advance when the
	// window has enough packets for a meaningful sample; with probes
	// alone (5/s) that means one sample every ~4s.
	ownTx := p.txPackets.Load()
	if !p.haveReport {
		p.prevPeerRxPackets = pr.RxPackets
		p.prevPeerRxBytes = pr.RxBytes
		p.prevOwnTxPackets = ownTx
		p.prevReportAtUs = nowUs
		p.haveReport = true
	} else if dTx := ownTx - p.prevOwnTxPackets; dTx >= minLossSample {
		dRx := pr.RxPackets - p.prevPeerRxPackets
		sample := 1 - float64(dRx)/float64(dTx)
		if sample < 0 {
			sample = 0
		}
		if sample > 1 {
			sample = 1
		}
		p.loss = (1-lossAlpha)*p.loss + lossAlpha*sample
		if dt := nowUs - p.prevReportAtUs; dt > 0 {
			p.deliveryBps = float64(pr.RxBytes-p.prevPeerRxBytes) / (float64(dt) / 1e6)
		}
		p.prevPeerRxPackets = pr.RxPackets
		p.prevPeerRxBytes = pr.RxBytes
		p.prevOwnTxPackets = ownTx
		p.prevReportAtUs = nowUs
	}

	if p.State() == Down {
		p.probesSinceDown++
		if p.probesSinceDown >= reviveProbes {
			p.probesSinceDown = 0
			return true
		}
	} else {
		p.probesSinceDown = 0
	}
	return false
}

// OnControlReceived refreshes liveness for authenticated non-data,
// non-probe packets (PathAck etc) and counts them for loss accounting.
func (p *Path) OnControlReceived(nowUs int64) {
	p.rxPackets.Add(1)
	p.rxBytes.Add(wire.PathInitPayloadSize)
	p.lastAliveUs.Store(nowUs)
}

// OnControlSent counts an outgoing probe/control packet so both sides
// account the same packet universe when computing loss.
func (p *Path) OnControlSent(n int) {
	p.txPackets.Add(1)
	p.txBytes.Add(uint64(n))
}

// SilentFor reports how long the path has been without any authenticated
// receive.
func (p *Path) SilentFor(nowUs int64) time.Duration {
	last := p.lastAliveUs.Load()
	if last == 0 {
		return 0
	}
	return time.Duration(nowUs-last) * time.Microsecond
}

// Metrics snapshots the scheduler-facing quality numbers.
func (p *Path) Metrics() sched.Metrics {
	p.mu.Lock()
	defer p.mu.Unlock()
	return sched.Metrics{
		SRTT:        p.srtt,
		RTTVar:      p.rttvar,
		MinRTT:      p.minRTT,
		Loss:        p.loss,
		DeliveryBps: p.deliveryBps,
	}
}

// ResetLiveness marks the path alive now (used when (re)creating sockets
// so a path isn't instantly declared dead before the first probe).
func (p *Path) ResetLiveness(nowUs int64) {
	p.lastAliveUs.Store(nowUs)
}

// SetRates stores the current throughput estimates (bits/sec).
func (p *Path) SetRates(txBps, rxBps float64) {
	p.rateTxBps.Store(math.Float64bits(txBps))
	p.rateRxBps.Store(math.Float64bits(rxBps))
}

// Rates returns the current throughput estimates (bits/sec).
func (p *Path) Rates() (txBps, rxBps float64) {
	return math.Float64frombits(p.rateTxBps.Load()), math.Float64frombits(p.rateRxBps.Load())
}
