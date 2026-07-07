// Package sched implements per-packet path selection.
//
// In bonding mode it uses stride scheduling (a smooth byte-weighted fair
// scheduler equivalent in effect to DWRR): each path advances a virtual
// "pass" by pktLen/weight when chosen, and the path with the lowest pass
// is picked. Weights approximate each path's usable capacity in bytes/sec
// and are adapted by AIMD from probe-reported loss, delivery rate, and RTT.
//
// In redundant mode every packet is assigned to all usable paths; the
// receiver deduplicates by global sequence number.
package sched

import (
	"sync"
	"time"

	"github.com/TKYcraft/amane/internal/wire"
)

// Mode selects the scheduling policy.
type Mode int

const (
	ModeBonding Mode = iota
	ModeRedundant
	// ModeFEC schedules like bonding; the FEC layer (internal/fec) adds
	// Reed-Solomon parity packets on top.
	ModeFEC
)

func (m Mode) String() string {
	switch m {
	case ModeRedundant:
		return "redundant"
	case ModeFEC:
		return "fec"
	}
	return "bonding"
}

// ParseMode parses "bonding", "redundant", or "fec".
func ParseMode(s string) (Mode, bool) {
	switch s {
	case "bonding", "":
		return ModeBonding, true
	case "redundant":
		return ModeRedundant, true
	case "fec":
		return ModeFEC, true
	}
	return ModeBonding, false
}

// PathState is the scheduler-relevant health of a path.
type PathState int

const (
	StateActive PathState = iota
	StateDegraded
	StateDown
)

// Metrics is the probe-derived quality of one path, as maintained by the
// path layer.
type Metrics struct {
	SRTT        time.Duration
	RTTVar      time.Duration
	MinRTT      time.Duration
	Loss        float64 // EWMA, 0..1
	DeliveryBps float64 // peer-reported delivery rate, bytes/sec
}

// Tunables. Exported fields on Config so the config file can override them.
type Config struct {
	LossDecrease     float64       // loss above this → multiplicative decrease
	LossFloor        float64       // loss below this allows increase
	IncreaseFactor   float64       // additive-ish increase per metrics interval
	DecreaseFactor   float64       // multiplicative decrease on loss
	BloatFactor      float64       // decrease when srtt >> minrtt (bufferbloat)
	BloatRTTMult     float64       // srtt > BloatRTTMult*minrtt triggers bloat decrease
	MaxRTTSpread     time.Duration // paths slower than fastest+spread get capped
	SpreadCap        float64       // weight multiplier for RTT-spread paths
	DegradedFraction float64       // effective weight multiplier for degraded paths
	InitialBps       float64       // default initial weight (bytes/sec)
	SlowStartBps     float64       // weight when a path (re)joins
	MinBps           float64
	MaxBps           float64
}

// DefaultConfig returns the tunables from the design defaults.
func DefaultConfig() Config {
	return Config{
		LossDecrease:     0.02,
		LossFloor:        0.02,
		IncreaseFactor:   1.05,
		DecreaseFactor:   0.7,
		BloatFactor:      0.85,
		BloatRTTMult:     3,
		MaxRTTSpread:     150 * time.Millisecond,
		SpreadCap:        0.5,
		DegradedFraction: 0.01,
		InitialBps:       10e6 / 8,  // 10 Mbps
		SlowStartBps:     1e6 / 8,   // 1 Mbps
		MinBps:           100e3 / 8, // 100 kbps
		MaxBps:           10e9 / 8,  // 10 Gbps
	}
}

type pathState struct {
	id       byte
	present  bool
	state    PathState
	weight   float64 // estimated capacity, bytes/sec
	pass     float64 // stride scheduling virtual time
	srtt     time.Duration
	capped   bool // RTT-spread cap in effect
	initHint float64
}

// Scheduler assigns packets to paths. Safe for concurrent use.
type Scheduler struct {
	mu    sync.Mutex
	cfg   Config
	mode  Mode
	paths [wire.MaxPaths]pathState
}

// New creates a scheduler.
func New(cfg Config, mode Mode) *Scheduler {
	return &Scheduler{cfg: cfg, mode: mode}
}

// SetMode switches the scheduling policy at runtime.
func (s *Scheduler) SetMode(m Mode) {
	s.mu.Lock()
	s.mode = m
	s.mu.Unlock()
}

// Mode returns the current policy.
func (s *Scheduler) Mode() Mode {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mode
}

// AddPath admits a path. initialBps > 0 sets the starting weight (config
// hint); rejoin uses slow start instead.
func (s *Scheduler) AddPath(id byte, initialBps float64, rejoin bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w := s.cfg.InitialBps
	if initialBps > 0 {
		w = initialBps
	}
	if rejoin {
		w = s.cfg.SlowStartBps
	}
	// Start at the max pass of current paths so a new path doesn't hog.
	pass := 0.0
	for i := range s.paths {
		if s.paths[i].present && s.paths[i].pass > pass {
			pass = s.paths[i].pass
		}
	}
	s.paths[id] = pathState{id: id, present: true, state: StateActive, weight: clamp(w, s.cfg.MinBps, s.cfg.MaxBps), pass: pass, initHint: initialBps}
}

// RemovePath drops a path from scheduling entirely.
func (s *Scheduler) RemovePath(id byte) {
	s.mu.Lock()
	s.paths[id] = pathState{}
	s.mu.Unlock()
}

// SetState updates a path's health. Down paths receive no traffic.
func (s *Scheduler) SetState(id byte, st PathState) {
	s.mu.Lock()
	if s.paths[id].present {
		s.paths[id].state = st
	}
	s.mu.Unlock()
}

// OnMetrics adapts the path weight (AIMD) from fresh probe metrics.
// Call once per metrics interval per path.
func (s *Scheduler) OnMetrics(id byte, m Metrics) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := &s.paths[id]
	if !p.present {
		return
	}
	w := p.weight
	switch {
	case m.Loss > s.cfg.LossDecrease:
		// Loss while the path is genuinely being pushed (delivery near
		// the current weight) means the measured delivery rate IS the
		// path's capacity: snap the weight to just under it, in either
		// direction. This converges weights to the true capacity ratio
		// within a couple of intervals instead of shrinking all paths in
		// lockstep. Without utilization evidence (elastic senders like
		// TCP back off after loss, telling us nothing about capacity),
		// fall back to gentle multiplicative decrease.
		if m.DeliveryBps >= 0.5*w {
			w = 0.95 * m.DeliveryBps
		} else {
			w *= s.cfg.DecreaseFactor
		}
	case m.Loss < s.cfg.LossFloor && m.DeliveryBps >= 0.9*w:
		w *= s.cfg.IncreaseFactor
	}
	// A loss-free delivery rate is likewise a capacity floor: a weight
	// crushed by an outage or overload recovers in seconds, not minutes.
	if m.Loss < s.cfg.LossFloor && m.DeliveryBps > w {
		w = m.DeliveryBps
	}
	if m.MinRTT > 0 && m.SRTT > time.Duration(s.cfg.BloatRTTMult*float64(m.MinRTT)) {
		w *= s.cfg.BloatFactor
	}
	p.weight = clamp(w, s.cfg.MinBps, s.cfg.MaxBps)
	p.srtt = m.SRTT

	// Re-evaluate the RTT-spread cap across all paths.
	fastest := time.Duration(0)
	for i := range s.paths {
		q := &s.paths[i]
		if q.present && q.state == StateActive && q.srtt > 0 && (fastest == 0 || q.srtt < fastest) {
			fastest = q.srtt
		}
	}
	for i := range s.paths {
		q := &s.paths[i]
		if q.present {
			q.capped = fastest > 0 && q.srtt > fastest+s.cfg.MaxRTTSpread
		}
	}
}

func (s *Scheduler) effectiveWeight(p *pathState) float64 {
	w := p.weight
	if p.capped {
		w *= s.cfg.SpreadCap
	}
	if p.state == StateDegraded {
		w *= s.cfg.DegradedFraction
	}
	if w < 1 {
		w = 1
	}
	return w
}

// Assign returns the path IDs to carry a packet of pktLen bytes, appended
// to out. Bonding returns one path; redundant returns all usable paths.
// An empty result means no path is usable (caller should queue or drop).
func (s *Scheduler) Assign(pktLen int, out []byte) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mode == ModeRedundant {
		for i := range s.paths {
			p := &s.paths[i]
			if p.present && p.state != StateDown {
				out = append(out, p.id)
			}
		}
		return out
	}
	var best *pathState
	for i := range s.paths {
		p := &s.paths[i]
		if !p.present || p.state == StateDown {
			continue
		}
		if best == nil || p.pass < best.pass {
			best = p
		}
	}
	if best == nil {
		return out
	}
	best.pass += float64(pktLen) / s.effectiveWeight(best)
	return append(out, best.id)
}

// PathWeight reports a path's share of the total effective weight (for
// status output), in [0,1].
func (s *Scheduler) PathWeight(id byte) float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := &s.paths[id]
	if !p.present || p.state == StateDown {
		return 0
	}
	total := 0.0
	for i := range s.paths {
		q := &s.paths[i]
		if q.present && q.state != StateDown {
			total += s.effectiveWeight(q)
		}
	}
	if total == 0 {
		return 0
	}
	return s.effectiveWeight(p) / total
}

// WeightBps returns the current raw weight (capacity estimate) of a path.
func (s *Scheduler) WeightBps(id byte) float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.paths[id].present {
		return 0
	}
	return s.paths[id].weight
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
