// Package pmtud implements per-path MTU discovery in the style of RFC
// 8899 (DPLPMTUD): padded, DF-marked probes confirmed by acks, with no
// reliance on ICMP. A probe that doesn't come back within the timeout
// (or fails to send at all) counts against its size; a binary search
// converges on the largest wire MTU the path carries.
//
// The prober is a pure tick-driven state machine: the engine calls Tick
// once per probe interval and transmits whatever probe it returns; acks
// and send errors are fed back in. All sizes are outer IP packet sizes
// ("wire MTU").
//
// Search sequence: try the ceiling (local interface MTU — the common
// unconstrained case resolves in one probe), fall back to Base then
// Floor to find a working lower bound, then binary-search the gap.
// Results revalidate periodically; Restart is for path events (rebind,
// endpoint roaming) that may have changed the underlying network.
package pmtud

import "sync"

const (
	// Floor is the absolute smallest probed size; a path that cannot
	// carry Floor is reported Dead (Discovered() == -1).
	Floor = 576
	// Base is the practical lower bound tried before Floor.
	Base = 1200

	// granularity ends the binary search; Discovered may understate the
	// true MTU by up to this many bytes (conservative side).
	granularity = 8

	ackTimeoutTicks = 5 // 1s at the default 200ms probe interval
	maxAttempts     = 3 // probes per size before declaring it failed
	// revalidateTicks re-runs discovery periodically (~10min).
	revalidateTicks = 3000
	// initialDelayTicks lets a fresh path settle before probing.
	initialDelayTicks = 5
)

type phase int

const (
	phaseIdle phase = iota
	phaseCeil
	phaseBase
	phaseFloor
	phaseSearch
	phaseDone
	phaseDead
)

// Prober discovers one path's MTU. Safe for concurrent use.
type Prober struct {
	mu   sync.Mutex
	ceil int

	phase    phase
	wait     int // ticks until the next action
	inflight bool
	id       uint32
	size     int
	timeout  int
	attempt  int
	lo, hi   int

	discovered int // 0 unknown, -1 dead, else wire MTU
}

// New creates a prober with the given ceiling (typically the local
// interface MTU).
func New(ceil int) *Prober {
	if ceil < Floor {
		ceil = Floor
	}
	return &Prober{ceil: ceil, phase: phaseIdle, wait: initialDelayTicks}
}

// Tick advances one probe interval. When send is true the caller must
// transmit a probe of the returned wire size carrying the returned id.
func (p *Prober) Tick() (id uint32, size int, send bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.inflight {
		p.timeout--
		if p.timeout > 0 {
			return 0, 0, false
		}
		p.attempt++
		if p.attempt < maxAttempts {
			p.id++
			p.timeout = ackTimeoutTicks
			return p.id, p.size, true
		}
		p.inflight = false
		p.fail(p.size)
	}
	if p.wait > 0 {
		p.wait--
		return 0, 0, false
	}
	next, ok := p.nextSize()
	if !ok {
		return 0, 0, false
	}
	p.inflight = true
	p.size = next
	p.attempt = 0
	p.timeout = ackTimeoutTicks
	p.id++
	return p.id, next, true
}

// nextSize picks the next probe size for the current phase.
func (p *Prober) nextSize() (int, bool) {
	switch p.phase {
	case phaseIdle, phaseDone, phaseDead:
		// Fresh start or periodic revalidation.
		p.phase = phaseCeil
		return p.ceil, true
	case phaseCeil:
		return p.ceil, true
	case phaseBase:
		return Base, true
	case phaseFloor:
		return Floor, true
	case phaseSearch:
		if p.hi-p.lo <= granularity {
			p.finish(p.lo)
			return 0, false
		}
		return (p.lo + p.hi) / 2, true
	}
	return 0, false
}

// OnAck records a successful round trip for the probe with this id.
func (p *Prober) OnAck(id uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.inflight || id != p.id {
		return // stale or duplicate ack
	}
	p.inflight = false
	switch p.phase {
	case phaseCeil:
		p.finish(p.ceil)
	case phaseBase:
		p.lo, p.hi = Base, p.ceil
		p.phase = phaseSearch
		p.step()
	case phaseFloor:
		p.lo, p.hi = Floor, Base
		p.phase = phaseSearch
		p.step()
	case phaseSearch:
		p.lo = p.size
		p.step()
	}
}

// OnSendError reports that the probe with this id could not be sent at
// all (e.g. EMSGSIZE from the local interface): an immediate failure of
// its size.
func (p *Prober) OnSendError(id uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.inflight || id != p.id {
		return
	}
	p.inflight = false
	p.fail(p.size)
}

// fail marks a size as unreachable and advances the phase.
func (p *Prober) fail(size int) {
	switch p.phase {
	case phaseCeil:
		if p.ceil <= Base {
			p.phase = phaseFloor
		} else {
			p.phase = phaseBase
		}
	case phaseBase:
		p.phase = phaseFloor
	case phaseFloor:
		p.discovered = -1
		p.phase = phaseDead
		p.wait = revalidateTicks
	case phaseSearch:
		p.hi = size
		p.step()
	}
}

// step checks search convergence.
func (p *Prober) step() {
	if p.phase == phaseSearch && p.hi-p.lo <= granularity {
		p.finish(p.lo)
	}
}

// finish records a completed discovery and schedules revalidation.
func (p *Prober) finish(mtu int) {
	p.discovered = mtu
	p.phase = phaseDone
	p.wait = revalidateTicks
}

// Discovered returns the current result: 0 while unknown, -1 if even
// Floor fails, else the discovered wire MTU.
func (p *Prober) Discovered() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.discovered
}

// Restart discards state after a path event (socket rebind, endpoint
// change): the network may be different, so the old result is dropped.
func (p *Prober) Restart() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.phase = phaseIdle
	p.wait = initialDelayTicks
	p.inflight = false
	p.discovered = 0
}
