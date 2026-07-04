// Package reorder implements the receive-side resequencing buffer.
//
// Live-video-first policy: never wait long for a gap. IP does not require
// in-order delivery, so packets that arrive after their gap was given up
// on are emitted immediately out of order ("late pass") rather than
// dropped; only true duplicates are discarded. Gap waits are bounded by a
// dynamic timeout derived from inter-path RTT spread and capped by
// max_reorder_delay.
package reorder

import (
	"sync"
	"time"
)

const (
	ringSize = 8192 // power of two
	ringMask = ringSize - 1

	// seenSpan is how far behind the highest seen sequence duplicates are
	// tracked (for redundant-mode dedup and late-pass decisions).
	seenSpan   = 8192
	seenBlocks = seenSpan / 64
)

// Stats are cumulative counters exposed via the control API.
type Stats struct {
	Emitted      uint64 `json:"emitted"`
	Reordered    uint64 `json:"reordered"`     // arrived out of order, resequenced via ring
	TimeoutFlush uint64 `json:"timeout_flush"` // gaps given up on
	LatePass     uint64 `json:"late_pass"`     // late arrivals emitted out of order
	DupDrop      uint64 `json:"dup_drop"`      // duplicates discarded
	OverflowSkip uint64 `json:"overflow_skip"` // ring overflow forced advance
	Held         int    `json:"held"`          // packets currently buffered
	HeldOldestMs int64  `json:"held_oldest_ms"`
}

type slot struct {
	used bool
	seq  uint64
	pkt  []byte
	buf  any // opaque owner token passed back to release
}

// Buffer resequences packets by global sequence number. Safe for
// concurrent Push from multiple receive goroutines.
type Buffer struct {
	mu sync.Mutex

	emit    func(pkt []byte, buf any) // called in emission order, under lock; must not block
	release func(pkt []byte, buf any) // return a dropped packet's storage
	timeout func() time.Duration      // dynamic gap timeout
	now     func() time.Time

	started  bool
	nextSeq  uint64
	ring     [ringSize]slot
	held     int
	maxHold  int
	deadline time.Time // zero when no gap pending
	gapSince time.Time

	// duplicate tracking: sliding bitmap over [seenHigh-seenSpan, seenHigh]
	seen     [seenBlocks]uint64
	seenHigh uint64
	seenInit bool

	stats Stats
}

// Option configures a Buffer.
type Option func(*Buffer)

// WithClock injects a time source (tests).
func WithClock(now func() time.Time) Option {
	return func(b *Buffer) { b.now = now }
}

// WithMaxHold caps buffered packets before forcing a flush.
func WithMaxHold(n int) Option {
	return func(b *Buffer) { b.maxHold = n }
}

// New creates a buffer. emit receives packets in emission order and must
// not block (typically: append to a batch or send to a buffered channel).
// release is called for discarded duplicates. timeout returns the current
// gap timeout (called when a gap forms).
func New(emit func(pkt []byte, buf any), release func(pkt []byte, buf any), timeout func() time.Duration, opts ...Option) *Buffer {
	b := &Buffer{
		emit:    emit,
		release: release,
		timeout: timeout,
		now:     time.Now,
		maxHold: 4096,
	}
	for _, o := range opts {
		o(b)
	}
	return b
}

// markSeen records seq in the duplicate bitmap; reports true if it was
// already seen (duplicate) and false if fresh. Sequences older than
// seenSpan behind the highest are treated as duplicates.
func (b *Buffer) markSeen(seq uint64) bool {
	if !b.seenInit {
		b.seenInit = true
		b.seenHigh = seq
		for i := range b.seen {
			b.seen[i] = 0
		}
		b.seen[(seq>>6)%seenBlocks] = 1 << (seq & 63)
		return false
	}
	switch {
	case seq > b.seenHigh:
		cur, next := b.seenHigh>>6, seq>>6
		diff := next - cur
		if diff > seenBlocks {
			diff = seenBlocks
		}
		for i := uint64(1); i <= diff; i++ {
			b.seen[(cur+i)%seenBlocks] = 0
		}
		b.seenHigh = seq
	case b.seenHigh-seq >= seenSpan:
		return true // too old to know; treat as duplicate
	}
	blk := &b.seen[(seq>>6)%seenBlocks]
	bit := uint64(1) << (seq & 63)
	if *blk&bit != 0 {
		return true
	}
	*blk |= bit
	return false
}

// Push hands a packet to the buffer. Ownership of pkt/buf transfers; it
// will be passed to either emit or release exactly once.
func (b *Buffer) Push(seq uint64, pkt []byte, buf any) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.markSeen(seq) {
		b.stats.DupDrop++
		b.release(pkt, buf)
		return
	}

	if !b.started {
		b.started = true
		b.nextSeq = seq
	}

	if seq > b.nextSeq && seq-b.nextSeq >= ringSize {
		// The gap exceeds the ring span: those predecessors can never all
		// be buffered, so stop waiting for them. Flush everything below
		// seq in order and emit seq now; stragglers will late-pass.
		b.stats.OverflowSkip++
		b.advanceTo(seq)
	}

	switch {
	case seq == b.nextSeq:
		b.emitLocked(pkt, buf)
		b.nextSeq++
		b.drainLocked()

	case seq < b.nextSeq:
		// Its gap was already given up on: emit immediately, out of order.
		b.stats.LatePass++
		b.emitLocked(pkt, buf)

	default: // seq > nextSeq: a gap
		s := &b.ring[seq&ringMask]
		if s.used {
			// Stale occupant should be impossible (dedup + span checks),
			// but never leak a buffer.
			b.release(s.pkt, s.buf)
			b.held--
		}
		*s = slot{used: true, seq: seq, pkt: pkt, buf: buf}
		b.held++
		b.stats.Reordered++
		if b.deadline.IsZero() {
			now := b.now()
			b.deadline = now.Add(b.timeout())
			b.gapSince = now
		}
		if b.held > b.maxHold {
			b.stats.TimeoutFlush++
			b.skipGapLocked()
		}
	}
}

// FlushExpired gives up on the pending gap if its deadline has passed.
// It returns the next deadline (zero if no gap is pending). Call it
// periodically from a timer goroutine.
func (b *Buffer) FlushExpired(now time.Time) time.Time {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.deadline.IsZero() || now.Before(b.deadline) {
		return b.deadline
	}
	b.stats.TimeoutFlush++
	b.skipGapLocked()
	return b.deadline
}

// emitLocked passes one packet out.
func (b *Buffer) emitLocked(pkt []byte, buf any) {
	b.stats.Emitted++
	b.emit(pkt, buf)
}

// drainLocked emits the consecutive run starting at nextSeq, then resets
// or rearms the gap deadline.
func (b *Buffer) drainLocked() {
	for b.held > 0 {
		s := &b.ring[b.nextSeq&ringMask]
		if !s.used || s.seq != b.nextSeq {
			break
		}
		b.emitLocked(s.pkt, s.buf)
		*s = slot{}
		b.held--
		b.nextSeq++
	}
	if b.held == 0 {
		b.deadline = time.Time{}
	} else if b.deadline.IsZero() {
		now := b.now()
		b.deadline = now.Add(b.timeout())
		b.gapSince = now
	}
}

// skipGapLocked advances nextSeq to the oldest buffered packet, emitting
// from there.
func (b *Buffer) skipGapLocked() {
	if b.held == 0 {
		b.deadline = time.Time{}
		return
	}
	oldest := uint64(0)
	found := false
	for i := range b.ring {
		s := &b.ring[i]
		if s.used && (!found || s.seq < oldest) {
			oldest = s.seq
			found = true
		}
	}
	if !found {
		b.held = 0
		b.deadline = time.Time{}
		return
	}
	b.nextSeq = oldest
	b.deadline = time.Time{}
	b.drainLocked()
}

// advanceTo force-advances nextSeq to target, emitting everything buffered
// below it in order (overflow handling).
func (b *Buffer) advanceTo(target uint64) {
	if target-b.nextSeq > ringSize {
		// Huge jump: drain everything below target without walking every
		// sequence number. Occupied slots are few; selection sort in seq
		// order is fine for this rare event.
		for {
			var s *slot
			for i := range b.ring {
				c := &b.ring[i]
				if c.used && c.seq < target && (s == nil || c.seq < s.seq) {
					s = c
				}
			}
			if s == nil {
				break
			}
			b.emitLocked(s.pkt, s.buf)
			*s = slot{}
			b.held--
		}
		b.nextSeq = target
		if b.held == 0 {
			b.deadline = time.Time{}
		}
		return
	}
	for b.nextSeq < target {
		s := &b.ring[b.nextSeq&ringMask]
		if s.used && s.seq == b.nextSeq {
			b.emitLocked(s.pkt, s.buf)
			*s = slot{}
			b.held--
		}
		b.nextSeq++
	}
	if b.held == 0 {
		b.deadline = time.Time{}
	}
}

// Snapshot returns current statistics.
func (b *Buffer) Snapshot() Stats {
	b.mu.Lock()
	defer b.mu.Unlock()
	st := b.stats
	st.Held = b.held
	if !b.gapSince.IsZero() && b.held > 0 {
		st.HeldOldestMs = b.now().Sub(b.gapSince).Milliseconds()
	}
	return st
}
