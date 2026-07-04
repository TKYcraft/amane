package reorder

import (
	"testing"
	"time"
)

type harness struct {
	buf     *Buffer
	emitted []uint64
	now     time.Time
}

func newHarness(t *testing.T, timeout time.Duration, opts ...Option) *harness {
	t.Helper()
	h := &harness{now: time.Unix(1000, 0)}
	emit := func(pkt []byte, buf any) { h.emitted = append(h.emitted, buf.(uint64)) }
	release := func(pkt []byte, buf any) {}
	opts = append(opts, WithClock(func() time.Time { return h.now }))
	h.buf = New(emit, release, func() time.Duration { return timeout }, opts...)
	return h
}

// push sends a packet whose identity is its seq (carried via buf token).
func (h *harness) push(seq uint64) { h.buf.Push(seq, nil, seq) }

func (h *harness) expect(t *testing.T, want ...uint64) {
	t.Helper()
	if len(h.emitted) != len(want) {
		t.Fatalf("emitted %v, want %v", h.emitted, want)
	}
	for i := range want {
		if h.emitted[i] != want[i] {
			t.Fatalf("emitted %v, want %v", h.emitted, want)
		}
	}
}

func TestInOrder(t *testing.T) {
	h := newHarness(t, 50*time.Millisecond)
	for i := uint64(10); i < 15; i++ {
		h.push(i)
	}
	h.expect(t, 10, 11, 12, 13, 14)
}

func TestSimpleReorder(t *testing.T) {
	h := newHarness(t, 50*time.Millisecond)
	h.push(1)
	h.push(3)
	h.push(2)
	h.expect(t, 1, 2, 3)
	if st := h.buf.Snapshot(); st.Reordered != 1 || st.Held != 0 {
		t.Fatalf("stats: %+v", st)
	}
}

func TestGapTimeoutThenLatePass(t *testing.T) {
	h := newHarness(t, 50*time.Millisecond)
	h.push(1)
	h.push(3)
	h.push(4)
	h.expect(t, 1) // 3,4 held awaiting 2

	h.now = h.now.Add(60 * time.Millisecond)
	h.buf.FlushExpired(h.now)
	h.expect(t, 1, 3, 4) // gave up on 2

	h.push(2) // late arrival passes through immediately
	h.expect(t, 1, 3, 4, 2)
	st := h.buf.Snapshot()
	if st.TimeoutFlush != 1 || st.LatePass != 1 {
		t.Fatalf("stats: %+v", st)
	}
}

func TestFlushNotBeforeDeadline(t *testing.T) {
	h := newHarness(t, 50*time.Millisecond)
	h.push(1)
	h.push(3)
	h.now = h.now.Add(10 * time.Millisecond)
	h.buf.FlushExpired(h.now)
	h.expect(t, 1)
	h.push(2)
	h.expect(t, 1, 2, 3)
}

func TestDuplicateDrop(t *testing.T) {
	h := newHarness(t, 50*time.Millisecond)
	h.push(1)
	h.push(2)
	h.push(2)
	h.push(1)
	h.expect(t, 1, 2)
	if st := h.buf.Snapshot(); st.DupDrop != 2 {
		t.Fatalf("stats: %+v", st)
	}
}

func TestRedundantInterleave(t *testing.T) {
	// Two paths deliver the same stream; every packet arrives twice.
	h := newHarness(t, 50*time.Millisecond)
	for i := uint64(1); i <= 100; i++ {
		h.push(i)
		h.push(i)
	}
	if len(h.emitted) != 100 {
		t.Fatalf("emitted %d packets, want 100", len(h.emitted))
	}
	if st := h.buf.Snapshot(); st.DupDrop != 100 {
		t.Fatalf("stats: %+v", st)
	}
}

func TestMaxHoldForcesFlush(t *testing.T) {
	h := newHarness(t, time.Hour, WithMaxHold(10))
	h.push(1)
	for i := uint64(3); i < 14; i++ { // 11 held > 10
		h.push(i)
	}
	if len(h.emitted) < 2 {
		t.Fatalf("max hold did not force flush: emitted %v", h.emitted)
	}
}

func TestOverflowAdvance(t *testing.T) {
	h := newHarness(t, time.Hour)
	h.push(1)
	h.push(3) // gap at 2
	h.push(3 + ringSize)
	// 3 must have been force-emitted; nextSeq advanced past the gap.
	found := false
	for _, s := range h.emitted {
		if s == 3 {
			found = true
		}
	}
	if !found {
		t.Fatalf("overflow did not flush held packet: %v", h.emitted)
	}
	if st := h.buf.Snapshot(); st.OverflowSkip != 1 {
		t.Fatalf("stats: %+v", st)
	}
}

func TestHugeJump(t *testing.T) {
	h := newHarness(t, time.Hour)
	h.push(1)
	h.push(3)
	h.push(1 << 30) // absurd jump: must not hang, must flush 3
	if len(h.emitted) != 3 {
		t.Fatalf("emitted %v", h.emitted)
	}
	h.push(1<<30 + 1)
	h.expect(t, 1, 3, 1<<30, 1<<30+1)
}
