package pmtud

import "testing"

// run drives the prober against a simulated path that acks probes of
// size <= limit and drops the rest, until discovery completes or
// maxTicks elapse. Returns the final Discovered value.
func run(p *Prober, limit, maxTicks int) int {
	for i := 0; i < maxTicks; i++ {
		id, size, send := p.Tick()
		if send && size <= limit {
			p.OnAck(id)
		}
		if d := p.Discovered(); d != 0 {
			return d
		}
	}
	return p.Discovered()
}

func TestUnconstrainedResolvesAtCeiling(t *testing.T) {
	p := New(1500)
	d := run(p, 1500, 50)
	if d != 1500 {
		t.Fatalf("discovered %d, want 1500", d)
	}
}

func TestConstrainedBinarySearch(t *testing.T) {
	for _, limit := range []int{1300, 1452, 1201, 1499} {
		p := New(1500)
		d := run(p, limit, 2000)
		if d <= limit-granularity || d > limit {
			t.Fatalf("limit %d: discovered %d, want (%d, %d]", limit, d, limit-granularity, limit)
		}
	}
}

func TestBelowBase(t *testing.T) {
	p := New(1500)
	d := run(p, 1000, 2000)
	if d <= 1000-granularity || d > 1000 {
		t.Fatalf("discovered %d, want ~1000", d)
	}
}

func TestDeadPath(t *testing.T) {
	p := New(1500)
	d := run(p, 400, 2000) // below Floor
	if d != -1 {
		t.Fatalf("discovered %d, want -1 (dead)", d)
	}
}

func TestCeilingBelowBase(t *testing.T) {
	p := New(1100) // ceiling below Base
	d := run(p, 1100, 500)
	if d != 1100 {
		t.Fatalf("discovered %d, want 1100", d)
	}
}

func TestRetriesBeforeFail(t *testing.T) {
	p := New(1500)
	// Swallow initial delay.
	sends := 0
	for i := 0; i < initialDelayTicks+maxAttempts*ackTimeoutTicks+5; i++ {
		_, size, send := p.Tick()
		if send {
			sends++
			if size != 1500 {
				break // moved past ceiling phase
			}
		}
	}
	if sends < maxAttempts {
		t.Fatalf("only %d attempts at ceiling before giving up, want %d", sends, maxAttempts)
	}
}

func TestSendErrorFailsImmediately(t *testing.T) {
	p := New(1500)
	var probes int
	d := 0
	for i := 0; i < 300; i++ {
		id, size, send := p.Tick()
		if send {
			probes++
			if size > 1300 {
				p.OnSendError(id) // e.g. EMSGSIZE
			} else {
				p.OnAck(id)
			}
		}
		if d = p.Discovered(); d != 0 {
			break
		}
	}
	if d <= 1300-granularity || d > 1300 {
		t.Fatalf("discovered %d, want ~1300", d)
	}
	// Immediate failures skip the 3x timeout cycles: far fewer ticks used.
	if probes > 15 {
		t.Fatalf("%d probes with instant errors, expected fast convergence", probes)
	}
}

func TestStaleAckIgnored(t *testing.T) {
	p := New(1500)
	var lastID uint32
	for i := 0; i < initialDelayTicks+2; i++ {
		if id, _, send := p.Tick(); send {
			lastID = id
		}
	}
	p.OnAck(lastID + 99) // wrong id
	if d := p.Discovered(); d != 0 {
		t.Fatalf("stale ack completed discovery: %d", d)
	}
	p.OnAck(lastID)
	if d := p.Discovered(); d != 1500 {
		t.Fatalf("valid ack ignored: %d", d)
	}
}

func TestRestartClearsResult(t *testing.T) {
	p := New(1500)
	if d := run(p, 1500, 50); d != 1500 {
		t.Fatal("setup failed")
	}
	p.Restart()
	if d := p.Discovered(); d != 0 {
		t.Fatalf("Restart kept discovered=%d", d)
	}
	if d := run(p, 1300, 2000); d <= 1300-granularity || d > 1300 {
		t.Fatalf("re-discovery got %d, want ~1300", d)
	}
}

func TestRevalidation(t *testing.T) {
	p := New(1500)
	if d := run(p, 1500, 50); d != 1500 {
		t.Fatal("setup failed")
	}
	// Path degrades to 1300; nothing changes until revalidation fires.
	fired := false
	for i := 0; i < revalidateTicks+2000; i++ {
		id, size, send := p.Tick()
		if send {
			fired = true
			if size <= 1300 {
				p.OnAck(id)
			}
		}
		if d := p.Discovered(); d != 1500 && d != 0 {
			if d <= 1300-granularity || d > 1300 {
				t.Fatalf("revalidated to %d, want ~1300", d)
			}
			return
		}
	}
	t.Fatalf("revalidation never completed (fired=%v)", fired)
}

func TestDeadPathRetriesLater(t *testing.T) {
	p := New(1500)
	if d := run(p, 400, 2000); d != -1 {
		t.Fatal("setup failed")
	}
	// Network heals; after the revalidation wait it must recover.
	// (run()'s early exit would return the stale -1, so loop manually.)
	for i := 0; i < revalidateTicks+500; i++ {
		id, _, send := p.Tick()
		if send {
			p.OnAck(id)
		}
		if p.Discovered() == 1500 {
			return
		}
	}
	t.Fatalf("dead path never recovered: %d", p.Discovered())
}
