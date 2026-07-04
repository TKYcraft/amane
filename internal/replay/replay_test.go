package replay

import "testing"

func TestSequential(t *testing.T) {
	var w Window
	for i := uint64(0); i < 5000; i++ {
		if !w.Check(i) {
			t.Fatalf("fresh counter %d rejected", i)
		}
		if w.Check(i) {
			t.Fatalf("duplicate counter %d accepted", i)
		}
	}
}

func TestOutOfOrderWithinWindow(t *testing.T) {
	var w Window
	const anchor = uint64(10000)
	if !w.Check(anchor) {
		t.Fatal("first packet rejected")
	}
	for i := anchor - 1; i > anchor-WindowSize; i-- {
		if !w.Check(i) {
			t.Fatalf("in-window counter %d rejected", i)
		}
	}
	if w.Check(anchor - WindowSize) {
		t.Fatal("too-old counter accepted")
	}
}

func TestDuplicateOld(t *testing.T) {
	var w Window
	w.Check(100)
	w.Check(50)
	if w.Check(50) {
		t.Fatal("old duplicate accepted")
	}
}

func TestBigJump(t *testing.T) {
	var w Window
	w.Check(1)
	if !w.Check(1 << 40) {
		t.Fatal("large jump rejected")
	}
	if w.Check(1) {
		t.Fatal("pre-jump counter accepted after window advanced far")
	}
	// Counters just behind the new highest must still work.
	if !w.Check(1<<40 - 1) {
		t.Fatal("counter just behind new highest rejected")
	}
}

func TestFirstPacketNonZero(t *testing.T) {
	var w Window
	if !w.Check(123456) {
		t.Fatal("first packet rejected")
	}
	if w.Check(123456) {
		t.Fatal("duplicate of first packet accepted")
	}
}
