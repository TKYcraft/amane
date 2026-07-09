package sched

import (
	"testing"
	"time"
)

func assign(s *Scheduler, n, pktLen int) map[byte]int {
	counts := map[byte]int{}
	var out []byte
	for i := 0; i < n; i++ {
		out = s.Assign(pktLen, out[:0])
		for _, id := range out {
			counts[id]++
		}
	}
	return counts
}

func TestBondingProportional(t *testing.T) {
	s := New(DefaultConfig(), ModeBonding)
	s.AddPath(0, 20e6/8, false) // 20 Mbps
	s.AddPath(1, 10e6/8, false) // 10 Mbps
	counts := assign(s, 3000, 1400)
	ratio := float64(counts[0]) / float64(counts[1])
	if ratio < 1.8 || ratio > 2.2 {
		t.Fatalf("expected ~2:1 split, got %v (ratio %.2f)", counts, ratio)
	}
}

func TestBondingEqualDefault(t *testing.T) {
	s := New(DefaultConfig(), ModeBonding)
	s.AddPath(0, 0, false)
	s.AddPath(1, 0, false)
	s.AddPath(2, 0, false)
	counts := assign(s, 3000, 1400)
	for id, c := range counts {
		if c < 900 || c > 1100 {
			t.Fatalf("path %d got %d of 3000, want ~1000", id, c)
		}
	}
}

func TestRedundantAll(t *testing.T) {
	s := New(DefaultConfig(), ModeRedundant)
	s.AddPath(0, 0, false)
	s.AddPath(1, 0, false)
	s.AddPath(2, 0, false)
	s.SetState(2, StateDown)
	out := s.Assign(1400, nil)
	if len(out) != 2 {
		t.Fatalf("want 2 usable paths, got %v", out)
	}
}

func TestDownExcluded(t *testing.T) {
	s := New(DefaultConfig(), ModeBonding)
	s.AddPath(0, 0, false)
	s.AddPath(1, 0, false)
	s.SetState(0, StateDown)
	counts := assign(s, 100, 1400)
	if counts[0] != 0 || counts[1] != 100 {
		t.Fatalf("down path received traffic: %v", counts)
	}
}

func TestAllDown(t *testing.T) {
	s := New(DefaultConfig(), ModeBonding)
	s.AddPath(0, 0, false)
	s.SetState(0, StateDown)
	if out := s.Assign(1400, nil); len(out) != 0 {
		t.Fatalf("want no assignment, got %v", out)
	}
}

func TestDegradedGetsTrickle(t *testing.T) {
	s := New(DefaultConfig(), ModeBonding)
	s.AddPath(0, 10e6/8, false)
	s.AddPath(1, 10e6/8, false)
	s.SetState(1, StateDegraded)
	counts := assign(s, 10000, 1400)
	if counts[1] == 0 {
		t.Fatal("degraded path fully starved; needs trickle to detect recovery")
	}
	if counts[1] > counts[0]/10 {
		t.Fatalf("degraded path got too much: %v", counts)
	}
}

func TestAIMDLossDecreasesWeight(t *testing.T) {
	s := New(DefaultConfig(), ModeBonding)
	s.AddPath(0, 10e6/8, false)
	w0 := s.WeightBps(0)
	s.OnMetrics(0, Metrics{SRTT: 50 * time.Millisecond, MinRTT: 40 * time.Millisecond, Loss: 0.10})
	if w1 := s.WeightBps(0); w1 >= w0 {
		t.Fatalf("weight did not decrease on loss: %v -> %v", w0, w1)
	}
}

func TestAIMDSaturationIncreasesWeight(t *testing.T) {
	s := New(DefaultConfig(), ModeBonding)
	s.AddPath(0, 10e6/8, false)
	w0 := s.WeightBps(0)
	s.OnMetrics(0, Metrics{SRTT: 50 * time.Millisecond, MinRTT: 45 * time.Millisecond, Loss: 0, DeliveryBps: w0})
	if w1 := s.WeightBps(0); w1 <= w0 {
		t.Fatalf("weight did not increase at saturation: %v -> %v", w0, w1)
	}
}

func TestAIMDBloatDecreases(t *testing.T) {
	s := New(DefaultConfig(), ModeBonding)
	s.AddPath(0, 10e6/8, false)
	w0 := s.WeightBps(0)
	s.OnMetrics(0, Metrics{SRTT: 400 * time.Millisecond, MinRTT: 40 * time.Millisecond, Loss: 0})
	if w1 := s.WeightBps(0); w1 >= w0 {
		t.Fatalf("weight did not decrease on bufferbloat: %v -> %v", w0, w1)
	}
}

func TestRTTSpreadCap(t *testing.T) {
	s := New(DefaultConfig(), ModeBonding)
	s.AddPath(0, 10e6/8, false)
	s.AddPath(1, 10e6/8, false)
	s.OnMetrics(0, Metrics{SRTT: 20 * time.Millisecond, MinRTT: 20 * time.Millisecond})
	s.OnMetrics(1, Metrics{SRTT: 300 * time.Millisecond, MinRTT: 250 * time.Millisecond})
	counts := assign(s, 3000, 1400)
	if counts[1] >= counts[0] {
		t.Fatalf("slow path not capped: %v", counts)
	}
}

func TestMTUFilterBonding(t *testing.T) {
	s := New(DefaultConfig(), ModeBonding)
	s.AddPath(0, 0, false)
	s.AddPath(1, 0, false)
	s.SetPathMTU(1, 1232)
	counts := assign(s, 200, 1400) // larger than path 1's limit
	if counts[1] != 0 {
		t.Fatalf("oversized packets sent through restricted path: %v", counts)
	}
	if counts[0] != 200 {
		t.Fatalf("packets lost: %v", counts)
	}
	counts = assign(s, 2000, 1000) // fits everywhere
	if counts[0] == 0 || counts[1] == 0 {
		t.Fatalf("small packets not spread: %v", counts)
	}
}

func TestMTUFilterRedundant(t *testing.T) {
	s := New(DefaultConfig(), ModeRedundant)
	s.AddPath(0, 0, false)
	s.AddPath(1, 0, false)
	s.SetPathMTU(1, 1232)
	if out := s.Assign(1400, nil); len(out) != 1 || out[0] != 0 {
		t.Fatalf("redundant ignored MTU filter: %v", out)
	}
	if out := s.Assign(1000, nil); len(out) != 2 {
		t.Fatalf("small packet should use both: %v", out)
	}
}

func TestMTUSurvivesRejoin(t *testing.T) {
	s := New(DefaultConfig(), ModeBonding)
	s.AddPath(0, 0, false)
	s.AddPath(1, 0, false)
	s.SetPathMTU(1, 1232)
	s.SetState(1, StateDown)
	s.AddPath(1, 0, true) // revive
	counts := assign(s, 100, 1400)
	if counts[1] != 0 {
		t.Fatalf("MTU restriction lost across rejoin: %v", counts)
	}
}

func TestSlowStartOnRejoin(t *testing.T) {
	cfg := DefaultConfig()
	s := New(cfg, ModeBonding)
	s.AddPath(0, 20e6/8, true)
	if w := s.WeightBps(0); w != cfg.SlowStartBps {
		t.Fatalf("rejoin weight %v, want slow start %v", w, cfg.SlowStartBps)
	}
}
