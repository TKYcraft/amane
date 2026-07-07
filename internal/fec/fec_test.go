package fec

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/TKYcraft/amane/internal/wire"
)

// fakePkt builds a valid IPv4 packet of total length n with recognizable
// content derived from seq.
func fakePkt(seq uint64, n int) []byte {
	if n < 20 {
		n = 20
	}
	p := make([]byte, n)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(n))
	for i := 20; i < n; i++ {
		p[i] = byte(seq + uint64(i))
	}
	return p
}

func collect(enc *Encoder, dec *Decoder, seq uint64, pkt []byte, lose bool, now time.Time) (*Group, []Recovered) {
	g := enc.Add(seq, pkt, byte(seq%2), now)
	var recs []Recovered
	if !lose {
		recs = dec.AddData(seq, pkt)
	}
	return g, recs
}

func TestRoundTripNoLoss(t *testing.T) {
	enc := NewEncoder(4, 1, time.Hour, nil)
	dec := NewDecoder()
	now := time.Unix(0, 0)
	for seq := uint64(100); seq < 104; seq++ {
		g, recs := collect(enc, dec, seq, fakePkt(seq, 200), false, now)
		if len(recs) != 0 {
			t.Fatal("recovered packets without loss")
		}
		if seq == 103 && g == nil {
			t.Fatal("group did not close at K")
		} else if seq == 103 {
			for _, p := range g.Parities {
				if r := dec.AddParity(p.Header, p.Shard); len(r) != 0 {
					t.Fatal("reconstruction ran with no loss")
				}
			}
		}
	}
	if st := dec.Stats(); st.Recovered != 0 {
		t.Fatalf("stats: %+v", st)
	}
}

func TestRecoverSingleLoss(t *testing.T) {
	enc := NewEncoder(4, 1, time.Hour, nil)
	dec := NewDecoder()
	now := time.Unix(0, 0)
	lost := fakePkt(101, 333)
	var g *Group
	for seq := uint64(100); seq < 104; seq++ {
		pkt := fakePkt(seq, 200+int(seq-100)*133) // varying sizes
		if seq == 101 {
			pkt = lost
		}
		gg, _ := collect(enc, dec, seq, pkt, seq == 101, now)
		if gg != nil {
			g = gg
		}
	}
	if g == nil || len(g.Parities) != 1 {
		t.Fatalf("expected 1 parity, got %+v", g)
	}
	recs := dec.AddParity(g.Parities[0].Header, g.Parities[0].Shard)
	if len(recs) != 1 {
		t.Fatalf("recovered %d packets, want 1", len(recs))
	}
	if recs[0].Seq != 101 {
		t.Fatalf("recovered seq %d", recs[0].Seq)
	}
	if !bytes.Equal(recs[0].Pkt, lost) {
		t.Fatal("recovered packet differs from original")
	}
}

func TestRecoverDoubleLossTwoParity(t *testing.T) {
	enc := NewEncoder(6, 2, time.Hour, nil)
	dec := NewDecoder()
	now := time.Unix(0, 0)
	var g *Group
	originals := map[uint64][]byte{}
	for seq := uint64(0); seq < 6; seq++ {
		pkt := fakePkt(seq, 400)
		originals[seq] = pkt
		gg, _ := collect(enc, dec, seq, pkt, seq == 2 || seq == 4, now)
		if gg != nil {
			g = gg
		}
	}
	if g == nil || len(g.Parities) != 2 {
		t.Fatalf("expected 2 parities: %+v", g)
	}
	// First parity alone cannot solve 2 losses.
	if recs := dec.AddParity(g.Parities[0].Header, g.Parities[0].Shard); len(recs) != 0 {
		t.Fatal("reconstructed with insufficient parity")
	}
	recs := dec.AddParity(g.Parities[1].Header, g.Parities[1].Shard)
	if len(recs) != 2 {
		t.Fatalf("recovered %d packets, want 2", len(recs))
	}
	for _, r := range recs {
		if !bytes.Equal(r.Pkt, originals[r.Seq]) {
			t.Fatalf("seq %d content mismatch", r.Seq)
		}
	}
}

func TestParityBeforeData(t *testing.T) {
	// Parity may arrive before some of the group's data (reordering).
	enc := NewEncoder(3, 1, time.Hour, nil)
	dec := NewDecoder()
	now := time.Unix(0, 0)
	pkts := [][]byte{fakePkt(0, 100), fakePkt(1, 100), fakePkt(2, 100)}
	var g *Group
	for seq := uint64(0); seq < 3; seq++ {
		if gg := enc.Add(seq, pkts[seq], 0, now); gg != nil {
			g = gg
		}
	}
	// Deliver: data 0, parity, data 2 (data 1 lost).
	dec.AddData(0, pkts[0])
	if recs := dec.AddParity(g.Parities[0].Header, g.Parities[0].Shard); len(recs) != 0 {
		t.Fatal("premature reconstruction")
	}
	recs := dec.AddData(2, pkts[2])
	if len(recs) != 1 || recs[0].Seq != 1 {
		t.Fatalf("want recovery of seq 1, got %+v", recs)
	}
	if !bytes.Equal(recs[0].Pkt, pkts[1]) {
		t.Fatal("content mismatch")
	}
}

func TestFlushExpiredPartialGroup(t *testing.T) {
	enc := NewEncoder(10, 1, 8*time.Millisecond, nil)
	dec := NewDecoder()
	t0 := time.Unix(0, 0)
	pkt := fakePkt(50, 300)
	if g := enc.Add(50, pkt, 0, t0); g != nil {
		t.Fatal("group closed early")
	}
	if g := enc.FlushExpired(t0.Add(5 * time.Millisecond)); g != nil {
		t.Fatal("flushed before timeout")
	}
	g := enc.FlushExpired(t0.Add(10 * time.Millisecond))
	if g == nil || len(g.Parities) != 1 {
		t.Fatalf("timeout flush failed: %+v", g)
	}
	if g.Parities[0].Header.K != 1 {
		t.Fatalf("K=%d, want shortened group K=1", g.Parities[0].Header.K)
	}
	// Lost the only data packet; parity of K=1 group must recover it.
	recs := dec.AddParity(g.Parities[0].Header, g.Parities[0].Shard)
	if len(recs) != 1 || !bytes.Equal(recs[0].Pkt, pkt) {
		t.Fatalf("K=1 recovery failed: %+v", recs)
	}
}

func TestSeqDiscontinuityClosesGroup(t *testing.T) {
	enc := NewEncoder(8, 1, time.Hour, nil)
	now := time.Unix(0, 0)
	enc.Add(10, fakePkt(10, 100), 0, now)
	enc.Add(11, fakePkt(11, 100), 0, now)
	g := enc.Add(20, fakePkt(20, 100), 0, now) // jump
	if g == nil || len(g.Parities) != 1 || g.Parities[0].Header.K != 2 || g.Parities[0].Header.BaseSeq != 10 {
		t.Fatalf("discontinuity did not close group: %+v", g)
	}
}

func TestAdaptiveParityCount(t *testing.T) {
	loss := 0.0
	enc := NewEncoder(10, 0, time.Hour, func() float64 { return loss })
	now := time.Unix(0, 0)
	fill := func() *Group {
		var g *Group
		base := enc.stats.Groups * 100
		for i := uint64(0); i < 10; i++ {
			if gg := enc.Add(base*1000+i, fakePkt(i, 100), 0, now); gg != nil {
				g = gg
			}
		}
		return g
	}
	if g := fill(); len(g.Parities) != 1 {
		t.Fatalf("loss 0%%: R=%d, want 1", len(g.Parities))
	}
	loss = 0.10
	if g := fill(); len(g.Parities) != 3 {
		t.Fatalf("loss 10%%: R=%d, want 3", len(g.Parities))
	}
	loss = 0.50
	if g := fill(); len(g.Parities) != 4 {
		t.Fatalf("loss 50%%: R=%d, want capped 4", len(g.Parities))
	}
}

func TestDecoderPruning(t *testing.T) {
	dec := NewDecoder()
	// A group whose data will never arrive.
	h := wire.FECHeader{BaseSeq: 0, K: 4, R: 1, Index: 0}
	dec.AddParity(h, make([]byte, 100))
	// Advance far beyond the ring.
	for seq := uint64(1000); seq < 1000+ringSize+20; seq++ {
		dec.AddData(seq, fakePkt(seq, 60))
	}
	if st := dec.Stats(); st.Failed != 1 {
		t.Fatalf("stale group not pruned as failed: %+v", st)
	}
}

func TestPathCounts(t *testing.T) {
	enc := NewEncoder(4, 1, time.Hour, nil)
	now := time.Unix(0, 0)
	var g *Group
	paths := []byte{0, 0, 1, 0}
	for i, p := range paths {
		if gg := enc.Add(uint64(i), fakePkt(uint64(i), 100), p, now); gg != nil {
			g = gg
		}
	}
	if g.PathCounts[0] != 3 || g.PathCounts[1] != 1 {
		t.Fatalf("path counts: %v", g.PathCounts[:2])
	}
}
