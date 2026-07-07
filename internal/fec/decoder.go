package fec

import (
	"sync"

	"github.com/TKYcraft/amane/internal/wire"
)

const (
	// ringSize is how many recent data packets the decoder retains for
	// possible reconstruction (must exceed the group span of 15 by a
	// comfortable reordering margin). Slot buffers allocate lazily.
	ringSize = 256
	// maxGroups bounds tracked parity groups awaiting reconstruction.
	maxGroups = 64
)

// Recovered is one reconstructed data packet. Pkt is caller-owned: it
// aliases memory freshly allocated by the reconstruction (only missing
// shards are returned, and those are always newly allocated), never the
// decoder's reusable scratch.
type Recovered struct {
	Seq uint64
	Pkt []byte
}

// DecoderStats are cumulative counters.
type DecoderStats struct {
	Recovered uint64 `json:"recovered"`
	Failed    uint64 `json:"failed"` // groups that expired unreconstructable
}

type ringSlot struct {
	used bool
	seq  uint64
	n    int
	buf  []byte
}

type rxGroup struct {
	base      uint64
	k, r      int
	shardSize int
	parity    [][]byte // r slots
	got       int
	done      bool
}

// Decoder tracks received data packets and parity shards, reconstructing
// missing packets when enough of a group has arrived. Safe for
// concurrent use from multiple receive goroutines.
type Decoder struct {
	mu      sync.Mutex
	ring    [ringSize]ringSlot
	highest uint64
	started bool
	groups  map[uint64]*rxGroup
	scratch [][]byte
	stats   DecoderStats
}

// NewDecoder creates a decoder.
func NewDecoder() *Decoder {
	return &Decoder{groups: make(map[uint64]*rxGroup)}
}

// AddData records a received (already authenticated) data packet so it
// can serve as a data shard. Returns any packets that reconstruction
// completed as a side effect (rare; usually nil).
func (d *Decoder) AddData(seq uint64, ipPkt []byte) []Recovered {
	if len(ipPkt) > shardCap {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	s := &d.ring[seq%ringSize]
	if s.buf == nil {
		s.buf = make([]byte, shardCap)
	}
	copy(s.buf[:len(ipPkt)], ipPkt)
	*s = ringSlot{used: true, seq: seq, n: len(ipPkt), buf: s.buf}
	if !d.started || seq > d.highest {
		d.highest = seq
		d.started = true
	}
	d.pruneLocked()

	// This arrival may complete a tracked group (or make one solvable).
	for base, g := range d.groups {
		if g.done || seq < base || seq >= base+uint64(g.k) {
			continue
		}
		return d.tryReconstructLocked(g)
	}
	return nil
}

// AddParity ingests a parity shard and attempts reconstruction.
func (d *Decoder) AddParity(h wire.FECHeader, shard []byte) []Recovered {
	if len(shard) > shardCap {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	g := d.groups[h.BaseSeq]
	if g == nil {
		if len(d.groups) >= maxGroups {
			d.evictOldestLocked()
		}
		g = &rxGroup{
			base:      h.BaseSeq,
			k:         int(h.K),
			r:         int(h.R),
			shardSize: len(shard),
			parity:    make([][]byte, h.R),
		}
		d.groups[h.BaseSeq] = g
	}
	if g.done || int(h.K) != g.k || int(h.R) != g.r || len(shard) != g.shardSize {
		return nil // inconsistent or already handled
	}
	if g.parity[h.Index] == nil {
		g.parity[h.Index] = append([]byte(nil), shard...)
		g.got++
	}
	return d.tryReconstructLocked(g)
}

// tryReconstructLocked runs Reed-Solomon reconstruction if the group is
// missing data and enough shards are on hand.
func (d *Decoder) tryReconstructLocked(g *rxGroup) []Recovered {
	present := 0
	for i := 0; i < g.k; i++ {
		if s := &d.ring[(g.base+uint64(i))%ringSize]; s.used && s.seq == g.base+uint64(i) {
			present++
		}
	}
	missing := g.k - present
	if missing == 0 {
		g.done = true
		delete(d.groups, g.base)
		return nil
	}
	if g.got < missing {
		return nil // not solvable yet
	}

	enc, err := codec(g.k, g.r)
	if err != nil {
		return nil
	}
	// Assemble equal-size shards: present data (padded copies), nil for
	// missing, parity as stored.
	if len(d.scratch) < g.k {
		d.scratch = make([][]byte, g.k)
	}
	work := make([][]byte, g.k+g.r)
	for i := 0; i < g.k; i++ {
		s := &d.ring[(g.base+uint64(i))%ringSize]
		if s.used && s.seq == g.base+uint64(i) {
			if s.n > g.shardSize {
				return nil // sender inconsistency; give up on this group
			}
			if d.scratch[i] == nil {
				d.scratch[i] = make([]byte, shardCap)
			}
			buf := d.scratch[i][:g.shardSize]
			copy(buf, s.buf[:s.n])
			for j := s.n; j < g.shardSize; j++ {
				buf[j] = 0
			}
			work[i] = buf
		}
	}
	for i := 0; i < g.r; i++ {
		work[g.k+i] = g.parity[i]
	}
	if err := enc.ReconstructData(work); err != nil {
		return nil // parity insufficient or corrupt accounting; wait for more
	}

	var out []Recovered
	for i := 0; i < g.k; i++ {
		seq := g.base + uint64(i)
		s := &d.ring[seq%ringSize]
		if s.used && s.seq == seq {
			continue
		}
		n, ok := wire.InnerIPLen(work[i])
		if !ok {
			continue
		}
		out = append(out, Recovered{Seq: seq, Pkt: work[i][:n]})
		d.stats.Recovered++
	}
	g.done = true
	delete(d.groups, g.base)
	return out
}

// pruneLocked drops groups too old for their data shards to still be in
// the ring.
func (d *Decoder) pruneLocked() {
	if d.highest < ringSize {
		return
	}
	floor := d.highest - ringSize + uint64(wire.MaxFECShards)
	for base, g := range d.groups {
		if base < floor {
			if !g.done {
				d.stats.Failed++
			}
			delete(d.groups, base)
		}
	}
}

// evictOldestLocked makes room in the group table.
func (d *Decoder) evictOldestLocked() {
	var oldest uint64
	first := true
	for base := range d.groups {
		if first || base < oldest {
			oldest = base
			first = false
		}
	}
	if !first {
		if g := d.groups[oldest]; g != nil && !g.done {
			d.stats.Failed++
		}
		delete(d.groups, oldest)
	}
}

// Stats snapshots the counters.
func (d *Decoder) Stats() DecoderStats {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.stats
}
