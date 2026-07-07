// Package fec implements the Reed-Solomon forward-error-correction layer:
// a middle ground between bonding (no loss protection) and redundant
// (100%+ overhead). The code is systematic — data packets travel
// unmodified and parity shards (wire.TypeFEC) protect groups of K
// consecutive global sequence numbers, so when nothing is lost the
// receiver does no FEC work at all.
//
// Shards cover the raw inner IP packets, zero-padded to the group's
// largest packet. A reconstructed packet's length is recovered from its
// own IP header and its sequence number is BaseSeq + shard index (see
// wire/fec.go for why that is sound).
package fec

import (
	"sync"
	"time"

	"github.com/klauspost/reedsolomon"

	"github.com/TKYcraft/amane/internal/wire"
)

// shardCap fits any inner packet (MTU ≤ 1500) with headroom.
const shardCap = 2048

// codecs caches Reed-Solomon encoders per (K, R); they are stateless and
// safe for concurrent use.
var codecs sync.Map // uint16(k<<8|r) -> reedsolomon.Encoder

func codec(k, r int) (reedsolomon.Encoder, error) {
	key := uint16(k)<<8 | uint16(r)
	if v, ok := codecs.Load(key); ok {
		return v.(reedsolomon.Encoder), nil
	}
	enc, err := reedsolomon.New(k, r)
	if err != nil {
		return nil, err
	}
	v, _ := codecs.LoadOrStore(key, enc)
	return v.(reedsolomon.Encoder), nil
}

// --- Encoder (send side) ---

// Parity is one shard to transmit. Shard is freshly allocated per group
// and owned by the caller (the data path and the flush timer run in
// different goroutines, so aliasing encoder buffers would race).
type Parity struct {
	Header wire.FECHeader
	Shard  []byte
}

// Group is the result of closing one FEC group.
type Group struct {
	Parities []Parity
	// PathCounts is how many of the group's data shards each path
	// carried; the caller uses it to place parity on the least-loaded
	// (least-correlated) paths.
	PathCounts [wire.MaxPaths]uint16
}

// EncoderStats are cumulative counters.
type EncoderStats struct {
	Groups     uint64 `json:"groups"`
	ParitySent uint64 `json:"parity_sent"`
}

// Encoder accumulates sent data packets into groups and emits parity.
// Safe for concurrent use (data path + flush timer).
type Encoder struct {
	mu         sync.Mutex
	k          int           // max data shards per group
	rFixed     int           // 0 = adaptive from loss()
	flushAfter time.Duration // close a partial group after this long
	loss       func() float64

	baseSeq    uint64
	n          int
	maxLen     int
	lens       []int
	shards     [][]byte // k data slots + MaxFECShards parity slots
	pathCounts [wire.MaxPaths]uint16
	startedAt  time.Time

	stats EncoderStats
}

// NewEncoder creates an encoder. k is the group size (2..15); rParity is
// the fixed parity count, or 0 to adapt from loss() (the current worst
// active-path loss estimate, 0..1).
func NewEncoder(k, rParity int, flushAfter time.Duration, loss func() float64) *Encoder {
	if k < 2 {
		k = 2
	}
	if k > wire.MaxFECShards {
		k = wire.MaxFECShards
	}
	if rParity > wire.MaxFECShards {
		rParity = wire.MaxFECShards
	}
	e := &Encoder{
		k:          k,
		rFixed:     rParity,
		flushAfter: flushAfter,
		loss:       loss,
		lens:       make([]int, k),
		shards:     make([][]byte, k+wire.MaxFECShards),
	}
	for i := range e.shards {
		e.shards[i] = make([]byte, shardCap)
	}
	return e
}

// Add records a sent data packet (before encryption destroys the
// plaintext). seq must be the packet's global sequence number and pathID
// the path it was scheduled on. Returns a closed group when this packet
// filled it, else nil.
func (e *Encoder) Add(seq uint64, ipPkt []byte, pathID byte, now time.Time) *Group {
	if len(ipPkt) > shardCap {
		return nil // cannot protect; never happens with sane MTUs
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	var out *Group
	// Groups must cover contiguous sequence numbers; a discontinuity
	// (mode switch races, dropped assignment) closes the current group.
	if e.n > 0 && seq != e.baseSeq+uint64(e.n) {
		out = e.flushLocked()
	}
	if e.n == 0 {
		e.baseSeq = seq
		e.startedAt = now
		e.maxLen = 0
	}
	copy(e.shards[e.n][:len(ipPkt)], ipPkt)
	e.lens[e.n] = len(ipPkt)
	if len(ipPkt) > e.maxLen {
		e.maxLen = len(ipPkt)
	}
	e.pathCounts[pathID]++
	e.n++
	if e.n == e.k {
		g := e.flushLocked()
		if out == nil {
			out = g
		} else if g != nil {
			// Two closures in one call (discontinuity + fill): deliver the
			// merged parity list; path counts of the later group win.
			out.Parities = append(out.Parities, g.Parities...)
			out.PathCounts = g.PathCounts
		}
	}
	return out
}

// FlushExpired closes a partial group older than the flush timeout.
func (e *Encoder) FlushExpired(now time.Time) *Group {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.n == 0 || now.Sub(e.startedAt) < e.flushAfter {
		return nil
	}
	return e.flushLocked()
}

// parityCount picks R for a group of k data shards.
func (e *Encoder) parityCount(k int) int {
	r := e.rFixed
	if r == 0 {
		// Adaptive: 1 parity at zero loss, ~2x the measured loss rate on
		// top of that, capped to keep overhead bounded.
		l := 0.0
		if e.loss != nil {
			l = e.loss()
		}
		r = 1 + int(float64(k)*2*l+0.5)
	}
	if r > 4 {
		r = 4
	}
	if r > k {
		r = k
	}
	if r < 1 {
		r = 1
	}
	return r
}

// flushLocked encodes the current group's parity. The returned Group
// (including shard memory) is valid until the next Encoder call.
func (e *Encoder) flushLocked() *Group {
	if e.n == 0 {
		return nil
	}
	k, size := e.n, e.maxLen
	r := e.parityCount(k)

	enc, err := codec(k, r)
	if err != nil {
		e.n = 0
		e.pathCounts = [wire.MaxPaths]uint16{}
		return nil
	}
	// Zero the padding tail of every data shard (buffers are reused).
	work := make([][]byte, k+r)
	for i := 0; i < k; i++ {
		s := e.shards[i][:size]
		for j := e.lens[i]; j < size; j++ {
			s[j] = 0
		}
		work[i] = s
	}
	for i := 0; i < r; i++ {
		work[k+i] = e.shards[e.k+i][:size]
	}
	if err := enc.Encode(work); err != nil {
		e.n = 0
		e.pathCounts = [wire.MaxPaths]uint16{}
		return nil
	}

	g := &Group{PathCounts: e.pathCounts}
	for i := 0; i < r; i++ {
		g.Parities = append(g.Parities, Parity{
			Header: wire.FECHeader{BaseSeq: e.baseSeq, K: byte(k), R: byte(r), Index: byte(i)},
			Shard:  append([]byte(nil), work[k+i]...),
		})
	}
	e.stats.Groups++
	e.stats.ParitySent += uint64(r)
	e.n = 0
	e.pathCounts = [wire.MaxPaths]uint16{}
	return g
}

// Stats snapshots the counters.
func (e *Encoder) Stats() EncoderStats {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.stats
}
