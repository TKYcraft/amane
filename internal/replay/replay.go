// Package replay implements an anti-replay sliding window in the style of
// RFC 6479, using a bitmap of blocks. It is not safe for concurrent use;
// callers hold the per-path receive lock.
package replay

const (
	blockBits  = 64
	blockShift = 6
	// WindowSize is the number of counters tracked behind the highest
	// received counter. Packets older than this are rejected.
	WindowSize = 2048
	numBlocks  = WindowSize / blockBits
	blockMask  = numBlocks - 1
	bitMask    = blockBits - 1
)

// Window tracks received per-path counters and rejects duplicates and
// packets older than WindowSize.
type Window struct {
	blocks  [numBlocks]uint64
	highest uint64
	started bool
}

// Check reports whether counter is acceptable (not seen, not too old) and
// marks it as seen.
func (w *Window) Check(counter uint64) bool {
	if !w.started {
		// First packet on this path: accept anything and anchor the window.
		w.started = true
		w.highest = counter
		w.blocks[(counter>>blockShift)&blockMask] = 1 << (counter & bitMask)
		return true
	}
	switch {
	case counter > w.highest:
		// Advance the window, clearing skipped blocks.
		curBlock := w.highest >> blockShift
		newBlock := counter >> blockShift
		diff := newBlock - curBlock
		if diff > numBlocks {
			diff = numBlocks
		}
		for i := uint64(1); i <= diff; i++ {
			w.blocks[(curBlock+i)&blockMask] = 0
		}
		w.highest = counter
	case w.highest-counter >= WindowSize:
		return false // too old
	}
	block := &w.blocks[(counter>>blockShift)&blockMask]
	bit := uint64(1) << (counter & bitMask)
	if *block&bit != 0 {
		return false // duplicate
	}
	*block |= bit
	return true
}
