package wire

import (
	"encoding/binary"
	"errors"
)

// FEC (TypeFEC) carries one Reed-Solomon parity shard protecting a group
// of consecutive data packets (systematic code: the data packets
// themselves are the data shards and are sent unmodified).
//
// A group covers the inner IP packets of global_seq [BaseSeq, BaseSeq+K),
// each zero-padded to the group's shard size. The shard size is implied
// by the payload length (plaintext length - FECHeaderSize), so it is not
// carried explicitly. A reconstructed shard's true packet length is
// recovered from its own IP header (IPv4 total length / IPv6 payload
// length), and its sequence number is BaseSeq + shard index; both are
// trustworthy because every input shard was AEAD-authenticated.
//
// The FEC header is exactly DataHeaderSize (8) bytes so a parity packet
// is never larger on the wire than the largest possible data packet:
// enabling FEC does not change the MTU budget.
//
// Header layout (inside AEAD):
//
//	0  6  base_seq (48-bit LE, global_seq of the group's first packet)
//	6  1  K<<4 | R      (data shards / parity shards, each 1..15)
//	7  1  index<<4 | 0  (which parity shard this is, 0..R-1)
const FECHeaderSize = 8

// MaxFECShards bounds K and R (4-bit fields).
const MaxFECShards = 15

// FlagFEC marks data packets sent under FEC mode; the server mirrors the
// client's mode from it (like FlagDuplicate for redundant).
const FlagFEC byte = 1 << 1

// FECHeader describes one parity shard.
type FECHeader struct {
	BaseSeq uint64 // 48-bit
	K       byte   // data shards in the group (1..15)
	R       byte   // parity shards generated for the group (1..15)
	Index   byte   // this parity shard's index (0..R-1)
}

// Marshal writes the header into b (at least FECHeaderSize long).
func (h *FECHeader) Marshal(b []byte) {
	_ = b[FECHeaderSize-1]
	b[0] = byte(h.BaseSeq)
	b[1] = byte(h.BaseSeq >> 8)
	b[2] = byte(h.BaseSeq >> 16)
	b[3] = byte(h.BaseSeq >> 24)
	b[4] = byte(h.BaseSeq >> 32)
	b[5] = byte(h.BaseSeq >> 40)
	b[6] = h.K<<4 | h.R&0x0f
	b[7] = h.Index << 4
}

// ParseFECHeader reads a FEC header and returns the parity shard bytes
// (aliasing b).
func ParseFECHeader(b []byte) (FECHeader, []byte, error) {
	if len(b) < FECHeaderSize+1 { // header plus at least one shard byte
		return FECHeader{}, nil, ErrShortPacket
	}
	h := FECHeader{
		BaseSeq: uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 |
			uint64(b[3])<<24 | uint64(b[4])<<32 | uint64(b[5])<<40,
		K:     b[6] >> 4,
		R:     b[6] & 0x0f,
		Index: b[7] >> 4,
	}
	if h.K == 0 || h.R == 0 || h.Index >= h.R {
		return FECHeader{}, nil, ErrBadFEC
	}
	return h, b[FECHeaderSize:], nil
}

// ErrBadFEC reports a malformed FEC header.
var ErrBadFEC = errors.New("wire: invalid fec header")

// InnerIPLen returns the true length of an IP packet whose buffer may
// carry zero padding (used after Reed-Solomon reconstruction). ok is
// false if the header is not parseable or the length exceeds the buffer.
func InnerIPLen(b []byte) (int, bool) {
	if len(b) < 1 {
		return 0, false
	}
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 {
			return 0, false
		}
		n := int(binary.BigEndian.Uint16(b[2:4]))
		if n < 20 || n > len(b) {
			return 0, false
		}
		return n, true
	case 6:
		if len(b) < 40 {
			return 0, false
		}
		n := 40 + int(binary.BigEndian.Uint16(b[4:6]))
		if n > len(b) {
			return 0, false
		}
		return n, true
	}
	return 0, false
}
