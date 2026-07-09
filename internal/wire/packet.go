// Package wire defines the amane wire format: the outer packet header
// carried in every UDP datagram and the inner data header protected by
// AEAD. It contains pure serialization only — no crypto, no I/O.
//
// Outer header (16 bytes, authenticated as AEAD additional data):
//
//	offset size field
//	0      1    type
//	1      1    path_id
//	2      2    reserved (0 on send, ignored on receive)
//	4      4    session_id (LE, receiver index)
//	8      8    counter    (LE, per-path send counter = AEAD nonce)
//
// Data plaintext (inside AEAD):
//
//	0      6    global_seq (48-bit LE)
//	6      1    flags
//	7      1    reserved
//	8      -    inner IP packet
package wire

import (
	"encoding/binary"
	"errors"
)

// Packet types.
const (
	TypeHandshakeInit byte = 1
	TypeHandshakeResp byte = 2
	TypeData          byte = 3
	TypeProbe         byte = 4
	TypePathInit      byte = 5
	TypePathAck       byte = 6
	TypeClose         byte = 7
	TypeFEC           byte = 8
	TypeMTUProbe      byte = 9
	TypeMTUAck        byte = 10
)

// ProtocolVersion is carried in the handshake payload; both sides must match.
const ProtocolVersion byte = 1

const (
	// HeaderSize is the outer header length.
	HeaderSize = 16
	// DataHeaderSize is the inner data header length (inside AEAD).
	DataHeaderSize = 8
	// TagSize is the AEAD (ChaCha20-Poly1305) tag length.
	TagSize = 16
	// Overhead is the total per-packet overhead on top of the inner IP
	// packet: outer header + inner header + AEAD tag. UDP/IP headers of
	// the outer packet are not included.
	Overhead = HeaderSize + DataHeaderSize + TagSize

	// MaxPaths is the maximum number of paths per session.
	MaxPaths = 32

	// MaxGlobalSeq is the largest representable 48-bit sequence number.
	MaxGlobalSeq = 1<<48 - 1
)

// Data flags.
const (
	// FlagDuplicate marks a packet sent redundantly on multiple paths.
	FlagDuplicate byte = 1 << 0
)

var (
	ErrShortPacket = errors.New("wire: packet too short")
	ErrBadPathID   = errors.New("wire: path id out of range")
)

// Header is the outer packet header.
type Header struct {
	Type      byte
	PathID    byte
	SessionID uint32
	Counter   uint64
}

// Marshal writes the header into b, which must be at least HeaderSize long.
func (h *Header) Marshal(b []byte) {
	_ = b[HeaderSize-1]
	b[0] = h.Type
	b[1] = h.PathID
	b[2] = 0
	b[3] = 0
	binary.LittleEndian.PutUint32(b[4:8], h.SessionID)
	binary.LittleEndian.PutUint64(b[8:16], h.Counter)
}

// ParseHeader reads the outer header from the start of b.
func ParseHeader(b []byte) (Header, error) {
	if len(b) < HeaderSize {
		return Header{}, ErrShortPacket
	}
	h := Header{
		Type:      b[0],
		PathID:    b[1],
		SessionID: binary.LittleEndian.Uint32(b[4:8]),
		Counter:   binary.LittleEndian.Uint64(b[8:16]),
	}
	if h.PathID >= MaxPaths {
		return Header{}, ErrBadPathID
	}
	return h, nil
}

// PutDataHeader writes the inner data header (global_seq + flags) into b.
func PutDataHeader(b []byte, globalSeq uint64, flags byte) {
	_ = b[DataHeaderSize-1]
	b[0] = byte(globalSeq)
	b[1] = byte(globalSeq >> 8)
	b[2] = byte(globalSeq >> 16)
	b[3] = byte(globalSeq >> 24)
	b[4] = byte(globalSeq >> 32)
	b[5] = byte(globalSeq >> 40)
	b[6] = flags
	b[7] = 0
}

// ParseDataHeader reads the inner data header. The returned payload slice
// aliases b.
func ParseDataHeader(b []byte) (globalSeq uint64, flags byte, payload []byte, err error) {
	if len(b) < DataHeaderSize {
		return 0, 0, nil, ErrShortPacket
	}
	globalSeq = uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 |
		uint64(b[3])<<24 | uint64(b[4])<<32 | uint64(b[5])<<40
	return globalSeq, b[6], b[8:], nil
}
