package wire

import "encoding/binary"

// Noise handshake payloads. Both are encrypted by the Noise handshake
// itself; each side contributes a 32-byte random seed from which the
// epoch's per-path traffic keys are derived (see package noiseio).

// InitPayloadSize is the plaintext payload size of HandshakeInit.
// version(1) + seed(32) + timestamp(8)
const InitPayloadSize = 41

// RespPayloadSize is the plaintext payload size of HandshakeResp.
// seed(32) + responder session index(4)
const RespPayloadSize = 36

// InitPayload is the client's handshake payload.
type InitPayload struct {
	Version byte
	Seed    [32]byte
	// TimestampNs is the client wall clock (unix nanoseconds). The server
	// requires it to be strictly greater than the last accepted value for
	// this peer, preventing handshake replay.
	TimestampNs uint64
}

func (p *InitPayload) Marshal(b []byte) {
	_ = b[InitPayloadSize-1]
	b[0] = p.Version
	copy(b[1:33], p.Seed[:])
	binary.LittleEndian.PutUint64(b[33:41], p.TimestampNs)
}

func ParseInitPayload(b []byte) (InitPayload, error) {
	if len(b) < InitPayloadSize {
		return InitPayload{}, ErrShortPacket
	}
	var p InitPayload
	p.Version = b[0]
	copy(p.Seed[:], b[1:33])
	p.TimestampNs = binary.LittleEndian.Uint64(b[33:41])
	return p, nil
}

// RespPayload is the server's handshake payload.
type RespPayload struct {
	Seed [32]byte
	// SessionID is the index the server assigned to this epoch; the client
	// must place it in the outer header of every packet it sends.
	SessionID uint32
}

func (p *RespPayload) Marshal(b []byte) {
	_ = b[RespPayloadSize-1]
	copy(b[0:32], p.Seed[:])
	binary.LittleEndian.PutUint32(b[32:36], p.SessionID)
}

func ParseRespPayload(b []byte) (RespPayload, error) {
	if len(b) < RespPayloadSize {
		return RespPayload{}, ErrShortPacket
	}
	var p RespPayload
	copy(p.Seed[:], b[0:32])
	p.SessionID = binary.LittleEndian.Uint32(b[32:36])
	return p, nil
}

// PathInitPayloadSize is the AEAD plaintext size of PathInit/PathAck.
// magic(4) + timestamp µs (8)
const PathInitPayloadSize = 12

// PathInitMagic distinguishes a valid decrypted PathInit from garbage.
var PathInitMagic = [4]byte{'a', 'm', 'n', 'e'}

// PutPathInitPayload writes a PathInit/PathAck payload.
func PutPathInitPayload(b []byte, tsUs uint64) {
	_ = b[PathInitPayloadSize-1]
	copy(b[0:4], PathInitMagic[:])
	binary.LittleEndian.PutUint64(b[4:12], tsUs)
}

// CheckPathInitPayload validates a decrypted PathInit/PathAck payload.
func CheckPathInitPayload(b []byte) bool {
	return len(b) >= PathInitPayloadSize && [4]byte(b[0:4]) == PathInitMagic
}
