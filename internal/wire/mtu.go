package wire

import "encoding/binary"

// MTU discovery packets (see internal/pmtud). A TypeMTUProbe carries a
// 6-byte payload plus zero padding sized so the outer IP packet totals
// the probed wire MTU; the receiver answers with a TypeMTUAck echoing
// the id (no padding, so the ack passes any reverse path).
//
// Both are AEAD-protected with the normal path keys but are deliberately
// excluded from the loss/delivery accounting on both sides: probes are
// expected to be lost while searching, and counting them would poison
// the loss estimate that drives the scheduler.

// MTUPayloadSize is the id+size prefix of probe and ack payloads.
const MTUPayloadSize = 6

// Fixed per-packet overhead between plaintext and outer IP packet:
// outer IP header + UDP + amane header + AEAD tag.
const (
	probeOverheadV4 = 20 + 8 + HeaderSize + TagSize // 60
	probeOverheadV6 = 40 + 8 + HeaderSize + TagSize // 80
)

// PutMTUPayload writes an MTU probe/ack payload prefix.
func PutMTUPayload(b []byte, id uint32, size uint16) {
	_ = b[MTUPayloadSize-1]
	binary.LittleEndian.PutUint32(b[0:4], id)
	binary.LittleEndian.PutUint16(b[4:6], size)
}

// ParseMTUPayload reads an MTU probe/ack payload prefix.
func ParseMTUPayload(b []byte) (id uint32, size uint16, err error) {
	if len(b) < MTUPayloadSize {
		return 0, 0, ErrShortPacket
	}
	return binary.LittleEndian.Uint32(b[0:4]), binary.LittleEndian.Uint16(b[4:6]), nil
}

// ProbePlaintextLen returns the AEAD plaintext length that makes an MTU
// probe's outer IP packet exactly wireMTU bytes (< MTUPayloadSize means
// the probe cannot be built).
func ProbePlaintextLen(wireMTU int, v4 bool) int {
	if v4 {
		return wireMTU - probeOverheadV4
	}
	return wireMTU - probeOverheadV6
}

// MaxInnerForWireMTU converts a discovered path wire MTU into the
// largest inner IP packet a data packet on that path can carry.
func MaxInnerForWireMTU(wireMTU int, v4 bool) int {
	if v4 {
		return wireMTU - 28 - Overhead
	}
	return wireMTU - 48 - Overhead
}
