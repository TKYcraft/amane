package wire

import "encoding/binary"

// ProbeSize is the serialized size of a Probe payload.
const ProbeSize = 44

// Probe is the per-path keepalive and quality measurement payload
// (AEAD-protected, indistinguishable from data on the wire).
//
// RTT is measured without clock synchronization: the receiver echoes the
// sender's monotonic timestamp along with its own processing delay, so
// rtt = now - EchoTSend - EchoDelay.
//
// Loss and delivery rate use cumulative counters (RxPackets/RxBytes are
// totals for this path since the epoch began), which avoids interval
// alignment problems between the two sides.
type Probe struct {
	Seq       uint32 // sender's probe sequence on this path
	TSendUs   uint64 // sender monotonic timestamp (µs)
	EchoSeq   uint32 // last received peer probe seq (0 if none)
	EchoTSend uint64 // that probe's TSendUs, echoed verbatim
	EchoDelay uint32 // µs between receiving that probe and sending this one
	RxPackets uint64 // cumulative data packets received on this path
	RxBytes   uint64 // cumulative data bytes received on this path
}

// Marshal writes the probe into b, which must be at least ProbeSize long.
func (p *Probe) Marshal(b []byte) {
	_ = b[ProbeSize-1]
	binary.LittleEndian.PutUint32(b[0:4], p.Seq)
	binary.LittleEndian.PutUint64(b[4:12], p.TSendUs)
	binary.LittleEndian.PutUint32(b[12:16], p.EchoSeq)
	binary.LittleEndian.PutUint64(b[16:24], p.EchoTSend)
	binary.LittleEndian.PutUint32(b[24:28], p.EchoDelay)
	binary.LittleEndian.PutUint64(b[28:36], p.RxPackets)
	binary.LittleEndian.PutUint64(b[36:44], p.RxBytes)
}

// ParseProbe reads a probe payload.
func ParseProbe(b []byte) (Probe, error) {
	if len(b) < ProbeSize {
		return Probe{}, ErrShortPacket
	}
	return Probe{
		Seq:       binary.LittleEndian.Uint32(b[0:4]),
		TSendUs:   binary.LittleEndian.Uint64(b[4:12]),
		EchoSeq:   binary.LittleEndian.Uint32(b[12:16]),
		EchoTSend: binary.LittleEndian.Uint64(b[16:24]),
		EchoDelay: binary.LittleEndian.Uint32(b[24:28]),
		RxPackets: binary.LittleEndian.Uint64(b[28:36]),
		RxBytes:   binary.LittleEndian.Uint64(b[36:44]),
	}, nil
}
