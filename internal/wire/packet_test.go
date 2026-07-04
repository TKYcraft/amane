package wire

import (
	"bytes"
	"testing"
)

func TestHeaderRoundTrip(t *testing.T) {
	h := Header{Type: TypeData, PathID: 7, SessionID: 0xdeadbeef, Counter: 1<<63 + 12345}
	var b [HeaderSize]byte
	h.Marshal(b[:])
	got, err := ParseHeader(b[:])
	if err != nil {
		t.Fatal(err)
	}
	if got != h {
		t.Fatalf("got %+v want %+v", got, h)
	}
}

func TestParseHeaderShort(t *testing.T) {
	if _, err := ParseHeader(make([]byte, HeaderSize-1)); err != ErrShortPacket {
		t.Fatalf("want ErrShortPacket, got %v", err)
	}
}

func TestParseHeaderBadPath(t *testing.T) {
	var b [HeaderSize]byte
	(&Header{Type: TypeData, PathID: MaxPaths}).Marshal(b[:])
	b[1] = MaxPaths
	if _, err := ParseHeader(b[:]); err != ErrBadPathID {
		t.Fatalf("want ErrBadPathID, got %v", err)
	}
}

func TestDataHeaderRoundTrip(t *testing.T) {
	payload := []byte("hello ip packet")
	b := make([]byte, DataHeaderSize+len(payload))
	seq := uint64(MaxGlobalSeq)
	PutDataHeader(b, seq, FlagDuplicate)
	copy(b[DataHeaderSize:], payload)
	gotSeq, flags, gotPayload, err := ParseDataHeader(b)
	if err != nil {
		t.Fatal(err)
	}
	if gotSeq != seq || flags != FlagDuplicate || !bytes.Equal(gotPayload, payload) {
		t.Fatalf("round trip mismatch: seq=%d flags=%d payload=%q", gotSeq, flags, gotPayload)
	}
}

func TestProbeRoundTrip(t *testing.T) {
	p := Probe{Seq: 42, TSendUs: 1 << 50, EchoSeq: 41, EchoTSend: 999, EchoDelay: 150, RxPackets: 1 << 40, RxBytes: 1 << 45}
	var b [ProbeSize]byte
	p.Marshal(b[:])
	got, err := ParseProbe(b[:])
	if err != nil {
		t.Fatal(err)
	}
	if got != p {
		t.Fatalf("got %+v want %+v", got, p)
	}
}

func FuzzParseHeader(f *testing.F) {
	f.Add(make([]byte, HeaderSize))
	f.Fuzz(func(t *testing.T, b []byte) {
		h, err := ParseHeader(b)
		if err == nil {
			var out [HeaderSize]byte
			h.Marshal(out[:])
		}
	})
}
