package wire

import (
	"encoding/binary"
	"testing"
)

func TestFECHeaderRoundTrip(t *testing.T) {
	h := FECHeader{BaseSeq: MaxGlobalSeq - 5, K: 10, R: 3, Index: 2}
	b := make([]byte, FECHeaderSize+4)
	h.Marshal(b)
	got, shard, err := ParseFECHeader(b)
	if err != nil {
		t.Fatal(err)
	}
	if got != h {
		t.Fatalf("got %+v want %+v", got, h)
	}
	if len(shard) != 4 {
		t.Fatalf("shard len %d", len(shard))
	}
}

func TestParseFECHeaderRejects(t *testing.T) {
	b := make([]byte, FECHeaderSize+1)
	// K=0
	(&FECHeader{K: 0, R: 1}).Marshal(b)
	if _, _, err := ParseFECHeader(b); err == nil {
		t.Fatal("K=0 accepted")
	}
	// index >= R
	(&FECHeader{K: 4, R: 2, Index: 2}).Marshal(b)
	if _, _, err := ParseFECHeader(b); err == nil {
		t.Fatal("index >= R accepted")
	}
	// short
	if _, _, err := ParseFECHeader(b[:FECHeaderSize]); err != ErrShortPacket {
		t.Fatal("short packet accepted")
	}
}

func TestInnerIPLen(t *testing.T) {
	// IPv4 packet of 60 bytes inside an 80-byte padded buffer.
	buf := make([]byte, 80)
	buf[0] = 0x45
	binary.BigEndian.PutUint16(buf[2:4], 60)
	if n, ok := InnerIPLen(buf); !ok || n != 60 {
		t.Fatalf("ipv4: n=%d ok=%v", n, ok)
	}
	// IPv6: payload 24 -> total 64 inside 80.
	buf6 := make([]byte, 80)
	buf6[0] = 0x60
	binary.BigEndian.PutUint16(buf6[4:6], 24)
	if n, ok := InnerIPLen(buf6); !ok || n != 64 {
		t.Fatalf("ipv6: n=%d ok=%v", n, ok)
	}
	// Length exceeding buffer must fail.
	binary.BigEndian.PutUint16(buf[2:4], 200)
	if _, ok := InnerIPLen(buf); ok {
		t.Fatal("oversized length accepted")
	}
	// Garbage version nibble.
	if _, ok := InnerIPLen([]byte{0x10, 0, 0}); ok {
		t.Fatal("bad version accepted")
	}
}
