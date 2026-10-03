package pmtunotify

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

// buildTCPv4 crafts a minimal IPv4+TCP packet of totalLen bytes, DF set.
func buildTCPv4(src, dst netip.Addr, totalLen int) []byte {
	if totalLen < 40 {
		totalLen = 40
	}
	b := make([]byte, totalLen)
	b[0] = 0x45
	b[1] = 0
	binary.BigEndian.PutUint16(b[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(b[4:6], 1234)
	binary.BigEndian.PutUint16(b[6:8], 0x4000) // DF
	b[8] = 64
	b[9] = 6 // TCP
	s := src.As4()
	d := dst.As4()
	copy(b[12:16], s[:])
	copy(b[16:20], d[:])
	binary.BigEndian.PutUint16(b[10:12], checksum1071(b[:20]))
	// TCP header starts at 20; first 8 bytes = sports/dports/seq.
	binary.BigEndian.PutUint16(b[20:22], 51000) // src port
	binary.BigEndian.PutUint16(b[22:24], 22)    // dst port
	binary.BigEndian.PutUint32(b[24:28], 0xdeadbeef)
	return b
}

func buildTCPv6(src, dst netip.Addr, payloadLen int) []byte {
	total := 40 + 20 + payloadLen
	b := make([]byte, total)
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:6], uint16(20+payloadLen))
	b[6] = 6 // TCP
	b[7] = 64
	s := src.As16()
	d := dst.As16()
	copy(b[8:24], s[:])
	copy(b[24:40], d[:])
	binary.BigEndian.PutUint16(b[40:42], 51000)
	binary.BigEndian.PutUint16(b[42:44], 22)
	return b
}

func TestBuildPTBv4Shape(t *testing.T) {
	local := netip.MustParseAddr("10.77.0.2")
	src := netip.MustParseAddr("10.77.0.5")
	dst := netip.MustParseAddr("1.2.3.4")
	inner := buildTCPv4(src, dst, 1400)
	out := make([]byte, 2048)
	n, ok := BuildPTB(out, inner, local, 1232, 1400)
	if !ok {
		t.Fatal("BuildPTB rejected a valid v4 input")
	}
	if n > 1400 {
		t.Fatalf("v4 PTB exceeds maxOuter: n=%d", n)
	}
	// IPv4 header checks.
	if out[0] != 0x45 {
		t.Fatalf("version/IHL byte = %#x", out[0])
	}
	totalLen := binary.BigEndian.Uint16(out[2:4])
	if int(totalLen) != n {
		t.Fatalf("IP total-length %d != n %d", totalLen, n)
	}
	if out[9] != 1 {
		t.Fatalf("protocol = %d, want 1 (ICMP)", out[9])
	}
	if got := netip.AddrFrom4([4]byte(out[12:16])); got != local {
		t.Fatalf("IP src = %s, want local %s", got, local)
	}
	if got := netip.AddrFrom4([4]byte(out[16:20])); got != src {
		t.Fatalf("IP dst = %s, want original src %s", got, src)
	}
	if ck := checksum1071(out[:20]); ck != 0 {
		t.Fatalf("IP header checksum fails to verify: %#x", ck)
	}
	// ICMP checks.
	if out[20] != 3 || out[21] != 4 {
		t.Fatalf("ICMP type/code = %d/%d, want 3/4", out[20], out[21])
	}
	nextHop := binary.BigEndian.Uint16(out[26:28])
	if nextHop != 1232 {
		t.Fatalf("ICMP next-hop MTU = %d, want 1232", nextHop)
	}
	if ck := checksum1071(out[20:n]); ck != 0 {
		t.Fatalf("ICMP checksum fails to verify: %#x", ck)
	}
	// RFC 1191: data must include the inner IP header plus 8 bytes.
	data := out[28:n]
	if len(data) < 20+8 {
		t.Fatalf("ICMP data too short: %d", len(data))
	}
	if string(data[:20]) != string(inner[:20]) {
		t.Fatal("ICMP embedded IP header differs from original")
	}
}

func TestBuildPTBv4MTUFloor(t *testing.T) {
	local := netip.MustParseAddr("10.77.0.2")
	src := netip.MustParseAddr("10.77.0.5")
	dst := netip.MustParseAddr("1.2.3.4")
	inner := buildTCPv4(src, dst, 1400)
	out := make([]byte, 2048)
	n, ok := BuildPTB(out, inner, local, 200, 1400)
	if !ok {
		t.Fatal("BuildPTB rejected a valid input")
	}
	nextHop := binary.BigEndian.Uint16(out[26:28])
	if nextHop != minMTUv4 {
		t.Fatalf("next-hop MTU not clamped: got %d, want %d", nextHop, minMTUv4)
	}
	_ = n
}

func TestBuildPTBv4RejectsFragmentContinuation(t *testing.T) {
	inner := buildTCPv4(netip.MustParseAddr("10.77.0.5"), netip.MustParseAddr("1.2.3.4"), 1400)
	// Non-zero fragment offset.
	binary.BigEndian.PutUint16(inner[6:8], 0x4000|0x0010)
	out := make([]byte, 2048)
	if _, ok := BuildPTB(out, inner, netip.MustParseAddr("10.77.0.2"), 1232, 1400); ok {
		t.Fatal("fragment continuation should be rejected")
	}
}

func TestBuildPTBv4RejectsNoDF(t *testing.T) {
	inner := buildTCPv4(netip.MustParseAddr("10.77.0.5"), netip.MustParseAddr("1.2.3.4"), 1400)
	binary.BigEndian.PutUint16(inner[6:8], 0) // clear DF
	out := make([]byte, 2048)
	if _, ok := BuildPTB(out, inner, netip.MustParseAddr("10.77.0.2"), 1232, 1400); ok {
		t.Fatal("DF-unset packet should be rejected")
	}
}

func TestBuildPTBv4RejectsICMPError(t *testing.T) {
	// Craft an inner ICMP destination-unreachable; PTB on that would
	// amplify the error chain.
	inner := buildTCPv4(netip.MustParseAddr("10.77.0.5"), netip.MustParseAddr("1.2.3.4"), 60)
	inner[9] = 1 // ICMP
	inner[20] = 3
	inner[21] = 4
	out := make([]byte, 2048)
	if _, ok := BuildPTB(out, inner, netip.MustParseAddr("10.77.0.2"), 1232, 1400); ok {
		t.Fatal("ICMP error inner should be rejected")
	}
}

func TestBuildPTBv4RejectsBadSource(t *testing.T) {
	for _, bad := range []string{"224.0.0.1", "169.254.1.1", "0.0.0.0"} {
		inner := buildTCPv4(netip.MustParseAddr(bad), netip.MustParseAddr("1.2.3.4"), 1400)
		out := make([]byte, 2048)
		if _, ok := BuildPTB(out, inner, netip.MustParseAddr("10.77.0.2"), 1232, 1400); ok {
			t.Fatalf("bad source %s accepted", bad)
		}
	}
}

func TestBuildPTBv6Shape(t *testing.T) {
	local := netip.MustParseAddr("fd00::1")
	src := netip.MustParseAddr("fd00::5")
	dst := netip.MustParseAddr("2001:db8::1")
	inner := buildTCPv6(src, dst, 2000)
	out := make([]byte, 2048)
	n, ok := BuildPTB(out, inner, local, 1280, 1500)
	if !ok {
		t.Fatal("BuildPTB rejected a valid v6 input")
	}
	if n > 1280 {
		t.Fatalf("v6 PTB exceeds 1280: n=%d", n)
	}
	if (out[0] >> 4) != 6 {
		t.Fatalf("version = %d", out[0]>>4)
	}
	if out[6] != 58 {
		t.Fatalf("next-header = %d, want 58", out[6])
	}
	payloadLen := binary.BigEndian.Uint16(out[4:6])
	if int(payloadLen) != n-40 {
		t.Fatalf("v6 payload-length %d, want %d", payloadLen, n-40)
	}
	if got := netip.AddrFrom16([16]byte(out[8:24])); got != local {
		t.Fatalf("IPv6 src = %s, want %s", got, local)
	}
	if got := netip.AddrFrom16([16]byte(out[24:40])); got != src {
		t.Fatalf("IPv6 dst = %s, want %s", got, src)
	}
	if out[40] != 2 || out[41] != 0 {
		t.Fatalf("ICMPv6 type/code = %d/%d, want 2/0", out[40], out[41])
	}
	if adv := binary.BigEndian.Uint32(out[44:48]); adv != 1280 {
		t.Fatalf("ICMPv6 advertised MTU = %d, want 1280", adv)
	}
	// Verify pseudo-header checksum.
	if ck := checksumV6(local, src, out[40:n]); ck != 0 {
		t.Fatalf("ICMPv6 checksum verification = %#x", ck)
	}
}

func TestBuildPTBv6MTUFloor(t *testing.T) {
	local := netip.MustParseAddr("fd00::1")
	src := netip.MustParseAddr("fd00::5")
	dst := netip.MustParseAddr("2001:db8::1")
	inner := buildTCPv6(src, dst, 1500)
	out := make([]byte, 2048)
	_, ok := BuildPTB(out, inner, local, 800, 1500)
	if !ok {
		t.Fatal("BuildPTB rejected")
	}
	if adv := binary.BigEndian.Uint32(out[44:48]); adv != minMTUv6 {
		t.Fatalf("v6 MTU not clamped: %d, want %d", adv, minMTUv6)
	}
}

func TestBuildPTBv6RejectsICMPv6Error(t *testing.T) {
	inner := buildTCPv6(netip.MustParseAddr("fd00::5"), netip.MustParseAddr("2001:db8::1"), 10)
	inner[6] = 58
	inner[40] = 2 // Packet Too Big
	out := make([]byte, 2048)
	if _, ok := BuildPTB(out, inner, netip.MustParseAddr("fd00::1"), 1280, 1500); ok {
		t.Fatal("ICMPv6 error inner should be rejected")
	}
}

func TestBuildPTBFamilyMismatch(t *testing.T) {
	v4Inner := buildTCPv4(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), 1400)
	out := make([]byte, 2048)
	if _, ok := BuildPTB(out, v4Inner, netip.MustParseAddr("fd00::1"), 1232, 1400); ok {
		t.Fatal("v4 inner with v6 local must be rejected")
	}
	v6Inner := buildTCPv6(netip.MustParseAddr("fd00::1"), netip.MustParseAddr("fd00::2"), 100)
	if _, ok := BuildPTB(out, v6Inner, netip.MustParseAddr("10.0.0.1"), 1280, 1500); ok {
		t.Fatal("v6 inner with v4 local must be rejected")
	}
}

func TestLimiterBurstAndRefill(t *testing.T) {
	l := NewLimiter(4, 8)
	now := time.Unix(0, 0)
	src := netip.MustParseAddr("10.0.0.1")
	for i := 0; i < 8; i++ {
		if !l.Allow(src, now) {
			t.Fatalf("allow %d: wanted true within initial burst", i)
		}
	}
	if l.Allow(src, now) {
		t.Fatal("allow past burst: wanted false")
	}
	// 1 second later: 4 fresh tokens.
	later := now.Add(time.Second)
	for i := 0; i < 4; i++ {
		if !l.Allow(src, later) {
			t.Fatalf("refill %d: wanted true", i)
		}
	}
	if l.Allow(src, later) {
		t.Fatal("post-refill: wanted false")
	}
}

func TestLimiterPerSourceIsolation(t *testing.T) {
	l := NewLimiter(1, 2)
	now := time.Unix(0, 0)
	a := netip.MustParseAddr("10.0.0.1")
	b := netip.MustParseAddr("10.0.0.2")
	for i := 0; i < 2; i++ {
		if !l.Allow(a, now) {
			t.Fatalf("a %d", i)
		}
	}
	if l.Allow(a, now) {
		t.Fatal("a over quota but allowed")
	}
	// b should start fresh.
	if !l.Allow(b, now) {
		t.Fatal("b new src: wanted true")
	}
}

func TestChecksum1071Known(t *testing.T) {
	// Classic RFC 1071 example: two 16-bit words 0x0001 and 0xf203
	// → ~0x0df3 (sum 0xf204 complement). Just a sanity call: we use the
	// shape-level v4 test to assert full validity.
	b := []byte{0x00, 0x01, 0xf2, 0x03}
	got := checksum1071(b)
	// 0x0001 + 0xf203 = 0xf204 → ^ = 0x0dfb
	if want := uint16(0x0dfb); got != want {
		t.Fatalf("checksum1071 = %#x, want %#x", got, want)
	}
}
