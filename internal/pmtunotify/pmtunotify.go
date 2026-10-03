// Package pmtunotify builds ICMP "fragmentation needed" / "packet too big"
// replies for inner packets that the scheduler cannot carry on any path,
// so the local inner-TCP endpoint can shrink its MSS instead of blackhole
// retransmitting (classic PMTUD, from the tunnel-endpoint side).
//
// The caller supplies a destination slice; the local TUN address becomes
// the ICMP source so the host kernel accepts the reply as targeted at it
// (updating the inner socket's PMTU cache). A per-source token bucket
// prevents an oversized burst from provoking an ICMP storm.
package pmtunotify

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"time"
)

// Minimum next-hop MTUs mandated by the respective IP standards.
const (
	minMTUv4 = 576
	minMTUv6 = 1280
)

// BuildPTB writes an ICMP destination-unreachable / fragmentation-needed
// (v4) or packet-too-big (v6) reply into dst for inner. mtu is the
// next-hop MTU to advertise, clamped to the per-family floor. maxOuter
// caps the resulting datagram's wire length. ok is false when inner is
// not a reply-worthy packet (ICMP error, non-first fragment, DF unset on
// v4, multicast/link-local/unspecified source, malformed) or when local
// has the wrong family for inner.
func BuildPTB(dst, inner []byte, local netip.Addr, mtu, maxOuter int) (int, bool) {
	if len(inner) < 1 {
		return 0, false
	}
	switch inner[0] >> 4 {
	case 4:
		return buildV4(dst, inner, local, mtu, maxOuter)
	case 6:
		return buildV6(dst, inner, local, mtu, maxOuter)
	}
	return 0, false
}

func buildV4(dst, inner []byte, local netip.Addr, mtu, maxOuter int) (int, bool) {
	if len(inner) < 20 || !local.Is4() {
		return 0, false
	}
	ihl := int(inner[0]&0x0f) * 4
	if ihl < 20 || len(inner) < ihl {
		return 0, false
	}
	fragWord := binary.BigEndian.Uint16(inner[6:8])
	if fragWord&0x1fff != 0 { // not the first fragment
		return 0, false
	}
	if fragWord&0x4000 == 0 { // DF not set: PTB does not apply
		return 0, false
	}
	// Don't reply to ICMP error messages — avoids amplification loops.
	proto := inner[9]
	if proto == 1 && len(inner) >= ihl+1 {
		switch inner[ihl] {
		case 3, 4, 5, 11, 12:
			return 0, false
		}
	}
	src := netip.AddrFrom4([4]byte(inner[12:16]))
	if !src.IsValid() || src.IsMulticast() || src.IsLinkLocalUnicast() || src.IsUnspecified() {
		return 0, false
	}
	if mtu < minMTUv4 {
		mtu = minMTUv4
	}
	if mtu > 0xffff {
		mtu = 0xffff
	}
	// RFC 1812: ICMP data = original IP header + next 8 bytes (minimum).
	// We include as much as fits within maxOuter.
	const hdrs = 20 + 8 // outer IPv4 + ICMP
	payloadMax := maxOuter - hdrs
	minData := ihl + 8
	if payloadMax < minData {
		return 0, false
	}
	payloadLen := len(inner)
	if payloadLen > payloadMax {
		payloadLen = payloadMax
	}
	total := hdrs + payloadLen
	if total > len(dst) {
		return 0, false
	}
	// IPv4 header.
	dst[0] = 0x45
	dst[1] = 0
	binary.BigEndian.PutUint16(dst[2:4], uint16(total))
	binary.BigEndian.PutUint16(dst[4:6], 0) // id
	binary.BigEndian.PutUint16(dst[6:8], 0) // flags/frag
	dst[8] = 64                             // ttl
	dst[9] = 1                              // protocol ICMP
	dst[10], dst[11] = 0, 0                 // checksum placeholder
	localB := local.As4()
	copy(dst[12:16], localB[:])
	srcB := src.As4()
	copy(dst[16:20], srcB[:])
	ipCk := checksum1071(dst[0:20])
	binary.BigEndian.PutUint16(dst[10:12], ipCk)
	// ICMP header.
	dst[20] = 3                             // type: Destination Unreachable
	dst[21] = 4                             // code: Fragmentation Needed, DF set
	dst[22], dst[23] = 0, 0                 // checksum placeholder
	dst[24], dst[25] = 0, 0                 // unused (RFC 1191: deprecated)
	binary.BigEndian.PutUint16(dst[26:28], uint16(mtu))
	copy(dst[28:28+payloadLen], inner[:payloadLen])
	icmpCk := checksum1071(dst[20 : 28+payloadLen])
	binary.BigEndian.PutUint16(dst[22:24], icmpCk)
	return total, true
}

func buildV6(dst, inner []byte, local netip.Addr, mtu, maxOuter int) (int, bool) {
	if len(inner) < 40 || !(local.Is6() && !local.Is4In6()) {
		return 0, false
	}
	// Loop-prevention: skip if the first upper-layer header is ICMPv6 and
	// the message is itself an error. Only inspect the base-header's
	// Next Header; a chain of extension headers is uncommon enough to
	// accept the extra reply.
	if inner[6] == 58 && len(inner) >= 41 {
		switch inner[40] {
		case 1, 2, 3, 4:
			return 0, false
		}
	}
	src := netip.AddrFrom16([16]byte(inner[8:24]))
	if src.Is4In6() {
		src = src.Unmap()
	}
	if !src.IsValid() || src.IsMulticast() || src.IsLinkLocalUnicast() || src.IsUnspecified() {
		return 0, false
	}
	if mtu < minMTUv6 {
		mtu = minMTUv6
	}
	// RFC 4443 §2.4(c): ICMPv6 PTB total length must not exceed the IPv6
	// minimum MTU (1280 bytes).
	outer := maxOuter
	if outer > 1280 {
		outer = 1280
	}
	const hdrs = 40 + 8 // outer IPv6 + ICMPv6
	payloadMax := outer - hdrs
	if payloadMax < 40 { // at least the inner's own IPv6 header
		return 0, false
	}
	payloadLen := len(inner)
	if payloadLen > payloadMax {
		payloadLen = payloadMax
	}
	icmpLen := 8 + payloadLen
	total := 40 + icmpLen
	if total > len(dst) {
		return 0, false
	}
	// IPv6 header.
	dst[0], dst[1], dst[2], dst[3] = 0x60, 0, 0, 0
	binary.BigEndian.PutUint16(dst[4:6], uint16(icmpLen))
	dst[6] = 58 // next header: ICMPv6
	dst[7] = 64 // hop limit
	localB := local.As16()
	copy(dst[8:24], localB[:])
	srcB := src.As16()
	copy(dst[24:40], srcB[:])
	// ICMPv6.
	dst[40] = 2 // type: Packet Too Big
	dst[41] = 0 // code
	dst[42], dst[43] = 0, 0 // checksum placeholder
	binary.BigEndian.PutUint32(dst[44:48], uint32(mtu))
	copy(dst[48:48+payloadLen], inner[:payloadLen])
	ck := checksumV6(local, src, dst[40:40+icmpLen])
	binary.BigEndian.PutUint16(dst[42:44], ck)
	return total, true
}

// checksum1071 is RFC 1071 one's-complement internet checksum.
func checksum1071(b []byte) uint16 {
	var sum uint32
	i := 0
	for ; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if i < len(b) {
		sum += uint32(b[i]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// checksumV6 is the ICMPv6 checksum with the mandatory IPv6
// pseudo-header (src, dst, upper-layer length, next-header=58).
func checksumV6(src, dst netip.Addr, body []byte) uint16 {
	var sum uint32
	s := src.As16()
	d := dst.As16()
	for i := 0; i < 16; i += 2 {
		sum += uint32(s[i])<<8 | uint32(s[i+1])
		sum += uint32(d[i])<<8 | uint32(d[i+1])
	}
	ulLen := uint32(len(body))
	sum += ulLen >> 16
	sum += ulLen & 0xffff
	sum += 58
	i := 0
	for ; i+1 < len(body); i += 2 {
		sum += uint32(body[i])<<8 | uint32(body[i+1])
	}
	if i < len(body) {
		sum += uint32(body[i]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// Limiter is a per-source-address token bucket. Allow is safe for
// concurrent use. Idle entries are reaped opportunistically.
type Limiter struct {
	rate, burst float64

	mu      sync.Mutex
	buckets map[netip.Addr]*bucket
	tick    int
}

type bucket struct {
	tokens float64
	last   time.Time
}

// Maximum tracked sources before an eviction sweep runs.
const limiterSoftCap = 1024

// Scan the whole map every N allows to reap idle sources.
const sweepStride = 128

// NewLimiter returns a token bucket emitting ratePerSec per source with
// burst leeway.
func NewLimiter(ratePerSec, burst float64) *Limiter {
	if ratePerSec <= 0 {
		ratePerSec = 1
	}
	if burst < 1 {
		burst = 1
	}
	return &Limiter{rate: ratePerSec, burst: burst, buckets: make(map[netip.Addr]*bucket)}
}

// Allow consumes a token for src at time now, returning true when one was
// available. The bucket for a new source starts full.
func (l *Limiter) Allow(src netip.Addr, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[src]
	if b == nil {
		if len(l.buckets) >= limiterSoftCap {
			l.sweepLocked(now, time.Second)
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[src] = b
	} else {
		b.tokens += now.Sub(b.last).Seconds() * l.rate
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
		b.last = now
	}
	l.tick++
	if l.tick >= sweepStride {
		l.tick = 0
		l.sweepLocked(now, 10*time.Second)
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *Limiter) sweepLocked(now time.Time, idle time.Duration) {
	for a, b := range l.buckets {
		if now.Sub(b.last) > idle && b.tokens >= l.burst-0.001 {
			delete(l.buckets, a)
		}
	}
}
