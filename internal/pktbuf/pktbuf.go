// Package pktbuf provides pooled packet buffers with the headroom layout
// shared by the whole data plane.
//
// Encapsulation (TUN → UDP) reads the inner IP packet at TunOffset and
// prepends headers in place:
//
//	[ 8B spare | 16B outer header | 8B inner header | IP packet | 16B tag ]
//	 0          8                  24                32
//
// Decapsulation (UDP → TUN) reads the datagram at offset 0; after in-place
// AEAD open the IP packet sits at offset 24, which satisfies the TUN write
// headroom requirement (10B virtio on Linux, 4B utun on macOS).
package pktbuf

import "sync"

const (
	// Size fits a 1500-byte-MTU inner packet plus all headers, plus
	// GSO-coalesced reads being split by the tun package.
	Size = 2048

	// TunOffset is where tun.Device.Read places the inner IP packet.
	TunOffset = 32

	// DatagramOffset is where the outer header begins for sending.
	DatagramOffset = 8

	// RxIPOffset is where the decrypted inner IP packet sits within a
	// received datagram (outer header 16 + inner header 8).
	RxIPOffset = 24
)

// Buf is one pooled packet buffer.
type Buf [Size]byte

var pool = sync.Pool{New: func() any { return new(Buf) }}

// Get returns a buffer from the pool.
func Get() *Buf { return pool.Get().(*Buf) }

// Put returns a buffer to the pool.
func Put(b *Buf) {
	if b != nil {
		pool.Put(b)
	}
}
