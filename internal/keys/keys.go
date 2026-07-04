// Package keys implements Curve25519 key generation and encoding,
// following the WireGuard convention (base64-encoded 32-byte keys).
package keys

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/curve25519"
)

// KeySize is the size in bytes of Curve25519 keys and preshared keys.
const KeySize = 32

// Key is a 32-byte key (private, public, or preshared).
type Key [KeySize]byte

// GeneratePrivateKey returns a new random Curve25519 private key,
// clamped per the X25519 specification.
func GeneratePrivateKey() (Key, error) {
	var k Key
	if _, err := rand.Read(k[:]); err != nil {
		return Key{}, fmt.Errorf("generate private key: %w", err)
	}
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
	return k, nil
}

// PublicKey computes the Curve25519 public key for a private key.
func PublicKey(private Key) Key {
	var pub Key
	p, _ := curve25519.X25519(private[:], curve25519.Basepoint)
	copy(pub[:], p)
	return pub
}

// Parse decodes a base64-encoded 32-byte key.
func Parse(s string) (Key, error) {
	var k Key
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return Key{}, fmt.Errorf("invalid key encoding: %w", err)
	}
	if len(b) != KeySize {
		return Key{}, fmt.Errorf("invalid key length %d, want %d", len(b), KeySize)
	}
	copy(k[:], b)
	return k, nil
}

// LoadFile reads and parses a base64-encoded key from a file.
func LoadFile(path string) (Key, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Key{}, err
	}
	k, err := Parse(string(b))
	if err != nil {
		return Key{}, fmt.Errorf("%s: %w", path, err)
	}
	return k, nil
}

// String returns the base64 encoding of the key.
func (k Key) String() string {
	return base64.StdEncoding.EncodeToString(k[:])
}

// IsZero reports whether the key is all zeros.
func (k Key) IsZero() bool {
	var zero Key
	return k == zero
}

// ShortString returns a truncated key for log output.
func (k Key) ShortString() string {
	return k.String()[:8] + "…"
}
