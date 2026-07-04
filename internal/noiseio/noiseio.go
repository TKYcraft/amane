// Package noiseio wraps the Noise IKpsk2 handshake (flynn/noise) and owns
// the per-epoch cryptographic state: per-path AEADs derived via HKDF,
// per-path send counters, and anti-replay windows.
//
// Key schedule: each side contributes a random 32-byte seed inside its
// encrypted handshake payload. The epoch secret is
//
//	prk = HKDF-Extract(BLAKE2s, ikm = clientSeed‖serverSeed, salt = channelBinding)
//
// and per-path, per-direction traffic keys are
//
//	key = HKDF-Expand(prk, "amane-v1 " + dir + pathID)
//
// so every path has an independent nonce space and replay window, and no
// counter coordination is needed across paths.
package noiseio

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"hash"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/flynn/noise"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"

	"github.com/TKYcraft/amane/internal/keys"
	"github.com/TKYcraft/amane/internal/replay"
	"github.com/TKYcraft/amane/internal/wire"
)

var errAuth = errors.New("noiseio: decryption failed")

// Prologue binds both sides to the same protocol revision.
var prologue = []byte("amane v1")

func cipherSuite() noise.CipherSuite {
	return noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)
}

func blake2sNew() hash.Hash {
	h, err := blake2s.New256(nil)
	if err != nil {
		panic(err)
	}
	return h
}

func newConfig(priv keys.Key, psk keys.Key, initiator bool) noise.Config {
	pub := keys.PublicKey(priv)
	return noise.Config{
		CipherSuite: cipherSuite(),
		Pattern:     noise.HandshakeIK,
		Initiator:   initiator,
		Prologue:    prologue,
		StaticKeypair: noise.DHKey{
			Private: priv[:],
			Public:  pub[:],
		},
		// Always run as psk2 (zero PSK when unset) so both sides agree on
		// the protocol name Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s.
		PresharedKey:          psk[:],
		PresharedKeyPlacement: 2,
	}
}

// Epoch is the result of one completed handshake: all traffic-key state
// for one key generation. Safe for concurrent use.
type Epoch struct {
	txID      uint32 // session_id we put in outgoing headers (peer-assigned)
	rxID      uint32 // session_id peers put in headers addressed to us
	createdAt time.Time

	send [wire.MaxPaths]cipher.AEAD
	recv [wire.MaxPaths]cipher.AEAD

	ctr [wire.MaxPaths]atomic.Uint64

	win [wire.MaxPaths]struct {
		mu sync.Mutex
		w  replay.Window
	}
}

func newEpoch(clientSeed, serverSeed [32]byte, channelBinding []byte, txID, rxID uint32, isClient bool) (*Epoch, error) {
	ikm := make([]byte, 0, 64)
	ikm = append(ikm, clientSeed[:]...)
	ikm = append(ikm, serverSeed[:]...)
	prk := hkdf.Extract(blake2sNew, ikm, channelBinding)

	e := &Epoch{txID: txID, rxID: rxID, createdAt: time.Now()}
	c2s, s2c := "c2s", "s2c"
	sendDir, recvDir := c2s, s2c
	if !isClient {
		sendDir, recvDir = s2c, c2s
	}
	for p := 0; p < wire.MaxPaths; p++ {
		var err error
		if e.send[p], err = deriveAEAD(prk, sendDir, byte(p)); err != nil {
			return nil, err
		}
		if e.recv[p], err = deriveAEAD(prk, recvDir, byte(p)); err != nil {
			return nil, err
		}
	}
	return e, nil
}

func deriveAEAD(prk []byte, dir string, pathID byte) (cipher.AEAD, error) {
	info := append([]byte("amane-v1 "+dir+" path "), pathID)
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(hkdf.Expand(blake2sNew, prk, info), key); err != nil {
		return nil, err
	}
	return chacha20poly1305.New(key)
}

// TxSessionID returns the session_id to place in outgoing headers.
func (e *Epoch) TxSessionID() uint32 { return e.txID }

// RxSessionID returns the session_id under which we receive.
func (e *Epoch) RxSessionID() uint32 { return e.rxID }

// CreatedAt returns when the handshake completed.
func (e *Epoch) CreatedAt() time.Time { return e.createdAt }

// NextCounter returns the next send counter for a path (also the AEAD nonce).
func (e *Epoch) NextCounter(pathID byte) uint64 {
	return e.ctr[pathID].Add(1)
}

// SendCounter returns the current send counter for a path.
func (e *Epoch) SendCounter(pathID byte) uint64 {
	return e.ctr[pathID].Load()
}

func nonceFor(counter uint64) [chacha20poly1305.NonceSize]byte {
	var n [chacha20poly1305.NonceSize]byte
	n[4] = byte(counter)
	n[5] = byte(counter >> 8)
	n[6] = byte(counter >> 16)
	n[7] = byte(counter >> 24)
	n[8] = byte(counter >> 32)
	n[9] = byte(counter >> 40)
	n[10] = byte(counter >> 48)
	n[11] = byte(counter >> 56)
	return n
}

// Seal encrypts plaintext for a path. dst may overlap plaintext exactly
// (in-place encryption); the sealed ciphertext (plaintext+tag) is returned.
func (e *Epoch) Seal(pathID byte, counter uint64, dst, plaintext, ad []byte) []byte {
	n := nonceFor(counter)
	return e.send[pathID].Seal(dst, n[:], plaintext, ad)
}

// Open authenticates and decrypts ciphertext for a path. It does NOT check
// the replay window; call CheckReplay after Open succeeds.
func (e *Epoch) Open(pathID byte, counter uint64, dst, ciphertext, ad []byte) ([]byte, error) {
	n := nonceFor(counter)
	pt, err := e.recv[pathID].Open(dst, n[:], ciphertext, ad)
	if err != nil {
		return nil, errAuth
	}
	return pt, nil
}

// CheckReplay marks counter as seen on a path, reporting whether it was
// fresh. Call only after Open succeeded (authenticated packets only).
func (e *Epoch) CheckReplay(pathID byte, counter uint64) bool {
	w := &e.win[pathID]
	w.mu.Lock()
	ok := w.w.Check(counter)
	w.mu.Unlock()
	return ok
}

// --- client handshake ---

// ClientHandshake is an in-progress initiator handshake.
type ClientHandshake struct {
	hs   *noise.HandshakeState
	seed [32]byte
	rxID uint32
}

// NewClientHandshake starts a handshake toward the server's static key.
// rxID is the session index this client chose for receiving.
func NewClientHandshake(priv, serverPub, psk keys.Key, rxID uint32) (*ClientHandshake, error) {
	cfg := newConfig(priv, psk, true)
	cfg.PeerStatic = serverPub[:]
	hs, err := noise.NewHandshakeState(cfg)
	if err != nil {
		return nil, err
	}
	ch := &ClientHandshake{hs: hs, rxID: rxID}
	if _, err := rand.Read(ch.seed[:]); err != nil {
		return nil, err
	}
	return ch, nil
}

// InitMessage produces the Noise message for HandshakeInit (placed after
// the outer header, whose session_id must be the client's rxID).
func (h *ClientHandshake) InitMessage(timestampNs uint64) ([]byte, error) {
	p := wire.InitPayload{Version: wire.ProtocolVersion, Seed: h.seed, TimestampNs: timestampNs}
	var buf [wire.InitPayloadSize]byte
	p.Marshal(buf[:])
	msg, _, _, err := h.hs.WriteMessage(nil, buf[:])
	return msg, err
}

// Finish consumes the HandshakeResp Noise message and returns the epoch.
func (h *ClientHandshake) Finish(respMsg []byte) (*Epoch, error) {
	payload, _, _, err := h.hs.ReadMessage(nil, respMsg)
	if err != nil {
		return nil, fmt.Errorf("handshake response: %w", errAuth)
	}
	rp, err := wire.ParseRespPayload(payload)
	if err != nil {
		return nil, err
	}
	return newEpoch(h.seed, rp.Seed, h.hs.ChannelBinding(), rp.SessionID, h.rxID, true)
}

// --- server handshake ---

// ServerHandshake is a consumed HandshakeInit awaiting a response.
type ServerHandshake struct {
	hs      *noise.HandshakeState
	payload wire.InitPayload
	peer    keys.Key
}

// ConsumeInit authenticates a HandshakeInit Noise message. The peer's PSK
// is not needed at this stage (psk2 applies to message 2); call Respond
// with the PSK configured for the identified peer.
func ConsumeInit(serverPriv keys.Key, msg []byte) (*ServerHandshake, error) {
	var zeroPSK keys.Key
	hs, err := noise.NewHandshakeState(newConfig(serverPriv, zeroPSK, false))
	if err != nil {
		return nil, err
	}
	payload, _, _, err := hs.ReadMessage(nil, msg)
	if err != nil {
		return nil, fmt.Errorf("handshake init: %w", errAuth)
	}
	p, err := wire.ParseInitPayload(payload)
	if err != nil {
		return nil, err
	}
	if p.Version != wire.ProtocolVersion {
		return nil, fmt.Errorf("noiseio: peer protocol version %d, want %d", p.Version, wire.ProtocolVersion)
	}
	sh := &ServerHandshake{hs: hs, payload: p}
	copy(sh.peer[:], hs.PeerStatic())
	return sh, nil
}

// PeerStatic returns the initiator's authenticated static public key.
func (h *ServerHandshake) PeerStatic() keys.Key { return h.peer }

// TimestampNs returns the initiator's handshake timestamp (replay check).
func (h *ServerHandshake) TimestampNs() uint64 { return h.payload.TimestampNs }

// Respond finalizes the handshake with the peer's PSK. rxID is the index
// the server assigned to this epoch; txID is the initiator's index taken
// from the HandshakeInit outer header. It returns the Noise message for
// HandshakeResp and the completed epoch.
func (h *ServerHandshake) Respond(psk keys.Key, rxID, txID uint32) ([]byte, *Epoch, error) {
	if !psk.IsZero() {
		if err := h.hs.SetPresharedKey(psk[:]); err != nil {
			return nil, nil, err
		}
	}
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, nil, err
	}
	rp := wire.RespPayload{Seed: seed, SessionID: rxID}
	var buf [wire.RespPayloadSize]byte
	rp.Marshal(buf[:])
	msg, _, _, err := h.hs.WriteMessage(nil, buf[:])
	if err != nil {
		return nil, nil, err
	}
	epoch, err := newEpoch(h.payload.Seed, seed, h.hs.ChannelBinding(), txID, rxID, false)
	if err != nil {
		return nil, nil, err
	}
	return msg, epoch, nil
}
