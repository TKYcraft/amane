package noiseio

import (
	"bytes"
	"testing"

	"github.com/TKYcraft/amane/internal/keys"
)

func handshakePair(t *testing.T, psk keys.Key) (client, server *Epoch) {
	t.Helper()
	cPriv, _ := keys.GeneratePrivateKey()
	sPriv, _ := keys.GeneratePrivateKey()
	sPub := keys.PublicKey(sPriv)

	const clientIdx, serverIdx = 111, 222

	ch, err := NewClientHandshake(cPriv, sPub, psk, clientIdx)
	if err != nil {
		t.Fatal(err)
	}
	msg1, err := ch.InitMessage(1234567890)
	if err != nil {
		t.Fatal(err)
	}
	sh, err := ConsumeInit(sPriv, msg1)
	if err != nil {
		t.Fatal(err)
	}
	if sh.PeerStatic() != keys.PublicKey(cPriv) {
		t.Fatal("peer static mismatch")
	}
	if sh.TimestampNs() != 1234567890 {
		t.Fatal("timestamp mismatch")
	}
	msg2, sEpoch, err := sh.Respond(psk, serverIdx, clientIdx)
	if err != nil {
		t.Fatal(err)
	}
	cEpoch, err := ch.Finish(msg2)
	if err != nil {
		t.Fatal(err)
	}
	if cEpoch.TxSessionID() != serverIdx || cEpoch.RxSessionID() != clientIdx {
		t.Fatalf("client ids: tx=%d rx=%d", cEpoch.TxSessionID(), cEpoch.RxSessionID())
	}
	if sEpoch.TxSessionID() != clientIdx || sEpoch.RxSessionID() != serverIdx {
		t.Fatalf("server ids: tx=%d rx=%d", sEpoch.TxSessionID(), sEpoch.RxSessionID())
	}
	return cEpoch, sEpoch
}

func testTraffic(t *testing.T, c, s *Epoch) {
	t.Helper()
	for pathID := byte(0); pathID < 3; pathID++ {
		msg := []byte("packet on path " + string('0'+pathID))
		ad := []byte("outer header bytes")
		ctr := c.NextCounter(pathID)
		ct := c.Seal(pathID, ctr, nil, msg, ad)
		pt, err := s.Open(pathID, ctr, nil, ct, ad)
		if err != nil {
			t.Fatalf("path %d: %v", pathID, err)
		}
		if !bytes.Equal(pt, msg) {
			t.Fatalf("path %d: plaintext mismatch", pathID)
		}
		if !s.CheckReplay(pathID, ctr) {
			t.Fatal("fresh counter rejected")
		}
		if s.CheckReplay(pathID, ctr) {
			t.Fatal("replayed counter accepted")
		}
		// reverse direction
		ctr = s.NextCounter(pathID)
		ct = s.Seal(pathID, ctr, nil, msg, ad)
		if _, err := c.Open(pathID, ctr, nil, ct, ad); err != nil {
			t.Fatalf("reverse path %d: %v", pathID, err)
		}
	}
}

func TestHandshakeZeroPSK(t *testing.T) {
	var psk keys.Key
	c, s := handshakePair(t, psk)
	testTraffic(t, c, s)
}

func TestHandshakeWithPSK(t *testing.T) {
	psk, _ := keys.GeneratePrivateKey()
	c, s := handshakePair(t, psk)
	testTraffic(t, c, s)
}

func TestPSKMismatchFails(t *testing.T) {
	cPriv, _ := keys.GeneratePrivateKey()
	sPriv, _ := keys.GeneratePrivateKey()
	sPub := keys.PublicKey(sPriv)
	pskA, _ := keys.GeneratePrivateKey()
	pskB, _ := keys.GeneratePrivateKey()

	ch, _ := NewClientHandshake(cPriv, sPub, pskA, 1)
	msg1, _ := ch.InitMessage(1)
	sh, err := ConsumeInit(sPriv, msg1)
	if err != nil {
		t.Fatal(err) // psk2: message 1 must still authenticate
	}
	msg2, _, err := sh.Respond(pskB, 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ch.Finish(msg2); err == nil {
		t.Fatal("handshake succeeded despite PSK mismatch")
	}
}

func TestWrongServerKeyFails(t *testing.T) {
	cPriv, _ := keys.GeneratePrivateKey()
	sPriv, _ := keys.GeneratePrivateKey()
	otherPriv, _ := keys.GeneratePrivateKey()
	var psk keys.Key

	ch, _ := NewClientHandshake(cPriv, keys.PublicKey(otherPriv), psk, 1)
	msg1, _ := ch.InitMessage(1)
	if _, err := ConsumeInit(sPriv, msg1); err == nil {
		t.Fatal("server accepted handshake encrypted to a different static key")
	}
}

func TestTamperedDataFails(t *testing.T) {
	var psk keys.Key
	c, s := handshakePair(t, psk)
	ad := []byte("hdr")
	ctr := c.NextCounter(0)
	ct := c.Seal(0, ctr, nil, []byte("data"), ad)
	ct[0] ^= 1
	if _, err := s.Open(0, ctr, nil, ct, ad); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
	// wrong path key
	ct = c.Seal(1, c.NextCounter(1), nil, []byte("data"), ad)
	if _, err := s.Open(2, 1, nil, ct, ad); err == nil {
		t.Fatal("cross-path ciphertext accepted")
	}
}
