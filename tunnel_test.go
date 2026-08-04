package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestZeroDisablesViaJSON(t *testing.T) {
	// An explicit 0 must be preserved (feature disabled); an omitted field must default.
	var c1 Config
	if err := json.Unmarshal([]byte(`{"pad_max":0,"keepalive":0}`), &c1); err != nil {
		t.Fatal(err)
	}
	c1.applyDefaults()
	if c1.PadMax == nil || *c1.PadMax != 0 {
		t.Fatalf("explicit pad_max:0 not preserved: %v", c1.PadMax)
	}
	if c1.Keepalive == nil || *c1.Keepalive != 0 {
		t.Fatalf("explicit keepalive:0 not preserved: %v", c1.Keepalive)
	}

	var c2 Config
	if err := json.Unmarshal([]byte(`{}`), &c2); err != nil {
		t.Fatal(err)
	}
	c2.applyDefaults()
	if c2.PadMax == nil || *c2.PadMax != 64 {
		t.Fatalf("omitted pad_max should default to 64: %v", c2.PadMax)
	}
	if c2.Keepalive == nil || *c2.Keepalive != 25 {
		t.Fatalf("omitted keepalive should default to 25: %v", c2.Keepalive)
	}
}

func pair(rekey uint64, pad int) (*Tunnel, *Tunnel) {
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = byte(i)
	}
	a := newTunnel(&Config{Role: "a", RekeyInterval: rekey, PadMax: &pad}, psk)
	b := newTunnel(&Config{Role: "b", RekeyInterval: rekey, PadMax: &pad}, psk)
	return a, b
}

func TestRoundTripBothDirections(t *testing.T) {
	a, b := pair(0, 64)
	msg := []byte("hello — a->b packet 12345")
	got, ok := b.open(a.seal(msg))
	if !ok || !bytes.Equal(got, msg) {
		t.Fatalf("a->b failed: ok=%v got=%q", ok, got)
	}
	msg2 := []byte("reply b->a 67890")
	got2, ok2 := a.open(b.seal(msg2))
	if !ok2 || !bytes.Equal(got2, msg2) {
		t.Fatalf("b->a failed: ok=%v got=%q", ok2, got2)
	}
}

func TestCiphertextLooksRandom(t *testing.T) {
	a, _ := pair(0, 0)
	// Same plaintext twice: outputs must differ (random nonce) and share no fixed prefix.
	p := bytes.Repeat([]byte{0x41}, 200)
	c1 := a.seal(p)
	c2 := a.seal(p)
	if bytes.Equal(c1, c2) {
		t.Fatal("two packets with identical plaintext produced identical output (fixed nonce?)")
	}
	if bytes.Equal(c1[:12], c2[:12]) {
		t.Fatal("nonces are identical")
	}
	// The all-0x41 plaintext pattern must not appear in the ciphertext.
	if bytes.Contains(c1[12:], bytes.Repeat([]byte{0x41}, 16)) {
		t.Fatal("plaintext pattern leaked into ciphertext")
	}
}

func TestReplayRejected(t *testing.T) {
	a, b := pair(0, 0)
	pkt := a.seal([]byte("once"))
	if _, ok := b.open(pkt); !ok {
		t.Fatal("first packet must be accepted")
	}
	if _, ok := b.open(pkt); ok {
		t.Fatal("replayed packet must be rejected")
	}
	if b.replayDrop != 1 {
		t.Fatalf("replay counter wrong: %d", b.replayDrop)
	}
}

func TestWrongKeyRejected(t *testing.T) {
	a, _ := pair(0, 0)
	other := make([]byte, 32) // different key (all zeros)
	bad := newTunnel(&Config{Role: "b"}, other)
	if _, ok := bad.open(a.seal([]byte("secret"))); ok {
		t.Fatal("packet with wrong key must not open")
	}
	if bad.authFail != 1 {
		t.Fatalf("auth_fail should be 1: %d", bad.authFail)
	}
}

func TestTamperRejected(t *testing.T) {
	a, b := pair(0, 0)
	pkt := a.seal([]byte("integrity"))
	pkt[len(pkt)-1] ^= 0xff // tamper the tag
	if _, ok := b.open(pkt); ok {
		t.Fatal("tampered packet must not be accepted")
	}
}

func TestKeepaliveEmpty(t *testing.T) {
	a, b := pair(0, 64)
	got, ok := b.open(a.seal(nil)) // keepalive
	if !ok {
		t.Fatal("keepalive packet must authenticate")
	}
	if len(got) != 0 {
		t.Fatalf("keepalive must have empty payload, got: %d bytes", len(got))
	}
}

func TestEpochSkewTolerance(t *testing.T) {
	a, b := pair(3600, 0)
	// Push the receiver one epoch ahead; it must still open via the adjacent epoch.
	pkt := a.seal([]byte("across epoch"))
	skewed := b.epochNow() + 1
	b.rememberEpoch(skewed, b.aead(false, skewed))
	if _, ok := b.open(pkt); !ok {
		t.Fatal("must still open with a one-epoch skew")
	}
}

func TestVariousSizes(t *testing.T) {
	a, b := pair(0, 100)
	for _, n := range []int{0, 1, 20, 576, 1300, 1400} {
		msg := bytes.Repeat([]byte{byte(n)}, n)
		got, ok := b.open(a.seal(msg))
		if !ok || !bytes.Equal(got, msg) {
			t.Fatalf("size %d failed: ok=%v len=%d", n, ok, len(got))
		}
	}
}

func TestReplayWindowReordering(t *testing.T) {
	w := newReplayWindow(64)
	// Accept out-of-order within the window.
	if !w.check(100) {
		t.Fatal("100 must be accepted")
	}
	if !w.check(98) {
		t.Fatal("98 (out of order) must be accepted")
	}
	if w.check(98) {
		t.Fatal("duplicate 98 must be rejected")
	}
	if !w.check(101) {
		t.Fatal("101 must be accepted")
	}
	// Too old: outside the window.
	if w.check(1) {
		t.Fatal("1 (very old) must be rejected")
	}
}
