package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func obfsPair(shape bool) (*Tunnel, *Tunnel) {
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = byte(i * 7)
	}
	pad := 64
	mk := func(role string) *Tunnel {
		c := &Config{Role: role, PadMax: &pad, Obfs: "quic", Shape: &shape}
		return newTunnel(c, psk)
	}
	return mk("a"), mk("b")
}

func TestObfsRoundTripBothDirections(t *testing.T) {
	a, b := obfsPair(true)
	msg := []byte("obfuscated payload — a to b")
	got, ok := b.open(a.seal(msg))
	if !ok || !bytes.Equal(got, msg) {
		t.Fatalf("a->b failed: ok=%v got=%q", ok, got)
	}
	msg2 := []byte("and back again")
	got2, ok2 := a.open(b.seal(msg2))
	if !ok2 || !bytes.Equal(got2, msg2) {
		t.Fatalf("b->a failed: ok=%v got=%q", ok2, got2)
	}
}

func TestObfsManyPacketsAllOpen(t *testing.T) {
	// Header protection derives its mask from the ciphertext, so a mistake there would
	// show up only on some packets. Push enough through to catch that.
	a, b := obfsPair(true)
	for i := 0; i < 2000; i++ {
		msg := bytes.Repeat([]byte{byte(i)}, i%900)
		got, ok := b.open(a.seal(msg))
		if !ok {
			t.Fatalf("packet %d failed to open", i)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("packet %d payload mismatch: got %d bytes want %d", i, len(got), len(msg))
		}
	}
}

func TestObfsLooksLikeQUICShortHeader(t *testing.T) {
	a, _ := obfsPair(false)
	for i := 0; i < 200; i++ {
		p := a.seal([]byte("x"))
		// Bit 7 clear = short header form; bit 6 set = the QUIC v1 fixed bit. A parser
		// that rejects either would classify this as "not QUIC", which is the whole
		// thing we are trying to avoid. Neither bit is header-protected.
		if p[0]&0x80 != 0 {
			t.Fatalf("packet %d: long-header form bit set (0x%02x)", i, p[0])
		}
		if p[0]&0x40 == 0 {
			t.Fatalf("packet %d: QUIC fixed bit clear (0x%02x)", i, p[0])
		}
	}
}

func TestObfsConnectionIDStable(t *testing.T) {
	a, _ := obfsPair(false)
	first := append([]byte(nil), a.seal([]byte("one"))[1:1+obfsCIDLen]...)
	for i := 0; i < 100; i++ {
		got := a.seal([]byte("more"))[1 : 1+obfsCIDLen]
		if !bytes.Equal(first, got) {
			t.Fatalf("connection ID changed at packet %d: %x -> %x", i, first, got)
		}
	}
}

func TestObfsPacketNumberIsNotVisiblySequential(t *testing.T) {
	// The packet number increments internally, but header protection must make the bytes
	// on the wire look random. An exposed monotonic counter is its own fingerprint —
	// arguably a louder one than the uniform-random payload this layer set out to hide.
	a, _ := obfsPair(false)
	const n = 300
	seq := 0
	var prev uint32
	for i := 0; i < n; i++ {
		p := a.seal([]byte("payload"))
		pn := binary.BigEndian.Uint32(p[obfsHeaderLen-4:])
		if i > 0 && pn == prev+1 {
			seq++
		}
		prev = pn
	}
	// With a good mask, consecutive-looking values should be vanishingly rare.
	if seq > n/20 {
		t.Fatalf("packet number field looks sequential in %d/%d packets — header protection is not working", seq, n)
	}
}

func TestObfsSizeShapingHitsBuckets(t *testing.T) {
	a, _ := obfsPair(true)
	for _, plainLen := range []int{0, 1, 20, 40, 100, 300, 700, 1000} {
		p := a.seal(bytes.Repeat([]byte{1}, plainLen))
		hit := false
		for _, b := range obfsBuckets {
			if len(p) == b {
				hit = true
				break
			}
		}
		// Past the largest bucket nothing is padded — that is where the bytes are.
		if !hit && len(p) < obfsBuckets[len(obfsBuckets)-1] {
			t.Fatalf("plain=%d produced %d bytes, not on a bucket %v", plainLen, len(p), obfsBuckets)
		}
	}
}

func TestObfsShapingOffLeavesSizesAlone(t *testing.T) {
	a, _ := obfsPair(false)
	// Without shaping the size should track the payload, not snap to a bucket.
	small := len(a.seal(bytes.Repeat([]byte{1}, 10)))
	big := len(a.seal(bytes.Repeat([]byte{1}, 900)))
	if big <= small {
		t.Fatalf("expected larger payload to produce a larger datagram: %d vs %d", small, big)
	}
}

func TestObfsDisabledKeepsLegacyWireFormat(t *testing.T) {
	// Rollback safety: with obfs off the output must stay byte-compatible with peers
	// running the pre-obfs build, which means a bare 12-byte random nonce up front.
	psk := make([]byte, 32)
	pad := 0
	a := newTunnel(&Config{Role: "a", PadMax: &pad}, psk)
	b := newTunnel(&Config{Role: "b", PadMax: &pad}, psk)
	if a.obfs != nil {
		t.Fatal("obfs must default to disabled")
	}
	p := a.seal([]byte("legacy"))
	if len(p) != 12+10+len("legacy")+16 {
		t.Fatalf("unexpected legacy datagram size: %d", len(p))
	}
	got, ok := b.open(p)
	if !ok || string(got) != "legacy" {
		t.Fatalf("legacy round trip failed: ok=%v got=%q", ok, got)
	}
}

func TestObfsTamperRejected(t *testing.T) {
	a, b := obfsPair(true)
	p := a.seal([]byte("integrity"))
	p[len(p)-1] ^= 0xff
	if _, ok := b.open(p); ok {
		t.Fatal("tampered packet must not be accepted")
	}
}

func TestObfsReplayRejected(t *testing.T) {
	a, b := obfsPair(true)
	p := a.seal([]byte("once"))
	if _, ok := b.open(p); !ok {
		t.Fatal("first packet must be accepted")
	}
	if _, ok := b.open(p); ok {
		t.Fatal("replayed packet must be rejected")
	}
}

func TestObfsWrongKeyRejected(t *testing.T) {
	a, _ := obfsPair(true)
	other := make([]byte, 32)
	shape := true
	bad := newTunnel(&Config{Role: "b", Obfs: "quic", Shape: &shape}, other)
	if _, ok := bad.open(a.seal([]byte("secret"))); ok {
		t.Fatal("packet with wrong key must not open")
	}
}

func TestObfsKeepaliveEmpty(t *testing.T) {
	a, b := obfsPair(true)
	got, ok := b.open(a.seal(nil))
	if !ok {
		t.Fatal("keepalive must authenticate")
	}
	if len(got) != 0 {
		t.Fatalf("keepalive must carry no payload, got %d bytes", len(got))
	}
}

func TestObfsCIDRotatesOnPacketNumberWrap(t *testing.T) {
	// A wrapped packet number would otherwise reissue nonces under a static key.
	a, _ := obfsPair(false)
	before := append([]byte(nil), a.obfs.cid.Load()[:]...)
	a.obfs.pn.Store(^uint32(0)) // next Add wraps to 0
	a.seal([]byte("wrap"))
	after := a.obfs.cid.Load()[:]
	if bytes.Equal(before, after) {
		t.Fatal("connection ID must rotate when the packet number wraps")
	}
}
