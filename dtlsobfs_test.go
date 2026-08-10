package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func dtlsPair(shape bool) (*Tunnel, *Tunnel) {
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = byte(i*11 + 3)
	}
	pad := 64
	mk := func(role string) *Tunnel {
		return newTunnel(&Config{Role: role, PadMax: &pad, Obfs: obfsDTLS, Shape: &shape}, psk)
	}
	return mk("a"), mk("b")
}

func TestDTLSRoundTripBothDirections(t *testing.T) {
	a, b := dtlsPair(true)
	msg := []byte("dtls-shaped payload — a to b")
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

// The whole point of the mode is that the datagram parses as a DTLS 1.2 application_data
// record. If any of these fields is wrong, a DPI's DTLS parser rejects it and the disguise
// is worse than none at all — a malformed record is more conspicuous than random bytes.
func TestDTLSLooksLikeADTLSRecord(t *testing.T) {
	a, _ := dtlsPair(true)
	for i := 0; i < 64; i++ {
		pkt := a.seal([]byte("payload"))
		if len(pkt) < dtlsHeaderLen {
			t.Fatalf("datagram shorter than a record header: %d", len(pkt))
		}
		if pkt[0] != dtlsTypeAppData {
			t.Fatalf("content type = 0x%02x, want application_data 0x%02x", pkt[0], dtlsTypeAppData)
		}
		if pkt[1] != dtlsVersion[0] || pkt[2] != dtlsVersion[1] {
			t.Fatalf("version = %02x%02x, want DTLS 1.2 fefd", pkt[1], pkt[2])
		}
		if got := int(binary.BigEndian.Uint16(pkt[11:13])); got != len(pkt)-dtlsHeaderLen {
			t.Fatalf("record length field = %d, want %d", got, len(pkt)-dtlsHeaderLen)
		}
	}
}

// The sequence number is the nonce's uniqueness guarantee, so it must actually advance —
// and it must be visible in the clear, because DTLS does not protect its record header.
func TestDTLSSequenceAdvances(t *testing.T) {
	a, _ := dtlsPair(false)
	seqOf := func(pkt []byte) uint64 {
		var v uint64
		for _, b := range pkt[5:11] {
			v = v<<8 | uint64(b)
		}
		return v
	}
	prev := seqOf(a.seal([]byte("x")))
	for i := 0; i < 200; i++ {
		cur := seqOf(a.seal([]byte("x")))
		if cur != prev+1 {
			t.Fatalf("sequence jumped from %d to %d", prev, cur)
		}
		prev = cur
	}
}

// Both ends derive the nonce salt from the PSK, so a peer holding a different key must not
// be able to open the traffic — the salt is obfuscation, the AEAD is the security boundary.
func TestDTLSWrongKeyRejected(t *testing.T) {
	a, _ := dtlsPair(true)
	other := make([]byte, 32)
	shape := true
	bad := newTunnel(&Config{Role: "b", Obfs: obfsDTLS, Shape: &shape}, other)
	if _, ok := bad.open(a.seal([]byte("secret"))); ok {
		t.Fatal("a tunnel with the wrong key opened the packet")
	}
}

// The two disguises are different wire formats; a packet sealed under one must not be
// mistaken for cover traffic by the other's one-byte test.
func TestDTLSCoverDetectionDoesNotCatchData(t *testing.T) {
	a, _ := dtlsPair(true)
	for i := 0; i < 256; i++ {
		if pkt := a.seal([]byte("payload")); dtlsIsCover(pkt) {
			t.Fatal("a data record was classified as handshake cover")
		}
	}
	hello := buildDTLSClientHello("www.example.org")
	if hello == nil {
		t.Fatal("building the ClientHello failed")
	}
	rec := dtlsHandshakeRecord(1, 0, 0, 42, hello)
	if !dtlsIsCover(rec) {
		t.Fatal("a handshake record was not classified as cover")
	}
	// The record's length field has to agree with the datagram here too.
	if got := int(binary.BigEndian.Uint16(rec[11:13])); got != len(rec)-dtlsHeaderLen {
		t.Fatalf("cover record length field = %d, want %d", got, len(rec)-dtlsHeaderLen)
	}
	// The SNI has to survive into the ClientHello, since that is what a DPI reads.
	if !bytes.Contains(rec, []byte("www.example.org")) {
		t.Fatal("the server name is not present in the ClientHello")
	}
}
