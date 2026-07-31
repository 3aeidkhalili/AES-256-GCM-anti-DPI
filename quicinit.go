// Synthetic QUIC handshake — gives the carrier flow a beginning that looks like a real
// QUIC connection, not just a stream of 1-RTT packets.
//
// obfs.go makes every datagram parse as a QUIC short-header packet, which is enough for a
// stateless classifier. It is not enough for a stateful one: a connection whose handshake
// was never observed is anomalous, and Wireshark says so out loud —
// "Unknown QUIC connection. Missing Initial Packet or migrated connection?". A censor's DPI
// watches the flow from its first packet, so that gap is exactly what it would key on.
//
// So at flow start we emit a real Initial packet: long header, version 1, and a CRYPTO frame
// carrying a structurally valid TLS 1.3 ClientHello with an SNI and an h3 ALPN. It is
// encrypted with the standard Initial keys from RFC 9001 — which are derived from the
// (public) destination connection ID, so any observer can and will decrypt it. That is the
// point: a DPI that looks inside finds an ordinary ClientHello for an ordinary host, rather
// than something it cannot parse.
//
// These packets carry no tunnel data. The receiver tells them apart by the header form bit
// (long = handshake cover, short = real traffic) and drops them after looking at that one bit.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
)

// quicInitialSalt is the version-1 salt fixed by RFC 9001 §5.2. Every QUIC v1 endpoint on
// the internet derives its Initial keys from this exact value.
var quicInitialSalt = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
	0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
}

func hkdfExtract(salt, ikm []byte) []byte {
	m := hmac.New(sha256.New, salt)
	m.Write(ikm)
	return m.Sum(nil)
}

// hkdfExpandLabel is the TLS 1.3 labelled expansion (RFC 8446 §7.1) that QUIC key
// derivation is defined in terms of.
func hkdfExpandLabel(secret []byte, label string, length int) []byte {
	full := "tls13 " + label
	info := make([]byte, 0, 4+len(full))
	info = append(info, byte(length>>8), byte(length))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0) // zero-length context

	var out, t []byte
	for i := 1; len(out) < length; i++ {
		h := hmac.New(sha256.New, secret)
		h.Write(t)
		h.Write(info)
		h.Write([]byte{byte(i)})
		t = h.Sum(nil)
		out = append(out, t...)
	}
	return out[:length]
}

type quicInitialKeys struct {
	aead cipher.AEAD
	iv   []byte
	hp   cipher.Block
}

// initialKeys derives the client- or server-side Initial keys for a destination connection
// ID, exactly as any QUIC v1 stack would.
func initialKeys(dcid []byte, client bool) (*quicInitialKeys, error) {
	initial := hkdfExtract(quicInitialSalt, dcid)
	side := "server in"
	if client {
		side = "client in"
	}
	secret := hkdfExpandLabel(initial, side, 32)

	blk, err := aes.NewCipher(hkdfExpandLabel(secret, "quic key", 16))
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	hpBlk, err := aes.NewCipher(hkdfExpandLabel(secret, "quic hp", 16))
	if err != nil {
		return nil, err
	}
	return &quicInitialKeys{aead: aead, iv: hkdfExpandLabel(secret, "quic iv", 12), hp: hpBlk}, nil
}

// --- varint (RFC 9000 §16) ------------------------------------------------

func appendVarint(b []byte, v uint64) []byte {
	switch {
	case v < 1<<6:
		return append(b, byte(v))
	case v < 1<<14:
		return append(b, byte(v>>8)|0x40, byte(v))
	case v < 1<<30:
		return append(b, byte(v>>24)|0x80, byte(v>>16), byte(v>>8), byte(v))
	default:
		var t [8]byte
		binary.BigEndian.PutUint64(t[:], v)
		t[0] |= 0xc0
		return append(b, t[:]...)
	}
}

// --- TLS ClientHello ------------------------------------------------------

func appendU16Block(b []byte, body []byte) []byte {
	b = append(b, byte(len(body)>>8), byte(len(body)))
	return append(b, body...)
}

// buildClientHello assembles a TLS 1.3 ClientHello carrying the given server name. It is
// structurally valid and parses cleanly, which is all that matters here — nothing ever
// completes this handshake, it exists to be looked at.
func buildClientHello(sni string) []byte {
	var ext []byte

	// server_name (0x0000)
	var sniList []byte
	sniList = append(sniList, 0x00) // host_name
	sniList = appendU16Block(sniList, []byte(sni))
	ext = append(ext, 0x00, 0x00)
	ext = appendU16Block(ext, appendU16Block(nil, sniList))

	// supported_groups (0x000a): x25519, secp256r1
	ext = append(ext, 0x00, 0x0a)
	ext = appendU16Block(ext, appendU16Block(nil, []byte{0x00, 0x1d, 0x00, 0x17}))

	// ALPN (0x0010): h3 — what every browser offers over QUIC
	var alpn []byte
	alpn = append(alpn, 0x02, 'h', '3')
	ext = append(ext, 0x00, 0x10)
	ext = appendU16Block(ext, appendU16Block(nil, alpn))

	// supported_versions (0x002b): TLS 1.3 only
	ext = append(ext, 0x00, 0x2b)
	ext = appendU16Block(ext, append([]byte{0x02}, 0x03, 0x04))

	// key_share (0x0033): x25519 with a random public value
	pub := make([]byte, 32)
	rand.Read(pub)
	var ks []byte
	ks = append(ks, 0x00, 0x1d)
	ks = appendU16Block(ks, pub)
	ext = append(ext, 0x00, 0x33)
	ext = appendU16Block(ext, appendU16Block(nil, ks))

	// quic_transport_parameters (0x0039): a couple of ordinary-looking values
	var tp []byte
	tp = appendVarint(tp, 0x04)  // initial_max_data
	tp = appendVarint(tp, 4)     // length
	tp = appendVarint(tp, 1<<20) //
	tp = appendVarint(tp, 0x09)  // initial_max_streams_uni
	tp = appendVarint(tp, 1)     //
	tp = appendVarint(tp, 3)     //
	ext = append(ext, 0x00, 0x39)
	ext = appendU16Block(ext, tp)

	var body []byte
	body = append(body, 0x03, 0x03) // legacy_version TLS 1.2
	rnd := make([]byte, 32)
	rand.Read(rnd)
	body = append(body, rnd...)
	body = append(body, 0x00) // legacy_session_id: empty
	// cipher_suites: the three TLS 1.3 suites, in the usual order
	body = appendU16Block(body, []byte{0x13, 0x01, 0x13, 0x02, 0x13, 0x03})
	body = append(body, 0x01, 0x00) // legacy_compression_methods: null
	body = appendU16Block(body, ext)

	// Handshake header: type 0x01, 24-bit length
	out := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(out, body...)
}

// --- Initial packet -------------------------------------------------------

// buildInitial produces a complete, correctly protected QUIC Initial packet carrying the
// given CRYPTO payload.
//
// keyCID and dcid are separate on purpose. RFC 9001 §5.2 derives Initial keys for *both*
// directions from the destination connection ID in the client's very first Initial, so the
// server's reply is encrypted under that same value even though the DCID it puts in its own
// header is the client's source connection ID. Deriving from the header's DCID instead
// produces a packet no QUIC stack — and no DPI — can decrypt, which defeats the entire
// purpose of sending it.
func buildInitial(keyCID, dcid, scid, crypto []byte, client bool) ([]byte, error) {
	keys, err := initialKeys(keyCID, client)
	if err != nil {
		return nil, err
	}

	// CRYPTO frame: type 0x06, offset 0, length, data.
	var payload []byte
	payload = append(payload, 0x06)
	payload = appendVarint(payload, 0)
	payload = appendVarint(payload, uint64(len(crypto)))
	payload = append(payload, crypto...)
	// Real Initials are padded to at least 1200 bytes for anti-amplification, and a short
	// one would stand out precisely because every genuine client pads.
	if n := 1200 - len(payload) - 40; n > 0 {
		payload = append(payload, make([]byte, n)...) // PADDING frames are zero bytes
	}

	const pnLen = 4
	var pn uint32
	var pnb [4]byte
	rand.Read(pnb[:])
	pn = binary.BigEndian.Uint32(pnb[:]) & 0xffff // keep it small, like a real first packet

	// Long header: 1 (form) 1 (fixed) 00 (Initial) 00 (reserved) 11 (pn len - 1)
	hdr := []byte{0xc0 | (pnLen - 1)}
	hdr = binary.BigEndian.AppendUint32(hdr, 1) // version 1
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, byte(len(scid)))
	hdr = append(hdr, scid...)
	hdr = appendVarint(hdr, 0) // token length: none
	hdr = appendVarint(hdr, uint64(pnLen+len(payload)+16))
	pnOffset := len(hdr)
	hdr = binary.BigEndian.AppendUint32(hdr, pn)

	// AEAD nonce: the IV xored with the packet number, right-aligned.
	nonce := make([]byte, len(keys.iv))
	copy(nonce, keys.iv)
	for i := 0; i < 4; i++ {
		nonce[len(nonce)-4+i] ^= byte(pn >> (8 * (3 - i)))
	}

	pkt := keys.aead.Seal(hdr, nonce, payload, hdr)

	// Header protection, sampling 16 bytes from 4 past the start of the packet number.
	sampleOff := pnOffset + 4
	if len(pkt) < sampleOff+16 {
		return nil, nil
	}
	var in, out [16]byte
	copy(in[:], pkt[sampleOff:sampleOff+16])
	keys.hp.Encrypt(out[:], in[:])
	pkt[0] ^= out[0] & 0x0f // long header: low 4 bits are protected
	for i := 0; i < 4; i++ {
		pkt[pnOffset+i] ^= out[1+i]
	}
	return pkt, nil
}

// quicIsLongHeader reports whether a datagram is one of the synthetic handshake packets
// rather than tunnel traffic. One bit, checked before anything expensive happens.
func quicIsLongHeader(pkt []byte) bool {
	return len(pkt) > 0 && pkt[0]&0x80 != 0
}

// quicParseLongCIDs pulls the connection IDs out of a long-header packet. They sit in the
// clear — header protection covers only the first byte's low bits and the packet number.
func quicParseLongCIDs(pkt []byte) (dcid, scid []byte, ok bool) {
	// 1 byte flags + 4 bytes version + 1 byte dcid length
	if len(pkt) < 7 {
		return nil, nil, false
	}
	p := 5
	dl := int(pkt[p])
	p++
	if dl > 20 || p+dl+1 > len(pkt) {
		return nil, nil, false
	}
	dcid = pkt[p : p+dl]
	p += dl
	sl := int(pkt[p])
	p++
	if sl > 20 || p+sl > len(pkt) {
		return nil, nil, false
	}
	return dcid, pkt[p : p+sl], true
}

// sendClientInitial emits the opening Initial for a freshly opened carrier flow and returns
// the source connection ID it advertised, which the peer echoes back as its destination.
// Errors are not fatal: this is cover traffic and the tunnel works without it.
func sendClientInitial(c carrier, sni string) ([]byte, error) {
	dcid := make([]byte, 8)
	scid := make([]byte, 8)
	if _, err := rand.Read(dcid); err != nil {
		return nil, err
	}
	if _, err := rand.Read(scid); err != nil {
		return nil, err
	}
	// The client picks the DCID, so it is both the header value and the key input.
	pkt, err := buildInitial(dcid, dcid, scid, buildClientHello(sni), true)
	if err != nil || pkt == nil {
		return scid, err
	}
	return scid, c.Send(pkt)
}

// replyServerInitial answers a client Initial the way a real server does: the response's
// destination connection ID is the one the client offered as its source. Two Initials with
// unrelated connection IDs would not correspond to any real handshake, which is exactly the
// kind of incoherence a stateful classifier is looking for.
func replyServerInitial(c carrier, clientPkt []byte) error {
	clientDCID, clientSCID, ok := quicParseLongCIDs(clientPkt)
	if !ok || len(clientSCID) == 0 || len(clientDCID) == 0 {
		return nil
	}
	scid := make([]byte, 8)
	if _, err := rand.Read(scid); err != nil {
		return err
	}
	// Header DCID is the client's source ID; the keys still come from the client's original
	// destination ID, per RFC 9001 §5.2.
	pkt, err := buildInitial(clientDCID, clientSCID, scid, nil, false)
	if err != nil || pkt == nil {
		return err
	}
	return c.Send(pkt)
}
