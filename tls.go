// TLS-record wire shaping for the TCP carrier.
//
// obfs.go gives the UDP carrier a QUIC disguise, which is the right shape for UDP. Over TCP
// that disguise is nonsense — QUIC is a UDP protocol, so a TCP stream carrying QUIC-short-header
// bytes matches nothing a DPI expects and the framing itself (a bare 2-byte length prefix) is a
// small signature of its own. The natural cover for a long-lived TCP flow to port 443 is TLS,
// and that is what this file provides.
//
// When transport is tcp and obfs is quic, the carrier does two things:
//
//  1. It opens the connection with a synthetic TLS 1.3 handshake — a real ClientHello (SNI +
//     h3/http ALPN, the same builder the QUIC cover uses) from the dialer, and a ServerHello
//     plus ChangeCipherSpec from the accepter. A record-level DPI watching the stream from its
//     first byte sees an ordinary TLS connection to an ordinary host getting established.
//
//  2. It frames every sealed tunnel datagram as a TLS 1.3 application-data record
//     ([0x17][0x03 0x03][len][ciphertext]). TLS application data is encrypted, so a
//     high-entropy payload is exactly what an inspector expects to see there — the same
//     "uniform random is the optimum against content inspection" property the whole project
//     rests on, now wearing the framing a DPI will not think twice about.
//
// Nothing here completes a real handshake or derives TLS keys: the tunnel's own AEAD already
// protects the payload. The records exist to be looked at, exactly like the QUIC Initials do.
// Same honest caveat as section 10 of the README — this removes cheap signatures, it is not a
// proof of undetectability, and a classifier that actively completes TLS would find the
// handshake does not go anywhere.
package main

import (
	"crypto/rand"
)

const (
	tlsRecHandshake      = 0x16
	tlsRecChangeCipher   = 0x14
	tlsRecAppData        = 0x17
	tlsRecordHeaderLen   = 5
	tlsRecordReadCeiling = 1<<14 + 2048 // a length past this on the wire means the stream desynced
)

// tlsRecord frames payload as one TLS record of the given content type and legacy version.
func tlsRecord(dst []byte, typ byte, version uint16, payload []byte) []byte {
	dst = append(dst, typ, byte(version>>8), byte(version))
	dst = append(dst, byte(len(payload)>>8), byte(len(payload)))
	return append(dst, payload...)
}

// buildTLSClientHelloRecord wraps a real TLS 1.3 ClientHello (with the given SNI) in a
// handshake record, using the legacy record version 0x0301 that real clients send.
func buildTLSClientHelloRecord(sni string) []byte {
	return tlsRecord(nil, tlsRecHandshake, 0x0301, buildClientHello(sni))
}

// buildTLSServerFlight is what the accepting side sends back: a ServerHello handshake record
// followed by a ChangeCipherSpec record, the way a TLS 1.3 server begins its response.
func buildTLSServerFlight() []byte {
	out := tlsRecord(nil, tlsRecHandshake, 0x0303, buildServerHello())
	return tlsRecord(out, tlsRecChangeCipher, 0x0303, []byte{0x01})
}

// buildServerHello assembles a structurally valid TLS 1.3 ServerHello handshake message. Like
// the ClientHello builder in quicinit.go it exists to parse cleanly, nothing more.
func buildServerHello() []byte {
	var body []byte
	body = append(body, 0x03, 0x03) // legacy_version TLS 1.2
	rnd := make([]byte, 32)
	rand.Read(rnd)
	body = append(body, rnd...)
	// legacy_session_id_echo: a 32-byte value, as a client that offered compatibility mode
	// would have sent and the server echoes.
	sid := make([]byte, 32)
	rand.Read(sid)
	body = append(body, 0x20)
	body = append(body, sid...)
	body = append(body, 0x13, 0x01) // cipher_suite TLS_AES_128_GCM_SHA256
	body = append(body, 0x00)       // legacy_compression_method: null

	var ext []byte
	// supported_versions (0x002b): selected TLS 1.3 (0x0304)
	ext = append(ext, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04)
	// key_share (0x0033): x25519 (0x001d) with a 32-byte public value
	pub := make([]byte, 32)
	rand.Read(pub)
	ext = append(ext, 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20)
	ext = append(ext, pub...)
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)

	// Handshake header: type 0x02 (server_hello), 24-bit length.
	out := []byte{0x02, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(out, body...)
}
