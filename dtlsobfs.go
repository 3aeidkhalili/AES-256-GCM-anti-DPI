// DTLS wire obfuscation — presents each carrier datagram as a DTLS 1.2 record.
//
// Why a second disguise exists at all. The QUIC disguise in obfs.go is the better one on a
// link that lets QUIC through: it is what most encrypted UDP on the internet now looks like.
// But measurement on two independent Iranian carriers (AS25184 Afranet, AS34918 Pishgaman)
// found QUIC *v1* long-header packets dropped outright in both directions — the same
// national rule on both networks, not an ISP quirk. A censor that already maintains a
// version blocklist for QUIC can extend it; obfs=quic2 sidesteps today's list, but a
// disguise that is not QUIC at all is the thing that survives the list growing.
//
// DTLS is the natural second choice, and the same measurement backs it: DTLS-shaped
// datagrams sustained the full offered rate on both carriers. It is also what a censor can
// least afford to block wholesale — every WebRTC call, and OpenVPN in its UDP mode, is DTLS.
//
// Wire format — a DTLS 1.2 application_data record, which is 13 bytes of header, exactly
// the size the QUIC short-header format already uses, so the framing costs nothing extra:
//
//	[1 type=0x17][2 version=0xfefd][2 epoch][6 sequence][2 length][ciphertext][16 tag]
//
// As in real DTLS with an AEAD cipher (RFC 6347 §4.1.2.1, RFC 5288), the nonce is a salt
// derived from the key material followed by the record's own epoch and sequence number, so
// the header doubles as nonce material rather than being prepended to a separate one. The
// header is left in the clear, because that is what a real DTLS record looks like: unlike
// QUIC there is no header protection to imitate.
package main

import (
	"crypto/rand"
	"encoding/binary"
	"sync"
	"sync/atomic"
)

const (
	dtlsHeaderLen = 13 // 1 type + 2 version + 2 epoch + 6 sequence + 2 length
	dtlsSaltLen   = 4  // implicit nonce prefix, derived from the PSK per direction

	dtlsTypeHandshake = 22 // synthetic handshake cover
	dtlsTypeAppData   = 23 // tunnel traffic
)

// dtlsVersion is DTLS 1.2 on the wire: the ones' complement encoding {254, 253}.
var dtlsVersion = [2]byte{0xfe, 0xfd}

// dtlsState carries everything the DTLS wire format needs that the QUIC one does not.
type dtlsState struct {
	// Implicit nonce prefix, one per direction, derived from the PSK. Both ends compute
	// the same value, so it never has to travel on the wire — which is exactly how TLS
	// and DTLS build record nonces.
	sendSalt [dtlsSaltLen]byte
	recvSalt [dtlsSaltLen]byte

	// epoch is random per process rather than starting at zero. Together with the random
	// starting sequence number it gives the nonce space per-process separation, so a
	// restart inside one rekey interval cannot reissue a (key, nonce) pair — the same
	// property the QUIC path gets from a fresh random connection ID.
	epoch atomic.Uint32 // low 16 bits are the wire value
	seq   atomic.Uint64 // low 48 bits are the wire value
	mu    sync.Mutex
}

func newDTLSState(psk []byte, sendDir, recvDir string) (*dtlsState, error) {
	d := &dtlsState{}
	copy(d.sendSalt[:], hkdf(psk, nil, []byte("aestun-v1 dtls salt "+sendDir), dtlsSaltLen))
	copy(d.recvSalt[:], hkdf(psk, nil, []byte("aestun-v1 dtls salt "+recvDir), dtlsSaltLen))
	var seed [8]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, err
	}
	d.epoch.Store(uint32(binary.BigEndian.Uint16(seed[0:2])))
	// Start well below the 48-bit ceiling so the counter has room to climb for the life
	// of the process without touching the wrap path.
	d.seq.Store(uint64(binary.BigEndian.Uint32(seed[2:6])))
	return d, nil
}

// nextRecordHeader writes the 13-byte DTLS record header and the nonce it encodes. The
// length field is filled in later by finishRecord, once the ciphertext length is known.
func (d *dtlsState) nextRecordHeader(hdr *[obfsHeaderLen]byte, nonce *[12]byte) {
	seq := d.seq.Add(1) & 0xffff_ffff_ffff
	if seq == 0 {
		// 2^48 packets on one epoch. Unreachable in practice, but a wrapped sequence
		// number would restart the nonce space, so move the epoch instead — which is
		// precisely what a real DTLS endpoint does when it rekeys.
		d.mu.Lock()
		if d.seq.Load()&0xffff_ffff_ffff == 0 {
			d.epoch.Add(1)
		}
		d.mu.Unlock()
	}
	epoch := uint16(d.epoch.Load())

	hdr[0] = dtlsTypeAppData
	hdr[1], hdr[2] = dtlsVersion[0], dtlsVersion[1]
	binary.BigEndian.PutUint16(hdr[3:5], epoch)
	putUint48(hdr[5:11], seq)
	// hdr[11:13] is the record length, written by finishRecord.

	// Nonce: implicit salt then the record's own epoch and sequence, as RFC 5288 builds it.
	copy(nonce[:dtlsSaltLen], d.sendSalt[:])
	binary.BigEndian.PutUint16(nonce[dtlsSaltLen:dtlsSaltLen+2], epoch)
	putUint48(nonce[dtlsSaltLen+2:], seq)
}

// finishRecord fills in the record's length field once the datagram is complete. A DTLS
// record whose length disagrees with the datagram is the first thing any parser notices.
func dtlsFinishRecord(pkt []byte) {
	if len(pkt) < dtlsHeaderLen {
		return
	}
	binary.BigEndian.PutUint16(pkt[11:13], uint16(len(pkt)-dtlsHeaderLen))
}

// recoverNonce rebuilds the receive nonce from a record header. The header is in the clear,
// so unlike the QUIC path there is nothing to unmask first.
func (d *dtlsState) recoverNonce(pkt []byte, nonce *[12]byte) bool {
	if len(pkt) < dtlsHeaderLen {
		return false
	}
	copy(nonce[:dtlsSaltLen], d.recvSalt[:])
	copy(nonce[dtlsSaltLen:], pkt[3:11]) // epoch (2) + sequence (6), straight from the record
	return true
}

func putUint48(b []byte, v uint64) {
	b[0] = byte(v >> 40)
	b[1] = byte(v >> 32)
	b[2] = byte(v >> 24)
	b[3] = byte(v >> 16)
	b[4] = byte(v >> 8)
	b[5] = byte(v)
}

// dtlsIsCover reports whether a datagram is synthetic handshake cover rather than tunnel
// traffic — the same one-byte test the QUIC path makes on the header form bit.
func dtlsIsCover(pkt []byte) bool {
	return len(pkt) > 0 && pkt[0] == dtlsTypeHandshake
}

// --- synthetic handshake cover --------------------------------------------
//
// The same reasoning as quicinit.go: a DTLS session whose handshake was never observed is
// anomalous to a stateful classifier, and application_data records that appear from nothing
// are exactly what it would key on. So the flow opens with a real-looking ClientHello, and
// the far end answers it.
//
// Unlike QUIC's Initial, a DTLS ClientHello is not encrypted on the wire at all — it is
// plaintext, cookie field and all. That works in our favour: a DPI that looks inside finds
// an ordinary ClientHello for an ordinary host, with no decryption needed.

// dtlsHandshakeRecord wraps a handshake message in a DTLS record and its handshake header.
// msgSeq distinguishes the ClientHello from the server's reply, as DTLS requires.
func dtlsHandshakeRecord(msgType byte, msgSeq uint16, epoch uint16, seq uint64, body []byte) []byte {
	// Handshake header: type (1), length (3), message_seq (2), fragment_offset (3),
	// fragment_length (3). Unfragmented, so offset is 0 and fragment length is the whole.
	hs := make([]byte, 0, 12+len(body))
	hs = append(hs, msgType)
	hs = append(hs, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	hs = append(hs, byte(msgSeq>>8), byte(msgSeq))
	hs = append(hs, 0, 0, 0)
	hs = append(hs, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	hs = append(hs, body...)

	rec := make([]byte, dtlsHeaderLen, dtlsHeaderLen+len(hs))
	rec[0] = dtlsTypeHandshake
	rec[1], rec[2] = dtlsVersion[0], dtlsVersion[1]
	binary.BigEndian.PutUint16(rec[3:5], epoch)
	putUint48(rec[5:11], seq)
	binary.BigEndian.PutUint16(rec[11:13], uint16(len(hs)))
	return append(rec, hs...)
}

// buildDTLSClientHello assembles a DTLS 1.2 ClientHello body carrying the given server name.
// It reuses the TLS extension block from quicinit.go so both disguises name the same host in
// the same way, and adds the empty cookie field that DTLS inserts after the session ID.
func buildDTLSClientHello(sni string) []byte {
	// buildClientHello returns a TLS handshake message (4-byte header + body); the body is
	// what a DTLS ClientHello needs, with a cookie spliced in after the session ID.
	tls := buildClientHello(sni)
	if len(tls) < 4 {
		return nil
	}
	body := tls[4:]
	// body = legacy_version(2) + random(32) + session_id_len(1) + ... ; the session ID is
	// empty in what buildClientHello produces, so the cookie goes at a fixed offset.
	const cut = 2 + 32 + 1
	if len(body) < cut {
		return nil
	}
	out := make([]byte, 0, len(body)+1)
	out = append(out, body[:cut]...)
	out = append(out, 0x00) // cookie: empty, as in a first flight before HelloVerifyRequest
	out = append(out, body[cut:]...)
	// DTLS carries version {254,253} rather than the TLS legacy value.
	out[0], out[1] = dtlsVersion[0], dtlsVersion[1]
	return out
}

// sendDTLSClientHello opens a freshly bound carrier flow with a ClientHello, the DTLS
// counterpart of sendClientInitial. Errors are not fatal: this is cover, and the tunnel
// works without it.
func sendDTLSClientHello(c carrier, sni string) error {
	body := buildDTLSClientHello(sni)
	if body == nil {
		return nil
	}
	var seed [8]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return err
	}
	// Handshake records live on epoch 0 in real DTLS — the epoch only advances once the
	// cipher changes — so the cover uses 0 here even though data records do not.
	return c.Send(dtlsHandshakeRecord(1 /* client_hello */, 0, 0, uint64(binary.BigEndian.Uint32(seed[:4])), body))
}

// replyDTLSHelloVerify answers a ClientHello the way a real DTLS server does at first
// contact: a HelloVerifyRequest carrying a cookie, which is the standard anti-amplification
// step and therefore the least surprising thing to see on the wire.
func replyDTLSHelloVerify(c carrier) error {
	var cookie [20]byte
	if _, err := rand.Read(cookie[:]); err != nil {
		return err
	}
	body := make([]byte, 0, 3+len(cookie))
	body = append(body, dtlsVersion[0], dtlsVersion[1])
	body = append(body, byte(len(cookie)))
	body = append(body, cookie[:]...)
	var seed [4]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return err
	}
	return c.Send(dtlsHandshakeRecord(3 /* hello_verify_request */, 0, 0, uint64(binary.BigEndian.Uint32(seed[:])), body))
}
