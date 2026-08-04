// Obfuscation layer — presents each carrier datagram as a QUIC v1 short-header packet.
//
// Why this layer exists at all: aestun's payload is already AEAD ciphertext, so there is
// nothing left to gain against *content* inspection — uniform random bytes are the optimum
// and no amount of new framing improves on them. What is still visible is the datagram's
// *shape*, and that is what gets tunnels classified in practice:
//
//   - high entropy starting at byte 0, which no real protocol produces;
//   - a bimodal size distribution (a mass of full-MTU packets plus a cluster of tiny ones);
//   - a perfectly periodic keepalive, which is a clean clock signature.
//
// So this layer does not invent new cryptography. It gives the datagram a header a QUIC
// parser accepts, quantises sizes onto buckets, and lets main.go jitter the keepalive.
//
// Wire format when enabled (13-byte header, one byte more than the bare-nonce format):
//
//	[1 byte flags][8 byte connection ID][4 byte packet number][ciphertext][16 byte tag]
//
// The AEAD nonce is the connection ID followed by the packet number, so the header *is*
// the nonce rather than being prepended to one — the 12 bytes do double duty and the
// overhead versus the unobfuscated format is a single byte.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"sync"
	"sync/atomic"
)

const (
	obfsHeaderLen = 13 // 1 flags + 8 connection ID + 4 packet number
	obfsSampleLen = 16 // header-protection sample, as in RFC 9001
	obfsCIDLen    = 8
)

// Size buckets for the "balanced" shaping mode. Small datagrams are padded up to the next
// bucket so the tiny-packet cluster (pure ACKs of the inner connections) stops forming its
// own mode in the size histogram; large ones are left alone, which is where nearly all the
// bytes are. Padding every packet up to ~1200 the way real QUIC does for anti-amplification
// would hide more, at a bandwidth cost this link cannot spare.
var obfsBuckets = []int{128, 256, 512, 768, 1024, 1280}

type obfuscator struct {
	// Stable for the life of the connection, like a real QUIC connection ID. Held behind
	// a pointer so it can be swapped if the packet number ever wraps (see nextHeader).
	cid   atomic.Pointer[[obfsCIDLen]byte]
	cidMu sync.Mutex
	pn    atomic.Uint32 // packet number, incremented per sent datagram
	// Set once the peer's handshake connection ID has been adopted; see adoptPeerCID.
	adopted atomic.Bool

	// Header protection, one key per direction. Deliberately NOT epoch-derived: the
	// receiver has to unmask the header to recover the nonce *before* it can try any
	// epoch key, so binding this to an epoch would be circular. It is obfuscation, not
	// a security boundary — the AEAD is what actually protects the packet.
	sendHP cipher.Block
	recvHP cipher.Block

	shape bool // quantise datagram sizes onto obfsBuckets

	// Spin bit state. Real QUIC flips this roughly once per RTT; a bit that never moves
	// (or one that flips every packet) is itself distinguishable from a real connection.
	spinCount atomic.Uint32
	spin      atomic.Bool
}

// spinPeriod is how many sent packets pass between spin-bit flips. Real QUIC flips once
// per round trip; at this tunnel's packet rates that lands in the low tens of packets.
const spinPeriod = 24

func newObfuscator(psk []byte, sendDir, recvDir string, shape bool) (*obfuscator, error) {
	o := &obfuscator{shape: shape}
	if err := o.rotateCID(); err != nil {
		return nil, err
	}
	// A fresh random connection ID per process is also what keeps the nonce space safe
	// across restarts: the packet number restarts at zero, so without a fresh ID a restart
	// inside the same rekey epoch would reuse (key, nonce) pairs and break GCM outright.
	mk := func(dir string) (cipher.Block, error) {
		return aes.NewCipher(hkdf(psk, nil, []byte("aestun-v1 hp "+dir), 16))
	}
	var err error
	if o.sendHP, err = mk(sendDir); err != nil {
		return nil, err
	}
	if o.recvHP, err = mk(recvDir); err != nil {
		return nil, err
	}
	// Start the packet number somewhere random in the low range rather than at 0, so a
	// passive observer cannot spot a process restart by watching the counter reset.
	var seed [4]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, err
	}
	o.pn.Store(binary.BigEndian.Uint32(seed[:]) >> 8) // 24-bit start, leaves room to climb
	return o, nil
}

// hpScratch is the working space for one header-protection operation: 16 bytes in,
// 16 bytes out. It has to be supplied by the caller rather than declared locally, because
// cipher.Block is an interface and the compiler therefore cannot prove that Encrypt does
// not retain the slices it is handed — so local arrays escape to the heap and cost two
// allocations on every single packet, in both directions. Callers keep one of these in
// their sealer or opener, where it is allocated once per goroutine for the process's life.
type hpScratch struct {
	in  [16]byte
	out [16]byte
}

// obfsMask derives the header-protection mask exactly as RFC 9001 does: encrypt a sample of
// the ciphertext under the HP key and use the resulting block as a one-time pad over the
// header's variable bits.
func obfsMask(blk cipher.Block, sample []byte, sc *hpScratch) [5]byte {
	copy(sc.in[:], sample)
	blk.Encrypt(sc.out[:], sc.in[:])
	var m [5]byte
	copy(m[:], sc.out[:5])
	return m
}

func (o *obfuscator) rotateCID() error {
	var c [obfsCIDLen]byte
	if _, err := rand.Read(c[:]); err != nil {
		return err
	}
	o.cid.Store(&c)
	return nil
}

// adoptPeerCID switches outgoing packets to the connection ID the peer advertised in its
// handshake, which is what a real QUIC endpoint does once the handshake names one. Without
// it the 1-RTT packets carry an ID unrelated to the Initial exchange and the flow reads as
// a handshake followed by packets belonging to some other connection.
//
// Applied once per process. The trigger is an unauthenticated packet, so accepting repeated
// updates would let anyone flip the ID at will; taking only the first bounds that to a
// single one-off. It is safe either way — the ID is public nonce material and the packet
// number keeps climbing across the change, so no (key, nonce) pair is ever reused.
func (o *obfuscator) adoptPeerCID(b []byte) bool {
	if len(b) != obfsCIDLen {
		return false
	}
	if !o.adopted.CompareAndSwap(false, true) {
		return false
	}
	var c [obfsCIDLen]byte
	copy(c[:], b)
	o.cid.Store(&c)
	return true
}

// nextHeader writes the 13-byte header for an outgoing packet into hdr and the AEAD nonce
// it encodes into nonce, returning the packet number. Caller-provided arrays rather than
// freshly made slices: this runs once per outbound packet, and two 12-13 byte allocations
// per packet was a steady stream of garbage for no reason. Protection is applied later,
// once the ciphertext exists.
func (o *obfuscator) nextHeader(hdr *[obfsHeaderLen]byte, nonce *[12]byte) (pn uint32) {
	pn = o.pn.Add(1)

	// The nonce is connection ID + packet number, so a wrapped packet number would start
	// reissuing nonces already used under the same key. Harmless when rekey_interval is
	// set (the key has long since changed), fatal for GCM when the key is static — so
	// take a fresh connection ID instead, which moves the whole nonce space. Real QUIC
	// rotates connection IDs too, so this does not look out of place on the wire.
	if pn == 0 {
		o.cidMu.Lock()
		if o.pn.Load() == 0 { // still zero: we are the goroutine that wrapped it
			_ = o.rotateCID()
		}
		o.cidMu.Unlock()
	}

	if o.spinCount.Add(1)%spinPeriod == 0 {
		o.spin.Store(!o.spin.Load())
	}

	// QUIC v1 short header: bit7=0 (short form), bit6=1 (fixed bit, always set in v1),
	// bit5=spin, bits4-3=reserved, bit2=key phase, bits1-0=packet number length - 1.
	// A 4-byte packet number means the length bits are 0b11.
	var flags byte = 0x40 | 0x03
	if o.spin.Load() {
		flags |= 0x20
	}
	// Reserved and key-phase bits are header-protected in real QUIC and therefore look
	// random on the wire; the mask applied below supplies exactly that randomness, so
	// they are left clear here.

	cid := o.cid.Load()

	hdr[0] = flags
	copy(hdr[1:1+obfsCIDLen], cid[:])
	binary.BigEndian.PutUint32(hdr[1+obfsCIDLen:], pn)

	// The nonce is the header's own connection ID and packet number. Unique per packet
	// because the packet number strictly increases, and unique across restarts because
	// the connection ID is freshly random per process.
	copy(nonce[:], cid[:])
	binary.BigEndian.PutUint32(nonce[obfsCIDLen:], pn)
	return pn
}

// protect applies header protection in place over a finished datagram (header+ciphertext).
func (o *obfuscator) protect(pkt []byte, sc *hpScratch) {
	if len(pkt) < obfsHeaderLen+obfsSampleLen {
		return
	}
	m := obfsMask(o.sendHP, pkt[obfsHeaderLen:obfsHeaderLen+obfsSampleLen], sc)
	// Only the bits QUIC itself protects: the low 5 bits of the first byte (reserved,
	// key phase, packet number length) and the packet number bytes. The form and fixed
	// bits stay clear so the packet still parses as a QUIC short header.
	pkt[0] ^= m[0] & 0x1f
	for i := 0; i < 4; i++ {
		pkt[obfsHeaderLen-4+i] ^= m[1+i]
	}
}

// unprotectInto reverses protect, writing the recovered nonce into the caller's array so
// the receive path does not allocate a 12-byte slice per packet.
func (o *obfuscator) unprotectInto(pkt []byte, nonce *[12]byte, sc *hpScratch) bool {
	if len(pkt) < obfsHeaderLen+obfsSampleLen {
		return false
	}
	m := obfsMask(o.recvHP, pkt[obfsHeaderLen:obfsHeaderLen+obfsSampleLen], sc)
	// The connection ID is not protected, so it can be read directly; only the packet
	// number needs unmasking to rebuild the nonce.
	copy(nonce[:], pkt[1:1+obfsCIDLen])
	for i := 0; i < 4; i++ {
		nonce[obfsCIDLen+i] = pkt[obfsHeaderLen-4+i] ^ m[1+i]
	}
	return true
}

// padTo reports how many bytes of padding bring a datagram of size n up to the next bucket.
// Returns 0 once n is past the largest bucket, which is where the bulk of the bytes live.
func obfsPadTo(n int) int {
	for _, b := range obfsBuckets {
		// <= not <, so a datagram that already lands exactly on a bucket is left alone
		// instead of being pushed a whole bucket wider.
		if n <= b {
			return b - n
		}
	}
	return 0
}
