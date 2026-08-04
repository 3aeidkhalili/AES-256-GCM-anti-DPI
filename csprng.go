// Buffered randomness for the packet path.
//
// crypto/rand.Read is a syscall (getrandom) plus Go's own locking around it, and it
// measured at ~1.9 microseconds per call on both of this project's servers — regardless
// of whether the caller wanted 12 bytes or 64. seal() called it once or twice for every
// single packet, so on a link doing a few thousand packets a second that one function
// was costing more CPU than AES-GCM itself on the machine that *has* AES-NI.
//
// The fix is to draw from the kernel in bulk and hand out slices. That is sound for what
// this randomness is used for: the padding length and the padding bytes live inside the
// AEAD and never appear on the wire, and the random nonce of the non-obfuscated format
// needs to be *unique*, not unpredictable — GCM's requirement is uniqueness, and 96 bits
// from the kernel CSPRNG delivers that whether it arrives one call or one page at a time.
// Consumed bytes are zeroed as they are handed out, so a later memory disclosure cannot
// recover nonce material this process already used.
//
// A csprng is NOT safe for concurrent use. Each goroutine on the packet path owns one.
package main

import (
	"crypto/rand"
	"log"
)

// 16 KiB refills once per ~250 full-MTU packets' worth of padding — small enough to stay
// in L1/L2, large enough that the syscall disappears into the noise.
const csprngBufSize = 16 << 10

type csprng struct {
	buf [csprngBufSize]byte
	off int // index of the next unconsumed byte; == len(buf) means "empty, refill"
}

func newCSPRNG() *csprng {
	r := &csprng{off: csprngBufSize}
	return r
}

func (r *csprng) fill() {
	if _, err := rand.Read(r.buf[:]); err != nil {
		// The kernel CSPRNG failing is not something a tunnel can paper over: every
		// nonce downstream of here would be suspect.
		log.Fatalf("crypto/rand: %v", err)
	}
	r.off = 0
}

// read fills p with random bytes.
func (r *csprng) read(p []byte) {
	for len(p) > 0 {
		if r.off >= csprngBufSize {
			r.fill()
		}
		n := copy(p, r.buf[r.off:])
		// Burn what we just handed out.
		clear(r.buf[r.off : r.off+n])
		r.off += n
		p = p[n:]
	}
}

// uint16 returns two random bytes as an integer — used to pick a padding length.
func (r *csprng) uint16() uint16 {
	if r.off+2 > csprngBufSize {
		r.fill()
	}
	v := uint16(r.buf[r.off])<<8 | uint16(r.buf[r.off+1])
	r.buf[r.off], r.buf[r.off+1] = 0, 0
	r.off += 2
	return v
}
