// Cipher suite selection.
//
// AES-256-GCM is the right default *when the CPU has AES-NI*. Without it, Go falls
// back to a constant-time table-free software AES plus a generic GHASH, and the cost
// is not a detail: measured on this project's own foreign endpoint (a QEMU virtual CPU
// exposing neither `aes` nor `pclmulqdq`), AES-256-GCM runs at 41 MB/s while
// ChaCha20-Poly1305 runs at 234 MB/s — 5.7x, or 26 microseconds saved on every
// 1300-byte packet. ChaCha20 was designed for exactly this case: it needs nothing but
// 32-bit adds, xors and rotates, so it does not care that the CPU is a stripped-down
// virtual model.
//
// Both AEADs take a 12-byte nonce and add a 16-byte tag, so the choice is invisible
// on the wire: the datagram layout, the sizes, and the obfuscation layer above are all
// byte-identical either way. What it is *not* is negotiable — there is no handshake to
// negotiate in, by design — so the two ends must be configured alike.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/sys/cpu"
)

const (
	cipherAESGCM = "aes-gcm"
	cipherChaCha = "chacha20-poly1305"
)

// newAEAD builds the AEAD for a 32-byte key under the named suite.
func newAEAD(suite string, key []byte) (cipher.AEAD, error) {
	switch suite {
	case cipherAESGCM:
		blk, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(blk)
	case cipherChaCha:
		return chacha20poly1305.New(key)
	default:
		return nil, fmt.Errorf("unknown cipher %q (want %q or %q)", suite, cipherAESGCM, cipherChaCha)
	}
}

// hasAESAccel reports whether this CPU can do AES-GCM in hardware. Both halves matter:
// AES-NI accelerates the block cipher and PCLMULQDQ (or the ARM equivalent) accelerates
// GHASH, and Go only takes its fast GCM path when both are present.
func hasAESAccel() bool {
	switch {
	case cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ:
		return true
	case cpu.ARM64.HasAES && cpu.ARM64.HasPMULL:
		return true
	}
	return false
}

// recommendedCipher is what this machine should use if the peer agrees. A link is only
// as fast as its slower end, so the answer on *either* box being chacha means both
// should be set to chacha.
func recommendedCipher() string {
	if hasAESAccel() {
		return cipherAESGCM
	}
	return cipherChaCha
}
