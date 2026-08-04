package main

import (
	"crypto/hmac"
	"crypto/sha256"
)

// ---------------------------------------------------------------------------
// HKDF (RFC 5869) over HMAC-SHA256 — short, dependency-free implementation
// ---------------------------------------------------------------------------

func hkdf(secret, salt, info []byte, n int) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	// Extract
	m := hmac.New(sha256.New, salt)
	m.Write(secret)
	prk := m.Sum(nil)
	// Expand
	var out, t []byte
	for i := 1; len(out) < n; i++ {
		h := hmac.New(sha256.New, prk)
		h.Write(t)
		h.Write(info)
		h.Write([]byte{byte(i)})
		t = h.Sum(nil)
		out = append(out, t...)
	}
	return out[:n]
}
