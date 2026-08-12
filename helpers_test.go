package main

import "sync"

// Test-only conveniences.
//
// The packet path is written around caller-owned scratch (sealer/opener) so that it never
// allocates, which is right for the tunnel and awkward for a test that just wants one
// packet. These wrappers keep one scratch struct per Tunnel behind a mutex and hand back a
// copy, so a test can write `b.open(a.seal(msg))` and hold on to both results.
//
// They live in a _test.go file on purpose: nothing in the tunnel should reach for them, and
// the copy they make is exactly what the production path exists to avoid.

var (
	scratchMu sync.Mutex
	sealers   = map[*Tunnel]*sealer{}
	openers   = map[*Tunnel]*opener{}
)

// seal encrypts one packet and returns a freshly allocated datagram.
func (t *Tunnel) seal(plain []byte) []byte {
	scratchMu.Lock()
	defer scratchMu.Unlock()
	s := sealers[t]
	if s == nil {
		s = newSealer()
		sealers[t] = s
	}
	out := t.sealInto(s, plain)
	cp := make([]byte, len(out))
	copy(cp, out)
	return cp
}

// open decrypts one datagram and returns a freshly allocated payload.
func (t *Tunnel) open(pkt []byte) ([]byte, bool) {
	scratchMu.Lock()
	defer scratchMu.Unlock()
	o := openers[t]
	if o == nil {
		o = newOpener()
		openers[t] = o
	}
	plain, ok := t.openInto(o, pkt)
	if !ok {
		return nil, false
	}
	cp := make([]byte, len(plain))
	copy(cp, plain)
	return cp, true
}
