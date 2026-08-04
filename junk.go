// Flow-start cover traffic — AmneziaWG-style "junk", made safe by construction.
//
// A classifier does not only look at what is inside packets; it looks at how a flow *begins*.
// A tunnel that opens with the same small number of packets, at the same sizes, in the same
// rhythm, every single time, has a start-of-flow fingerprint even when every byte is
// encrypted. AmneziaWG's answer is to prepend a run of random "junk" packets so the opening
// looks different on every connection and does not match the reference protocol's first-N
// packets. This does the same thing.
//
// The catch with literal random junk is what the *peer* does with it: unsealed random
// datagrams fail authentication and would be filed by the observer as a scan or an injection,
// turning our own cover traffic into noise in the DPI log. So the junk here is not raw random
// bytes — it is real sealed keepalive packets. They are high-entropy and indistinguishable
// from tunnel data on the wire (they are tunnel data), they authenticate cleanly at the peer,
// and they decrypt to an empty inner payload that the receive loop already discards as a
// keepalive. With obfs on they even parse as QUIC. Nothing new is needed on the receive side,
// and nothing about them can hurt the tunnel.
//
// What varies is the count and the timing: a burst of Count packets with a random gap between
// each, so the opening of the flow carries no fixed packet-count or inter-packet-interval
// signature. Sizes vary too, from the padding the sealer already applies (random up to
// pad_max, or the shaping buckets under obfs). Off by default.
package main

import (
	"log"
	"time"
)

// JunkConfig (struct + defaults) lives in tunnel.go next to Config.

// junkBurst emits Count sealed keepalives with a random gap between each, as flow-start cover.
// It owns its own sealer so it never contends with the TUN pump, and it uses the buffered
// CSPRNG the sealer already carries for the timing jitter, so it makes no syscall per packet.
func junkBurst(t *Tunnel, c carrier, cfg *JunkConfig) {
	if cfg == nil || cfg.Enabled == nil || !*cfg.Enabled || cfg.Count <= 0 {
		return
	}
	lo, hi := cfg.MinMs, cfg.MaxMs
	if lo < 0 {
		lo = 0
	}
	if hi < lo {
		hi = lo
	}
	s := newSealer()
	sent := 0
	for i := 0; i < cfg.Count; i++ {
		if err := c.Send(t.sealInto(s, nil)); err != nil {
			// A cover packet failing to send is not worth interrupting startup for; the peer
			// may simply not be reachable yet, which the real traffic path will report.
			break
		}
		sent++
		if i < cfg.Count-1 {
			time.Sleep(junkGap(s, lo, hi))
		}
	}
	if sent > 0 {
		log.Printf("junk: sent %d flow-start cover packet(s)", sent)
	}
}

// junkGap picks a random delay in [loMs, hiMs] using the sealer's CSPRNG.
func junkGap(s *sealer, loMs, hiMs int) time.Duration {
	span := hiMs - loMs
	ms := loMs
	if span > 0 {
		ms += int(s.rng.uint16()) % (span + 1)
	}
	return time.Duration(ms) * time.Millisecond
}
