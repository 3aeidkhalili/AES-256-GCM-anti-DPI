// Carrier rate limiting.
//
// This exists because of a measurement, not a theory. Sweeping offered UDP rate against
// delivered rate on this project's own link produced a cliff rather than a curve:
//
//	offered      delivered     loss
//	185 Mbit/s   183 Mbit/s      0%
//	210 Mbit/s   210 Mbit/s      0%
//	220 Mbit/s   145 Mbit/s     34%
//	260 Mbit/s   155 Mbit/s     40%
//
// That is a policer. Below its threshold the path is perfect; a few percent above it, a
// third of the traffic is discarded and *delivered* throughput falls by a quarter. Pushing
// harder makes the link slower.
//
// TCP cannot see this. Congestion control probes upward until it loses packets, so it sits
// permanently on the wrong side of the cliff: measured here, BBR offered 232 Mbit/s to
// deliver 194, retransmitting 18% — while a paced 190 Mbit/s delivered 188 with no loss at
// all. Nearly the same goodput for 20% less traffic on the wire, and without the retransmit
// storm that adds latency and jitter to every other connection sharing the tunnel.
//
// So: shape here, below the policer, and the policer never engages. Shaping and policing
// are not the same thing. A policer drops what exceeds the rate; this delays it, which
// backs pressure up through the TUN queue to the inner TCP senders, and they slow down on
// their own — which is what congestion control is for.
//
// Off by default. It has to be set from a measurement of your own path; a wrong value is
// just a speed limit.
package main

import (
	"time"
)

// pacer is a token bucket over carrier bytes. Not safe for concurrent use: the TUN pump
// owns one, and the keepalive and probe frames deliberately bypass it — a handful of small
// packets a minute is not what a rate limit is for, and delaying a keepalive could make an
// idle tunnel look dead.
type pacer struct {
	bytesPerSec float64
	burst       float64
	tokens      float64
	last        time.Time
}

// newPacer returns nil when rate is 0, which callers treat as "no limit".
func newPacer(mbps float64) *pacer {
	if mbps <= 0 {
		return nil
	}
	bps := mbps * 1e6 / 8
	return &pacer{
		bytesPerSec: bps,
		// A tenth of a second of burst. Large enough that a full send batch never has to
		// wait on an idle link, small enough that the queue it can build stays far below
		// anything a user would notice.
		burst:  bps * 0.1,
		tokens: bps * 0.1,
		last:   time.Now(),
	}
}

// minPacerSleep is the shortest sleep worth asking for. Below roughly this, the scheduler's
// own granularity dominates and the call costs more than the delay it is trying to create;
// the shortfall is carried as debt instead and settled by the next call.
const minPacerSleep = 200 * time.Microsecond

// accrue credits the tokens earned since the last call. It must be the *only* place the
// clock is read, because the credit has to be computed from the time that actually passed.
// Crediting the time we asked to sleep for, rather than the time we really slept, silently
// throws away the scheduler's overshoot — which on a millisecond-granularity timer against
// a sub-millisecond request meant discarding most of every interval, and shaped a nominal
// 100 Mbit/s down to 22.
func (p *pacer) accrue() {
	now := time.Now()
	if elapsed := now.Sub(p.last).Seconds(); elapsed > 0 {
		p.tokens += elapsed * p.bytesPerSec
		if p.tokens > p.burst {
			p.tokens = p.burst
		}
		p.last = now
	}
}

// wait blocks until n bytes may be sent.
func (p *pacer) wait(n int) {
	if p == nil {
		return
	}
	p.accrue()
	need := float64(n)
	if p.tokens < need {
		deficit := need - p.tokens
		if d := time.Duration(deficit / p.bytesPerSec * float64(time.Second)); d > minPacerSleep {
			time.Sleep(d)
			p.accrue()
		}
	}
	// Tokens may go negative. That is deliberate: a batch larger than the bucket still
	// goes out in one piece, and the debt simply delays the next one.
	p.tokens -= need
}
