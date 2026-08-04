// In-tunnel round-trip probes.
//
// Loss and reordering can be measured from the sequence numbers that anti-replay already
// puts in every packet, but latency cannot: nothing in the existing protocol asks the peer
// to answer. A DPI box that is throttling or delaying a flow rather than blocking it shows
// up as latency long before it shows up as loss, so it is worth one small packet every
// twenty seconds to see it.
//
// The probe travels *inside* the tunnel encryption, in the slot where an inner IP packet
// normally goes. Anything there is already indistinguishable from the rest of the traffic
// on the wire, so this adds no new signature — which is the whole reason not to build the
// measurement into the carrier layer instead.
//
// Wire format of the inner frame:
//
//	[0]     0x00   — no IP packet can start with this (v4 begins 0x4n, v6 begins 0x6n),
//	                 so a control frame is never mistaken for traffic, and a peer running
//	                 an older build simply writes it to its TUN where the kernel discards it
//	[1]     type   — 1 = ping, 2 = pong
//	[2:10]  the sender's monotonic-ish timestamp, unix nanoseconds
//	[10:18] on a pong, the timestamp copied from the ping being answered
package main

import (
	"encoding/binary"
	"time"
)

const (
	ctrlMagic    = 0x00
	ctrlPing     = 1
	ctrlPong     = 2
	ctrlFrameLen = 18
)

// isControlFrame reports whether an opened inner payload is a probe rather than an IP packet.
func isControlFrame(p []byte) bool {
	return len(p) >= ctrlFrameLen && p[0] == ctrlMagic
}

func buildCtrl(buf []byte, typ byte, mine, echo int64) []byte {
	b := buf[:ctrlFrameLen]
	b[0] = ctrlMagic
	b[1] = typ
	binary.BigEndian.PutUint64(b[2:10], uint64(mine))
	binary.BigEndian.PutUint64(b[10:18], uint64(echo))
	return b
}

// probeAgent owns the sending side of the probe exchange. It has its own sealer, so it
// never contends with the TUN pump, and it answers pings from a small buffered channel so
// the receive loop can hand off a reply without ever blocking.
type probeAgent struct {
	t     *Tunnel
	c     carrier
	every time.Duration
	pongs chan int64 // timestamps to echo back
	frame []byte
	seal  *sealer
}

func newProbeAgent(t *Tunnel, c carrier, every time.Duration) *probeAgent {
	return &probeAgent{
		t:     t,
		c:     c,
		every: every,
		pongs: make(chan int64, 64),
		frame: make([]byte, ctrlFrameLen),
		seal:  newSealer(),
	}
}

// onPing is called from the receive loop. It must never block.
func (p *probeAgent) onPing(sent int64) {
	select {
	case p.pongs <- sent:
	default: // reply queue full; dropping a probe reply costs nothing
	}
}

// onPong is called from the receive loop with a reply we sent out earlier.
func (p *probeAgent) onPong(theirs, mine int64) {
	if mine <= 0 {
		return
	}
	rtt := time.Now().UnixNano() - mine
	if rtt <= 0 || rtt > int64(30*time.Second) {
		return // clock went backwards, or the reply is far too old to mean anything
	}
	p.t.dpi.noteRTT(uint64(rtt / 1000))
}

// handle dispatches an inner control frame. Returns true if the payload was consumed here
// and must not be written to the TUN device.
func (p *probeAgent) handle(frame []byte) bool {
	if !isControlFrame(frame) {
		return false
	}
	theirs := int64(binary.BigEndian.Uint64(frame[2:10]))
	echo := int64(binary.BigEndian.Uint64(frame[10:18]))
	switch frame[1] {
	case ctrlPing:
		p.onPing(theirs)
	case ctrlPong:
		p.onPong(theirs, echo)
	}
	return true
}

func (p *probeAgent) run() {
	tick := time.NewTicker(p.every)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			now := time.Now().UnixNano()
			f := buildCtrl(p.frame, ctrlPing, now, 0)
			// A send error here is not worth logging on its own: the carrier already
			// reports its failures, and a lost probe is exactly what the loss and
			// blackhole detectors are there to notice.
			_ = p.c.Send(p.t.sealInto(p.seal, f))
		case sent := <-p.pongs:
			f := buildCtrl(p.frame, ctrlPong, time.Now().UnixNano(), sent)
			_ = p.c.Send(p.t.sealInto(p.seal, f))
		}
	}
}
