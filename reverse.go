// Reverse direction for the UDP carrier: the outside server opens the flow, and the inside
// server only ever answers.
//
// Normally role a — the server inside Iran — dials. It sends the first datagram of every
// carrier flow, plays the client half of the synthetic handshake, and is the end udp_rotate
// moves, so every flow on the wire is one opened from inside toward a foreign address. The
// premise of reverse tunnels (Backhaul, rathole, frp) is that a censor does not treat the two
// directions alike: a flow opened from inside toward a foreign address is the kind that gets
// flagged or cut when the filter tightens, while a foreign host reaching a server inside looks
// like a visitor reaching a domestic service. "reverse": true gives this tunnel that shape
// without changing anything else about it:
//
//   - role b, the outside server, dials. It sends the client hello of the handshake cover,
//     announces itself with a few sealed keepalives straight behind it, keeps the flow alive,
//     and is the end udp_rotate moves.
//   - role a, the inside server, listens and is passive: it sends nothing — no keepalive, no
//     probe, no handshake reply, no tunnel traffic — to any address that has not first sent
//     it an authenticated packet. Every datagram it emits is the reply direction of a flow the
//     outside server opened. Its "peer" setting is never dialled; the peer is learned from the
//     first authenticated packet, by the same roaming that already follows a moving source port.
//
// Roles keep everything else they meant before — the key directions, the tunnel addresses, and
// all the scripts derive from them — so the inside server is still role a and still 10.8.0.1.
// Only who speaks first changes. Like key, cipher and obfs, the switch is not negotiated, so it
// must be the same on both servers.
//
// The one new piece of machinery is the hello gate. The listener has to answer the dialer's
// handshake cover the way a server would — a client Initial that is never answered is exactly
// the "Unknown QUIC connection" a stateful classifier keys on — but the cover arrives before
// the dialer has authenticated, from an address that is so far as anonymous as a prober's.
// Answering it there would make the port respond to anybody who sends it an Initial; not
// answering would leave the cover half-built. So the listener holds the hello until an
// authenticated packet arrives from that exact address, which the dialer sends within a round
// trip, and only then answers it. A hello nobody vouches for is filed with the DPI observer as
// the probe it was, once the hold runs out.
//
// UDP and WebSocket. On the WebSocket carrier (ws.go) the swap is just which end runs the dial
// loop: its listener only ever answers connections the dialer opened, and admits one only once
// its first message authenticates, so it is passive by construction and needs no gate. The TCP
// carrier's accept path would need the same swap made on its own; ICMP has no direction to
// reverse, since both ends send echo requests and the reply is the one message the path is known
// to drop. Port hopping moves both ends on a shared schedule, so neither is a fixed point for the
// other to dial, and it is refused alongside.
package main

import (
	"fmt"
	"log"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// dials reports whether this end opens the carrier flow: role a normally, role b under reverse.
func (c *Config) dials() bool { return (c.Role == "a") != c.Reverse }

// checkReverse refuses the combinations reverse cannot honour. An error rather than a quiet
// fallback, like every other invalid combination here: a listener that silently went back to
// dialling would open precisely the outbound flow it was configured never to open.
func checkReverse(c *Config) error {
	if !c.Reverse {
		return nil
	}
	switch {
	case c.Transport != "udp" && c.Transport != "ws":
		return fmt.Errorf("\"reverse\" is implemented for transports \"udp\" and \"ws\", not %q; set "+
			"\"reverse\": false, or another transport, on BOTH servers", c.Transport)
	case c.Hop.on():
		return fmt.Errorf("\"reverse\" cannot be combined with port hopping: hopping moves both " +
			"ends on a shared schedule, so neither is a fixed point for the other to dial; turn " +
			"one of them off on BOTH servers")
	case c.Transport == "udp" && c.dials() && c.Peer == "":
		// The WebSocket dialer dials ws.url, which checkWS verifies.
		return fmt.Errorf("\"reverse\" makes this end (role b) the one that dials, so \"peer\" " +
			"must be the inside server's public host:port")
	}
	return nil
}

// reverseEnd names this end's part for the startup banner and the stats file.
func (t *Tunnel) reverseEnd() string {
	switch {
	case !t.reverse:
		return "off"
	case t.passive:
		return "listen"
	}
	return "dial"
}

// announce tells a reverse listener where this end is. The listener sends nothing to an address
// that has not authenticated, so until an authenticated packet arrives it can neither answer the
// handshake nor deliver a single byte — and without this the first one it hears is the first
// keepalive, up to 35 s away. A few sealed keepalives straight behind the hello; their count and
// spacing are drawn at random, like junk, so the opening of the flow has no fixed rhythm. They
// authenticate at the far end and decrypt to nothing, so they are never mistaken for traffic.
func announce(c carrier, t *Tunnel) {
	s := newSealer()
	n := 2 + int(s.rng.uint16()%3)
	for i := 0; i < n; i++ {
		lo, hi := 150, 900
		if i == 0 {
			lo, hi = 10, 120 // the first is the one that matters; send it promptly
		}
		time.Sleep(junkGap(s, lo, hi))
		if err := c.Send(t.sealInto(s, nil)); err != nil {
			log.Printf("reverse: announcing this end to the peer failed: %v", err)
			return
		}
	}
}

// ---------------------------------------------------------------------------
// hello gate
// ---------------------------------------------------------------------------

// helloHold is how long the listener waits for a hello's sender to authenticate. The dialer
// announces itself within a round trip; the margin covers every announcement being lost, in
// which case its first keepalive — at most 35 s away with the default 25 s, jittered — vouches
// for it instead.
const helloHold = 40 * time.Second

// heldHello is one handshake-cover datagram waiting for its sender to authenticate.
type heldHello struct {
	src   netip.AddrPort
	pkt   []byte // a copy: the receive buffer it arrived in is reused for the next datagram
	ttl   uint8
	class string // how the DPI observer files it if nobody vouches for it
	sni   string
	at    time.Time
}

// helloGate holds at most one unconfirmed hello. One slot is enough: the dialer sends a single
// hello per flow and authenticates within a round trip, and a hello displaced by a newer one is
// filed exactly as the listener filed every unauthenticated hello before the gate existed.
type helloGate struct {
	hold   time.Duration
	report func(heldHello)       // file a hello nobody vouched for
	answer func(heldHello) error // answer a hello whose sender has authenticated

	// armed is the hot path: confirm runs for every authenticated packet, and almost always
	// there is nothing held, so that case costs one atomic load and takes no lock.
	armed atomic.Bool
	mu    sync.Mutex
	held  *heldHello
	timer *time.Timer
}

func newHelloGate(hold time.Duration, report func(heldHello), answer func(heldHello) error) *helloGate {
	return &helloGate{hold: hold, report: report, answer: answer}
}

// offer holds a hello that arrived from an address which has not authenticated. The datagram is
// copied. Whatever it displaces is reported, since nothing can vouch for it any more.
func (g *helloGate) offer(src netip.AddrPort, pkt []byte, ttl uint8, class, sni string) {
	h := &heldHello{
		src: src, pkt: append([]byte(nil), pkt...), ttl: ttl,
		class: class, sni: sni, at: time.Now(),
	}
	g.mu.Lock()
	old := g.held
	g.held = h
	g.armed.Store(true)
	// One timer, rescheduled by every offer, so a flood of hellos costs one timer rather than
	// one each. A run that finds a newer hello not yet due leaves it to the run this Reset
	// scheduled, which by construction comes at least one hold after that hello arrived.
	if g.timer == nil {
		g.timer = time.AfterFunc(g.hold, g.expire)
	} else {
		g.timer.Reset(g.hold)
	}
	g.mu.Unlock()
	if old != nil {
		g.report(*old)
	}
}

// confirm is called with the source of every authenticated packet. If a hello from exactly that
// address is waiting, its sender has just proved it holds the key: answer it. Reports whether a
// hello was answered.
func (g *helloGate) confirm(src netip.AddrPort) (bool, error) {
	if !g.armed.Load() {
		return false, nil
	}
	g.mu.Lock()
	h := g.held
	if h == nil || h.src != src {
		g.mu.Unlock()
		return false, nil
	}
	g.held = nil
	g.armed.Store(false)
	g.mu.Unlock()
	return true, g.answer(*h)
}

// expire files the held hello once nobody has vouched for it within the hold.
func (g *helloGate) expire() {
	g.mu.Lock()
	h := g.held
	if h == nil || time.Since(h.at) < g.hold {
		g.mu.Unlock()
		return // answered already, or displaced by a newer hello whose own run is still due
	}
	g.held = nil
	g.armed.Store(false)
	g.mu.Unlock()
	g.report(*h)
}

// offerHello hands the gate a hello from an address that has not authenticated. The second step
// closes a race between the parallel receive goroutines: the sender may have authenticated on
// another goroutine while this one was classifying its hello, and then nothing would come along
// later to confirm it.
func offerHello(g *helloGate, t *Tunnel, src netip.AddrPort, pkt []byte, ttl uint8, class, sni string) {
	g.offer(src, pkt, ttl, class, sni)
	if t.samePeer(src) {
		confirmHello(g, src)
	}
}

// confirmHello is the receive loop's side of confirm: every authenticated source passes through
// it, and a failed answer is worth a log line but never worth stopping for.
func confirmHello(g *helloGate, src netip.AddrPort) {
	if _, err := g.confirm(src); err != nil {
		log.Printf("reverse: answering the handshake from %s failed: %v", src, err)
	}
}

// helloAnswer builds what a server sends back to a client's handshake cover — a QUIC server
// Initial, or a DTLS HelloVerifyRequest — and adopts the connection ID the client advertised,
// which the listener deliberately did not do while the hello was unconfirmed: taking it from an
// unauthenticated packet would let any prober choose the ID our traffic carries.
func (t *Tunnel) helloAnswer(h heldHello) ([]byte, error) {
	if t.obfs == nil {
		return nil, nil
	}
	if t.obfs.wire == wireDTLS {
		return dtlsHelloVerify()
	}
	if _, scid, ok := quicParseLongCIDs(h.pkt); ok {
		t.obfs.adoptPeerCID(scid)
	}
	return serverInitialFor(h.pkt)
}
