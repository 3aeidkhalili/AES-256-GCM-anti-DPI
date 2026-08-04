//go:build linux

// Native DPI desync — the in-process equivalent of zapret's nfqws, without a second
// process, without NFQUEUE, and without a single iptables rule.
//
// Why do this in-process at all when zapret already exists (aestun.sh can install it)?
// Because zapret is built for the hard case: the far end is a website you do not control,
// so every fake packet nfqws injects must be crafted so the *real* server ignores it while
// the DPI is fooled. That constraint is what forces nfqws through NFQUEUE — it has to
// intercept the kernel's own outbound packets to graft fakes onto a flow it did not create.
// It costs a userspace round trip per carrier packet, an iptables/connbytes rule that has to
// be kept in sync with the listen port, and it can wedge on its raw-socket send buffer while
// systemd still calls it "active" (aestun.sh documents exactly this failure).
//
// aestun owns *both* ends of this flow. That changes everything. We already know the carrier
// 5-tuple because we opened it; we already learned the peer's hop count in dpilog from the
// TTL of its packets; and the peer's receive path already discards stray QUIC long-header
// datagrams safely (main.go), so a fake that happens to arrive cannot hurt the tunnel. So the
// injector needs none of nfqws' machinery. It opens one raw socket and, at flow start, sprays
// a handful of genuine-looking QUIC Initials sharing the carrier's exact 5-tuple, with a TTL
// tuned to die a hop or two before the peer.
//
// What that buys against DPI: a stateful classifier watching the flow from its first packet
// sees what looks like an ordinary QUIC connection opening to a real CDN (the Initial carries
// a real, decryptable ClientHello with a plausible SNI — the same builder the obfs layer
// uses). The fakes never reach the peer, so they poison the DPI's model of the flow without
// costing the tunnel anything. It is the `--dpi-desync=fake` idea, but the fake is emitted by
// the same program that owns the connection, at the exact moment the connection opens, using
// a hop count the tunnel measured rather than guessed.
//
// Honest limits. IPv4 only (raw IP_HDRINCL): the live deployments here are v4, and a v6 raw
// path with per-packet hop-limit control is enough extra complexity that shipping it untested
// would be worse than skipping it — a v6 peer disables the injector with a log line. Needs
// CAP_NET_RAW (the systemd unit grants it). And like every desync technique this raises the
// cost of classification; it is not a proof of anything. Off by default.
package main

import (
	"crypto/rand"
	"encoding/binary"
	"log"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// The configuration type (DesyncConfig) and its defaults live in tunnel.go, next to the
// rest of Config, so the OS-independent core stays free of this Linux-only file.

// ---------------------------------------------------------------------------
// hop-count guessing (ported from zapret's darkmagic.c, same well-known-TTL heuristic)
// ---------------------------------------------------------------------------

// hopCountGuess estimates how many hops away a host is from the TTL/hop-limit its packets
// arrive with, assuming the sender started from one of the three conventional defaults
// (255, 128, 64). Returns 0 when the value is not close enough to any of them to be sure.
func hopCountGuess(ttl uint8) uint8 {
	var orig uint8
	switch {
	case ttl > 223:
		orig = 255
	case ttl > 96 && ttl < 128:
		orig = 128
	case ttl > 32 && ttl < 64:
		orig = 64
	default:
		return 0
	}
	return orig - ttl
}

// clampTTL applies the autottl delta and the min/max clamp, returning 0 (meaning "no usable
// value, fall back to the fixed TTL") when the result would not actually die before the peer.
func clampTTL(hop uint8, delta, lo, hi int) uint8 {
	d := int(hop) + delta
	if d < lo {
		d = lo
	}
	if d > hi {
		d = hi
	}
	// A fake whose TTL is >= the hop count would reach the peer; the whole point is that it
	// should not. Refuse to emit one in that case (the caller uses the fixed fallback).
	if delta < 0 && uint8(d) >= hop {
		return 0
	}
	return uint8(d)
}

// ---------------------------------------------------------------------------
// checksums (internet checksum + UDP pseudo-header)
// ---------------------------------------------------------------------------

// inetChecksum folds the standard one's-complement sum over 16-bit big-endian words. The
// input is expected to already be in network byte order, so reading it big-endian is correct.
func inetChecksum(parts ...[]byte) uint16 {
	var sum uint32
	carry := false
	var hi byte
	for _, b := range parts {
		i := 0
		if carry {
			sum += uint32(hi)<<8 | uint32(b[0])
			i = 1
			carry = false
		}
		for ; i+1 < len(b); i += 2 {
			sum += uint32(b[i])<<8 | uint32(b[i+1])
		}
		if i < len(b) {
			hi = b[i]
			carry = true
		}
	}
	if carry {
		sum += uint32(hi) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// ---------------------------------------------------------------------------
// the injector
// ---------------------------------------------------------------------------

type desyncAgent struct {
	t   *Tunnel
	cfg DesyncConfig
	sni string

	fd      int        // raw IPv4 socket, or -1 when unavailable / disabled
	src     netip.Addr // our source IP toward the peer (IP_HDRINCL fills it, so we must know it)
	srcPort uint16     // the carrier's source port = our listen port

	splitOn  bool // fragment the fakes at the IP layer (split.go)
	splitPos int  // fragment position, bytes from the transport header

	fakesSent atomic.Uint64
}

// newDesyncAgent builds an injector for an IPv4 peer from the full config. Returns nil (with a
// log line) for any condition that makes injection impossible, so the caller can simply skip
// when it is nil.
func newDesyncAgent(t *Tunnel, cfg *Config) *desyncAgent {
	if !cfg.Desync.on() {
		return nil
	}
	peer, ok := t.getPeer()
	if !ok || !peer.Addr().Is4() {
		if ok {
			log.Printf("desync: peer is not IPv4; the native fake injector supports IPv4 only, disabling")
		} else {
			log.Printf("desync: peer address not yet known, disabling injector")
		}
		return nil
	}
	src, ok := localIPForPeer(peer)
	if !ok || !src.Is4() {
		log.Printf("desync: could not determine a local IPv4 source toward the peer, disabling")
		return nil
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		log.Printf("desync: raw socket unavailable (need CAP_NET_RAW): %v; disabling", err)
		return nil
	}
	// IPPROTO_RAW already implies IP_HDRINCL, but set it so the intent is explicit and the
	// behaviour is identical on kernels that do not default it on.
	_ = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1)

	sni := cfg.Desync.SNI
	if sni == "" {
		sni = cfg.SNI
	}
	if sni == "" {
		sni = "www.cloudflare.com"
	}

	if cfg.Hop.on() {
		// The injector pins the fake to the carrier's fixed source and destination ports so
		// it shares the real flow's 5-tuple. Port hopping moves those every epoch, so under
		// hop the match is only approximate — the fake still looks like a QUIC handshake to
		// the peer's host, which is most of its value, but it no longer rides the exact tuple.
		log.Printf("desync: note — port hopping is on, so the fake 5-tuple match is approximate")
	}
	a := &desyncAgent{
		t:       t,
		cfg:     cfg.Desync,
		sni:     sni,
		fd:      fd,
		src:     src,
		srcPort: listenPortOf(cfg.Listen),
	}
	if cfg.Split.on() {
		a.splitOn = true
		a.splitPos = cfg.Split.FragPos
		if a.splitPos <= 0 {
			a.splitPos = 24 // a sane default inside a 1200-byte Initial, multiple of 8
		}
	}
	return a
}

// listenPortOf pulls the port out of a "host:port" listen string, defaulting to 51820.
func listenPortOf(listen string) uint16 {
	_, portStr, err := net.SplitHostPort(listen)
	if err != nil {
		return 51820
	}
	p, err := strconv.Atoi(portStr)
	if err != nil || p <= 0 || p > 65535 {
		return 51820
	}
	return uint16(p)
}

// localIPForPeer asks the routing table which source address a datagram to the peer would
// leave from, without sending anything. connect() on a UDP socket resolves the route and
// binds the local address, which LocalAddr then reports.
func localIPForPeer(peer netip.AddrPort) (netip.Addr, bool) {
	c, err := net.Dial("udp", peer.String())
	if err != nil {
		return netip.Addr{}, false
	}
	defer c.Close()
	la, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.Addr{}, false
	}
	a, ok2 := netip.AddrFromSlice(la.IP)
	return a.Unmap(), ok2
}

// ttlFor decides the TTL for a fake: the autottl-derived value if the peer hop count is known
// and usable, otherwise the configured fixed TTL, otherwise a conservative fallback.
func (a *desyncAgent) ttlFor() uint8 {
	if a.cfg.AutoTTL != nil && *a.cfg.AutoTTL {
		if peerTTL := uint8(a.t.dpi.peerTTL.Load()); peerTTL != 0 {
			if hop := hopCountGuess(peerTTL); hop != 0 {
				if ttl := clampTTL(hop, a.cfg.Delta, a.cfg.MinTTL, a.cfg.MaxTTL); ttl != 0 {
					return ttl
				}
			}
		}
	}
	if a.cfg.TTL > 0 && a.cfg.TTL < 256 {
		return uint8(a.cfg.TTL)
	}
	return 8 // dies near most ISPs; a blind but reasonable default before the hop count is known
}

// buildRawFake wraps a QUIC Initial payload in a UDP+IPv4 datagram sharing the carrier's
// 5-tuple, at the given TTL, and returns the on-the-wire bytes ready for the raw socket.
func (a *desyncAgent) buildRawFake(payload []byte, ttl uint8, badsum bool) []byte {
	const ipHdr, udpHdr = 20, 8
	total := ipHdr + udpHdr + len(payload)
	pkt := make([]byte, total)

	src4 := a.src.As4()
	dst4 := mustPeer4(a.t)

	// --- IPv4 header ---
	pkt[0] = 0x45 // version 4, IHL 5
	pkt[1] = 0x00 // DSCP/ECN
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	binary.BigEndian.PutUint16(pkt[4:6], uint16(1+randUint16()&0x7fff)) // ip_id, non-zero
	pkt[6], pkt[7] = 0x40, 0x00                                         // flags=DF, no fragment offset
	pkt[8] = ttl
	pkt[9] = unix.IPPROTO_UDP
	copy(pkt[12:16], src4[:])
	copy(pkt[16:20], dst4[:])
	binary.BigEndian.PutUint16(pkt[10:12], inetChecksum(pkt[:ipHdr]))

	// --- UDP header ---
	u := pkt[ipHdr:]
	binary.BigEndian.PutUint16(u[0:2], a.srcPort)
	binary.BigEndian.PutUint16(u[2:4], peerPort(a.t))
	binary.BigEndian.PutUint16(u[4:6], uint16(udpHdr+len(payload)))
	copy(u[udpHdr:], payload)

	// UDP checksum over the pseudo-header + UDP header + payload.
	var pseudo [12]byte
	copy(pseudo[0:4], src4[:])
	copy(pseudo[4:8], dst4[:])
	pseudo[9] = unix.IPPROTO_UDP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(udpHdr+len(payload)))
	csum := inetChecksum(pseudo[:], u[:udpHdr+len(payload)])
	if csum == 0 {
		csum = 0xffff // a computed zero is transmitted as all-ones (RFC 768)
	}
	if badsum {
		csum ^= 0xbeef // deliberately wrong; the peer kernel drops it, some DPIs still parse it
		if csum == 0 {
			csum = 1
		}
	}
	binary.BigEndian.PutUint16(u[6:8], csum)
	return pkt
}

// sendBurst emits one round of fakes: `repeats` genuine-looking QUIC Initials, each with a
// fresh connection ID and packet number, all sharing the carrier 5-tuple, at the desync TTL.
func (a *desyncAgent) sendBurst() {
	if a == nil || a.fd < 0 {
		return
	}
	ttl := a.ttlFor()
	badsum := a.cfg.Badsum != nil && *a.cfg.Badsum
	dst := mustPeer4(a.t)
	sa := &unix.SockaddrInet4{Addr: dst}
	for i := 0; i < a.cfg.Repeats; i++ {
		dcid := make([]byte, 8)
		scid := make([]byte, 8)
		rand.Read(dcid)
		rand.Read(scid)
		payload, err := buildInitial(dcid, dcid, scid, buildClientHello(a.sni), true)
		if err != nil || payload == nil {
			continue
		}
		raw := a.buildRawFake(payload, ttl, badsum)
		if err := a.sendRawFake(raw, sa); err != nil {
			log.Printf("desync: raw send failed: %v", err)
			return
		}
		a.fakesSent.Add(1)
	}
	log.Printf("desync: sent %d fake QUIC Initial(s) ttl=%d badsum=%v (sni=%s)", a.cfg.Repeats, ttl, badsum, a.sni)
}

// run drives the injector: one burst as soon as the flow opens, a second calibrated burst
// once the peer hop count has actually been learned (so autottl is precise), and then an
// optional periodic re-burst. It never blocks the packet loops — it is its own goroutine.
func (a *desyncAgent) run() {
	if a == nil || a.fd < 0 {
		return
	}
	a.sendBurst() // best effort now, using the fixed/fallback TTL if the hop count is unknown

	// Wait briefly for dpilog to learn the peer hop count, then re-burst with a precise TTL.
	if a.cfg.AutoTTL != nil && *a.cfg.AutoTTL {
		for i := 0; i < 30; i++ {
			time.Sleep(time.Second)
			if a.t.dpi.peerTTL.Load() != 0 {
				a.sendBurst()
				break
			}
		}
	}

	if a.cfg.EverySec > 0 {
		tick := time.NewTicker(time.Duration(a.cfg.EverySec) * time.Second)
		defer tick.Stop()
		for range tick.C {
			a.sendBurst()
		}
	}
}

func (a *desyncAgent) close() {
	if a != nil && a.fd >= 0 {
		unix.Close(a.fd)
		a.fd = -1
	}
}

// --- small helpers ---------------------------------------------------------

func mustPeer4(t *Tunnel) [4]byte {
	p, _ := t.getPeer()
	return p.Addr().As4()
}

func peerPort(t *Tunnel) uint16 {
	p, _ := t.getPeer()
	return p.Port()
}

func randUint16() uint16 {
	var b [2]byte
	rand.Read(b[:])
	return binary.BigEndian.Uint16(b[:])
}
