//go:build linux

// Keyed, synchronised port hopping — a thing zapret structurally cannot do, because zapret
// tampers with a flow it does not own and cannot move it.
//
// The reference deployment hit this exact wall (README §13): an ISP blocked the precise
// source-port/destination-port pair the tunnel used, while the *same* random UDP from any
// other port went through untouched. The block was on the 5-tuple, not the host. Moving one
// end to a different port fixed it instantly — until, presumably, that pair gets blocked too.
//
// Port hopping turns that manual fix into an automatic, continuous one. Both ends derive the
// same port from the pre-shared key and the wall clock — exactly the mechanism the tunnel
// already uses to rotate epoch keys without a handshake — and step through a small agreed set
// of ports on a timer. There is nothing for a 5-tuple block to hold onto: by the time a pair
// is identified and blocked, the flow has moved. It also removes the fixed-port fingerprint a
// long-lived flow otherwise carries.
//
// How it stays reliable across the hop. Every port in the set is bound for the whole life of
// the process, on both ends. The schedule only decides which port each side *sends* from and
// to this epoch; because every socket is always listening, a packet that arrives a little
// early or a little late — clock skew, a datagram in flight across the boundary — still lands
// on a bound socket and is delivered. There is no rebind, so there is no handover gap and no
// race. Peers are matched by IP alone while hopping (the port is expected to change), so the
// rotation does not spuriously trip the roam detector.
//
// Cost, stated plainly. This mode runs one socket per port and sends one datagram per syscall
// — it forgoes the UDP segmentation offload the single-socket path uses, so peak throughput
// is lower. It is insurance against blocking, not a throughput feature. The operator must
// open the whole port set in the cloud/OS firewall on both ends. Off by default.
package main

import (
	"encoding/binary"
	"log"
	"net"
	"net/netip"
	"sync/atomic"
	"time"
)

// HopConfig (struct + defaults) lives in tunnel.go next to Config.

// hopEpoch is the current hop index over time: which slot of the schedule we are in now.
func hopEpoch(intervalSec uint64) uint64 {
	if intervalSec == 0 {
		intervalSec = 30
	}
	return uint64(time.Now().Unix()) / intervalSec
}

// hopIndex maps (key, epoch) to a port slot in [0, n). Derived from the PSK exactly like the
// epoch keys are, so both ends compute the same slot with no exchange. Independent of the
// port list itself, so reordering the list in config on one end only would desynchronise it —
// the two ends must carry the same ports in the same order (the installer writes both).
func hopIndex(psk []byte, epoch uint64, n int) int {
	if n <= 1 {
		return 0
	}
	info := append([]byte("aestun-hop "), make([]byte, 8)...)
	binary.BigEndian.PutUint64(info[len(info)-8:], epoch)
	out := hkdf(psk, nil, info, 2)
	return int(binary.BigEndian.Uint16(out)) % n
}

// hopMsg is one received datagram carried from a per-socket reader to the single Recv caller.
type hopMsg struct {
	pkt []byte
	src netip.AddrPort
	ttl uint8
}

// hopCarrier owns one UDP socket per port in the set and presents them to the tunnel as a
// single carrier. It sends from and to the current epoch's port; it receives from all of them.
type hopCarrier struct {
	t        *Tunnel
	psk      []byte
	ports    []uint16
	interval uint64
	conns    []*net.UDPConn
	rx       chan hopMsg
	closed   atomic.Bool

	// Shapes bulk traffic only; owned by the TUN pump, which is single-threaded.
	pacer *pacer

	// Cache the current epoch's port slot so the send path does not run HKDF per packet.
	// hopIndex is HMAC-SHA256 extract+expand; at a few thousand packets a second that would
	// dominate the mode's CPU for a value that changes only once per interval. The epoch is
	// packed with the slot into one 64-bit word so a reader sees a consistent pair without a
	// lock: high 32 bits = epoch (mod 2^32), low 32 bits = slot.
	slotCache atomic.Uint64
	haveSlot  atomic.Bool
}

// newHopCarrier binds every port in the set on 0.0.0.0 and starts a reader per socket. A bind
// failure is fatal to the mode (not the process): the caller falls back to the single socket.
func newHopCarrier(cfg *Config, t *Tunnel, rcvbuf, sndbuf int, wantTTL bool) (*hopCarrier, error) {
	h := &hopCarrier{
		t:        t,
		psk:      t.psk,
		ports:    normalizeHopPorts(cfg.Hop.Ports),
		interval: cfg.Hop.Interval,
		rx:       make(chan hopMsg, 1024),
	}
	if h.interval == 0 {
		h.interval = 30
	}
	for _, p := range h.ports {
		conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: int(p)})
		if err != nil {
			for _, c := range h.conns {
				c.Close()
			}
			return nil, err
		}
		conn.SetReadBuffer(rcvbuf)
		conn.SetWriteBuffer(sndbuf)
		if wantTTL {
			enableTTLInfo(conn)
		}
		// GRO batches the receive side: one recvmsg can return many coalesced datagrams, which
		// is what keeps the heavy-receive end (the far server draining bulk traffic) from paying
		// a syscall per packet. Send-side segmentation offload is still forgone in this mode.
		enableGRO(conn)
		h.conns = append(h.conns, conn)
	}
	for _, c := range h.conns {
		go h.recvLoop(c)
	}
	if cfg.RateMbps > 0 {
		h.pacer = newPacer(cfg.RateMbps)
		log.Printf("carrier shaped to %.0f Mbit/s", cfg.RateMbps)
	}
	log.Printf("port hopping active: ports=%v interval=%ds (offload disabled in this mode)", h.ports, h.interval)
	return h, nil
}

func (h *hopCarrier) recvLoop(conn *net.UDPConn) {
	buf := make([]byte, maxPktSize) // per-goroutine scratch for the recvmsg
	oob := make([]byte, 256)
	for {
		n, oobn, _, src, err := conn.ReadMsgUDPAddrPort(buf, oob)
		if err != nil {
			if h.closed.Load() {
				return
			}
			time.Sleep(readErrBackoff)
			continue
		}
		addr, ttl := normAddr(src), parseTTL(oob[:oobn])
		seg := parseGROSegment(oob[:oobn])
		if seg <= 0 || seg >= n {
			seg = n // not coalesced: the whole buffer is one datagram
		}
		// GRO can return several datagrams from one recvmsg; hand each to the consumer. The
		// per-segment copy is unavoidable (the scratch is reused on the next read) but cheap
		// next to the syscall the batch shared.
		for off := 0; off < n; off += seg {
			end := off + seg
			if end > n {
				end = n
			}
			pkt := make([]byte, end-off)
			copy(pkt, buf[off:end])
			select {
			case h.rx <- hopMsg{pkt: pkt, src: addr, ttl: ttl}:
			default:
				// The receive side fell behind; dropping a carrier datagram costs only an
				// inner retransmission, and blocking a reader would stall every other port too.
			}
		}
	}
}

// currentSlot returns the port slot for the current epoch, deriving it via HKDF only when the
// epoch has actually advanced and returning the cached value on every packet in between.
func (h *hopCarrier) currentSlot() int {
	ep := hopEpoch(h.interval)
	if h.haveSlot.Load() {
		if c := h.slotCache.Load(); uint32(c>>32) == uint32(ep) {
			return int(uint32(c))
		}
	}
	idx := hopIndex(h.psk, ep, len(h.ports))
	h.slotCache.Store(uint64(uint32(ep))<<32 | uint64(uint32(idx)))
	h.haveSlot.Store(true)
	return idx
}

func (h *hopCarrier) sendConn() (*net.UDPConn, netip.AddrPort, bool) {
	peer, ok := h.t.getPeer()
	if !ok {
		return nil, netip.AddrPort{}, false
	}
	idx := h.currentSlot()
	dst := netip.AddrPortFrom(peer.Addr(), h.ports[idx])
	return h.conns[idx], dst, true
}

func (h *hopCarrier) Send(pkt []byte) error {
	conn, dst, ok := h.sendConn()
	if !ok {
		return nil // peer not known yet
	}
	_, err := conn.WriteToUDPAddrPort(pkt, dst)
	return err
}

func (h *hopCarrier) Recv() ([]byte, netip.AddrPort, uint8, error) {
	m, ok := <-h.rx
	if !ok {
		return nil, netip.AddrPort{}, 0, net.ErrClosed
	}
	return m.pkt, m.src, m.ttl, nil
}

func (h *hopCarrier) Close() error {
	if h.closed.CompareAndSwap(false, true) {
		for _, c := range h.conns {
			c.Close()
		}
	}
	return nil
}

// normalizeHopPorts drops zero/duplicate ports and guarantees at least one usable entry so the
// mode never binds nothing. Order is preserved, because hopIndex depends on it.
func normalizeHopPorts(in []int) []uint16 {
	seen := map[uint16]bool{}
	var out []uint16
	for _, p := range in {
		if p <= 0 || p > 65535 {
			continue
		}
		u := uint16(p)
		if seen[u] {
			continue
		}
		seen[u] = true
		out = append(out, u)
	}
	if len(out) == 0 {
		out = []uint16{51820}
	}
	return out
}
