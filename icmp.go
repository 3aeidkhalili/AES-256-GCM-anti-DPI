//go:build linux

// ICMP carrier.
//
// This exists because of a measurement, not a theory. On the link this was written for —
// a European VPS to a Tehran VPS — the path does something a policer does not:
//
//	protocol            offered      delivered    loss     outages
//	TCP (any port)          n/a       0.07-1.3 Mbit/s   500+ retransmits/15s
//	UDP (any port)      0.5 Mbit/s    0.30 Mbit/s   40.8%   ~94 ms every ~345 ms
//	UDP (any port)       40 Mbit/s     23.2 Mbit/s   42.5%   ~94 ms every ~345 ms
//	ICMP echo            30 Mbit/s     30.4 Mbit/s    0.4%   none
//
// The UDP loss is flat across two orders of magnitude of offered rate, so it is not
// congestion and not a policer — shaping cannot help, because there is no threshold to
// stay under. It arrives as blackouts: the path swallows every datagram for ~94 ms, then
// passes everything for ~250 ms, and repeats. Sampled across four flows on four different
// source and destination port pairs, those dead windows coincide with Jaccard 0.96-0.97,
// so the blackout is a property of the path and not of the flow. Port hopping, striping
// across sockets and rotating the 5-tuple all move traffic from one blocked window into
// the same blocked window.
//
// ICMP echo crosses the same path, at the same moment, at 30 Mbit/s with 0.4% loss and no
// blackout at all. So carry the tunnel in ping payloads.
//
// Three details make it work rather than merely look like it should:
//
// Echo *requests* (type 8) both ways, never replies. An unsolicited echo reply is dropped
// somewhere on this path — measured, 100% of 37500 — because a stateful middlebox has no
// request to match it to. A request is not a response to anything, so nothing has to
// remember it. Both ends therefore send requests and neither expects an answer.
//
// Which means the peer's kernel answers them. Every data packet would draw an echo reply
// carrying a copy of the payload back the way it came: the reverse direction's bandwidth,
// spent on nothing, and a volumetric signature no real ping ever has. suppressReplies
// installs one firewall rule to drop those replies before they leave. It matches on the
// ICMP identifier, so only this tunnel's pings go unanswered and ordinary ping to the peer
// keeps working — that diagnostic is worth an iptables extension test to keep.
//
// And a raw socket is not a UDP socket. It sees every ICMP message the host receives, it
// has no equivalent of GSO/GRO, and it costs one syscall per packet in each direction.
// Three things close that gap, in descending order of how much they were worth:
//
//   - a classic BPF filter attached to the socket, so the kernel queues only this tunnel's
//     echo requests and a ping flood aimed at the host cannot evict carrier data from the
//     receive buffer;
//   - sendmmsg/recvmmsg (mmsg.go), so a busy link pays one syscall per batch rather than
//     one per packet — measured, a single unbatched reader at 400 Mbit/s lost 22829 packets
//     to receive-buffer overflow while the path itself delivered 99.5% of them;
//   - several receive goroutines, because a reader also has to decrypt and write to the TUN
//     before it can come back around to the socket.
//
// Everything past that is opt-in and changes the wire, so it has to be set on both ends:
// identifier rotation (icmp.id_pool) and ping mimicry (icmp.mimic_ping).
package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

const (
	icmpEchoRequest = 8
	icmpHdrLen      = 8
	// ipv4MinHdr is the smallest legal IPv4 header; a received raw packet shorter than
	// this cannot be parsed for its real length, so it is not ours.
	ipv4MinHdr = 20
	// icmpMimicLen is the plaintext prefix added by mimic_ping: the struct timeval that
	// iputils' ping writes at the start of its payload, in the host's own 64-bit layout.
	icmpMimicLen = 16
	// icmpMaxIDPool bounds the identifier rotation set. Every identifier in it costs one
	// BPF comparison per received packet and one firewall rule, and a wider set buys
	// nothing a narrow one does not.
	icmpMaxIDPool = 8
	// icmpMaxBatch bounds messages per sendmmsg/recvmmsg. The kernel's own ceiling is
	// UIO_MAXIOV (1024); past a few tens the batch stops being the thing that costs.
	icmpMaxBatch = 64
)

// icmpCarrier moves sealed datagrams as ICMP echo request payloads over a raw socket.
//
// Safe for concurrent Send: the TUN pump, the keepalive loop, the probe agent and the junk
// burst all share one carrier. The sequence counter is atomic and the two pieces of shared
// mutable state take a lock each — the single-packet scratch buffer, and the pacer, which
// is documented single-threaded. They are deliberately separate locks: the batched TUN pump
// never touches the scratch buffer, so a keepalive can never wait behind a full batch.
type icmpCarrier struct {
	fd int
	t  *Tunnel

	scratchMu sync.Mutex
	scratch   []byte

	paceMu sync.Mutex
	pacer  *pacer

	seq atomic.Uint32

	buf []byte // backs the carrier-interface Recv; the parallel readers each own theirs

	// Every identifier this tunnel may stamp or accept. One entry unless id_pool asked for
	// rotation; the receive side (and the BPF filter, and the firewall rules) always covers
	// the whole set, so a packet in flight across an epoch boundary is never dropped.
	ids       []uint16
	rotateSec int
	slotCache atomic.Uint64 // epoch<<32 | slot, as in hop.go
	haveSlot  atomic.Bool

	mimic    bool // prepend a ping(8)-style timestamp to every payload
	batch    int  // messages per sendmmsg/recvmmsg; 1 disables batching
	slotSize int  // per-message buffer size in a batch, derived from the MTU

	suppress func() // undoes the echo-reply rule(s), or nil if none was installed
	closed   atomic.Bool
	truncs   atomic.Uint64 // receives the kernel had to truncate; an MTU/config mismatch
}

// icmpChecksum is the standard internet checksum over the ICMP message. The kernel fills
// this in for UDP and TCP but not for raw ICMP, so it has to be right here or the peer's
// kernel discards the packet before any socket sees it.
func icmpChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// icmpIDSet derives the identifier set from the pre-shared key, so the two ends agree on it
// without another config field and two unrelated tunnels between the same pair of hosts do
// not read each other's packets. An identifier is not a secret — it travels in clear in
// every header — and nothing is trusted because of it; authentication is still the AEAD's
// job. It only has to be stable, agreed, and unlikely to collide.
//
// A pool larger than one is identifier rotation: the same idea as hop.go's port hopping,
// applied to the one field an ICMP flow has to key on. A middlebox that learns to rate-limit
// or drop "the ping with identifier 0x8D94" has to learn the whole set, and by then the
// schedule has moved. Both ends must configure the same pool size, because the set is
// derived from it.
//
// The derivation is HKDF over the key rather than the key's own first two bytes, which is
// what the very first version of this carrier used. That earlier form leaked two bytes of
// the pre-shared key into the clear on every packet — recoverable, harmless to the AEAD, and
// still not something to put on the wire — and it has no natural way to produce a *set*.
// A peer still running that form is reached by pinning icmp.id to its identifier explicitly,
// which is exactly what that field is for.
func icmpIDSet(psk []byte, n int) []uint16 {
	if n < 1 {
		n = 1
	}
	if n > icmpMaxIDPool {
		n = icmpMaxIDPool
	}
	// Draw generously and skip collisions, so the set really has n distinct members.
	raw := hkdf(psk, nil, []byte("aestun-icmp-id"), 4*n+8)
	out := make([]uint16, 0, n)
	for i := 0; i+1 < len(raw) && len(out) < n; i += 2 {
		id := binary.BigEndian.Uint16(raw[i : i+2])
		if id == 0 {
			continue // 0 is what a socket that never set one uses; stay off it
		}
		dup := false
		for _, o := range out {
			if o == id {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, id)
		}
	}
	if len(out) == 0 {
		out = []uint16{1}
	}
	return out
}

// currentID is the identifier to stamp on outgoing packets right now. With a single-entry
// set this is a constant; with rotation on it steps through the set on a keyed schedule
// both ends compute independently, exactly as the epoch keys and the hop ports do.
func (i *icmpCarrier) currentID() uint16 {
	if len(i.ids) == 1 || i.rotateSec <= 0 {
		return i.ids[0]
	}
	ep := uint64(time.Now().Unix()) / uint64(i.rotateSec)
	if i.haveSlot.Load() {
		if c := i.slotCache.Load(); uint32(c>>32) == uint32(ep) {
			return i.ids[uint32(c)]
		}
	}
	// hopIndex is the same keyed (key, epoch) -> slot derivation port hopping uses; sharing
	// it means the two schedules cannot drift apart in their implementations.
	idx := hopIndex(i.t.psk, ep, len(i.ids))
	i.slotCache.Store(uint64(uint32(ep))<<32 | uint64(uint32(idx)))
	i.haveSlot.Store(true)
	return i.ids[idx]
}

// knownID reports whether an identifier belongs to this tunnel. The BPF filter already
// rejects everything else in the kernel; this is the userspace backstop for the case where
// the filter could not be attached.
func (i *icmpCarrier) knownID(id uint16) bool {
	for _, v := range i.ids {
		if v == id {
			return true
		}
	}
	return false
}

// buildMessage writes one complete ICMP echo request carrying pkt into dst, and returns the
// message. dst must have room for the header, the mimicry prefix and the payload.
func (i *icmpCarrier) buildMessage(dst, pkt []byte) []byte {
	n := icmpHdrLen + len(pkt)
	if i.mimic {
		n += icmpMimicLen
	}
	b := dst[:n]
	b[0], b[1] = icmpEchoRequest, 0
	b[2], b[3] = 0, 0 // checksum zero while computing it
	binary.BigEndian.PutUint16(b[4:6], i.currentID())
	binary.BigEndian.PutUint16(b[6:8], uint16(i.seq.Add(1)))
	body := b[icmpHdrLen:]
	if i.mimic {
		// What iputils' ping puts at the start of its payload: a struct timeval in native
		// byte order, which is what makes tcpdump and every ICMP dissector render this as
		// an ordinary ping with a plausible round-trip time instead of an opaque blob.
		now := time.Now()
		binary.NativeEndian.PutUint64(body[0:8], uint64(now.Unix()))
		binary.NativeEndian.PutUint64(body[8:16], uint64(now.Nanosecond()/1000))
		body = body[icmpMimicLen:]
	}
	copy(body, pkt)
	binary.BigEndian.PutUint16(b[2:4], icmpChecksum(b))
	return b
}

// msgOverhead is what buildMessage adds to a sealed datagram.
func (i *icmpCarrier) msgOverhead() int {
	if i.mimic {
		return icmpHdrLen + icmpMimicLen
	}
	return icmpHdrLen
}

func (i *icmpCarrier) pace(n int) {
	if i.pacer == nil {
		return
	}
	i.paceMu.Lock()
	i.pacer.wait(n)
	i.paceMu.Unlock()
}

func (i *icmpCarrier) Send(pkt []byte) error {
	peer, ok := i.t.getPeer()
	if !ok {
		return nil // peer address not known yet; nothing to do but drop
	}
	a4 := peer.Addr().As4()

	if n := len(pkt) + i.msgOverhead(); n > maxPktSize {
		return fmt.Errorf("icmp: packet too large: %d", n)
	}
	i.pace(len(pkt) + i.msgOverhead())

	i.scratchMu.Lock()
	b := i.buildMessage(i.scratch, pkt)
	err := unix.Sendto(i.fd, b, 0, &unix.SockaddrInet4{Addr: a4})
	i.scratchMu.Unlock()
	return err
}

// Recv satisfies the carrier interface for the single-reader callers. The data path uses
// recvInto or the batched loop instead, once per reader goroutine, because this one shares
// a single buffer.
func (i *icmpCarrier) Recv() ([]byte, netip.AddrPort, uint8, error) {
	return i.recvInto(i.buf)
}

// parse turns one raw received packet (IP header included, as raw(7) delivers it) into the
// sealed datagram it carries, or ok=false when it is not ours. A raw IPPROTO_ICMP socket
// sees every ICMP message the host receives — other people's pings, unreachables, the
// peer's kernel echo replies — and with the BPF filter unavailable all of that lands here,
// so everything that is not ours is dropped rather than handed up as a packet that fails to
// authenticate and pollutes the DPI log.
func (i *icmpCarrier) parse(buf []byte, n int) (pkt []byte, ttl uint8, ok bool) {
	if n < ipv4MinHdr {
		return nil, 0, false
	}
	ihl := int(buf[0]&0x0F) * 4
	if ihl < ipv4MinHdr || n < ihl+icmpHdrLen {
		return nil, 0, false
	}
	msg := buf[ihl:n]
	if msg[0] != icmpEchoRequest {
		return nil, 0, false // replies, unreachables, redirects — none carry our data
	}
	if !i.knownID(binary.BigEndian.Uint16(msg[4:6])) {
		return nil, 0, false // somebody else's ping
	}
	body := msg[icmpHdrLen:]
	if i.mimic {
		if len(body) < icmpMimicLen {
			return nil, 0, false
		}
		body = body[icmpMimicLen:] // the timestamp is cover, not data
	}
	return body, buf[8], true
}

// recvInto returns the next echo request carrying one of this tunnel's identifiers.
//
// Safe to call concurrently from several goroutines as long as each passes its own buffer:
// recvfrom on a shared socket is atomic per datagram, and nothing else here is shared.
func (i *icmpCarrier) recvInto(buf []byte) ([]byte, netip.AddrPort, uint8, error) {
	for {
		n, from, err := unix.Recvfrom(i.fd, buf, 0)
		if err != nil {
			if i.closed.Load() {
				return nil, netip.AddrPort{}, 0, net.ErrClosed
			}
			if err == unix.EINTR {
				continue
			}
			return nil, netip.AddrPort{}, 0, err
		}
		pkt, ttl, ok := i.parse(buf, n)
		if !ok {
			continue
		}
		sa, ok := from.(*unix.SockaddrInet4)
		if !ok {
			continue
		}
		// Port 0 throughout: ICMP has no ports, and the peer is stored the same way, so
		// samePeer compares equal instead of reporting a roam on every single packet.
		return pkt, netip.AddrPortFrom(netip.AddrFrom4(sa.Addr), 0), ttl, nil
	}
}

func (i *icmpCarrier) Close() error {
	if !i.closed.CompareAndSwap(false, true) {
		return nil
	}
	if i.suppress != nil {
		i.suppress()
	}
	return unix.Close(i.fd)
}

// ---------------------------------------------------------------------------
// socket setup
// ---------------------------------------------------------------------------

// newICMPCarrier opens the raw socket. This needs CAP_NET_RAW; the service unit already runs
// as root, but the error is worth naming because it is the one thing that makes this
// transport fail on an otherwise fine host.
func newICMPCarrier(cfg *Config, t *Tunnel) *icmpCarrier {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP)
	if err != nil {
		log.Fatalf("opening raw ICMP socket failed: %v\n"+
			"transport \"icmp\" needs CAP_NET_RAW (run as root, or grant the binary "+
			"CAP_NET_RAW with setcap).", err)
	}
	setRawBuffers(fd, cfg.RcvBuf, cfg.SndBuf)

	ic := &cfg.ICMP
	c := &icmpCarrier{
		fd:        fd,
		t:         t,
		scratch:   make([]byte, maxPktSize),
		buf:       make([]byte, maxPktSize),
		rotateSec: ic.IDRotateSec,
		mimic:     ic.MimicPing != nil && *ic.MimicPing,
		batch:     derefOr(ic.Batch, 32),
	}
	if c.batch < 1 {
		c.batch = 1
	}
	if c.batch > icmpMaxBatch {
		c.batch = icmpMaxBatch
	}
	if !mmsgOK {
		log.Printf("warning: mmsghdr layout unrecognised on this architecture; " +
			"batching disabled, one packet per syscall")
		c.batch = 1
	}
	// Batch slots are sized from the MTU rather than from the 64 KiB ceiling: 64 slots of
	// 64 KiB per goroutine would be 4 MiB of buffer for packets that cannot occur. The
	// margin covers the inner header, the padding and the ICMP/mimicry overhead, and a
	// receive that still does not fit is counted and reported rather than silently corrupted.
	c.slotSize = cfg.MTU + 512
	if c.slotSize < 1600 {
		c.slotSize = 1600
	}
	if c.slotSize > maxPktSize {
		c.slotSize = maxPktSize
	}

	if ic.ID > 0 && ic.ID <= 0xFFFF {
		// An explicitly configured identifier is a fixed one: rotation would contradict it.
		c.ids = []uint16{uint16(ic.ID)}
	} else {
		c.ids = icmpIDSet(t.psk, ic.IDPool)
	}
	if len(c.ids) > 1 {
		log.Printf("icmp identifier rotation: %d identifiers, one every %ds (must match on BOTH servers)",
			len(c.ids), c.rotateSec)
	}

	if derefOr2(ic.KernelFilter, true) {
		if err := attachICMPFilter(fd, c.ids); err != nil {
			log.Printf("warning: could not attach the kernel packet filter (%v); every ICMP "+
				"message on this host will be queued to the carrier socket and filtered in "+
				"userspace instead", err)
		}
	}

	// Publish the socket inode so the DPI observer can read this socket's own drop counter
	// out of /proc/net/raw — the only place a raw socket's receive-buffer overflow is visible.
	var st unix.Stat_t
	if unix.Fstat(fd, &st) == nil {
		t.dpi.rawInode.Store(uint64(st.Ino))
	}

	if cfg.RateMbps > 0 {
		c.pacer = newPacer(cfg.RateMbps)
		log.Printf("carrier shaped to %.0f Mbit/s", cfg.RateMbps)
	}
	return c
}

// setRawBuffers sizes the socket buffers, trying the privileged form first. SO_RCVBUF is
// clamped to net.core.rmem_max; SO_RCVBUFFORCE (CAP_NET_ADMIN) is not, which matters here
// because the raw receive path has no GRO to fall back on and a burst that overflows this
// buffer is lost on the host rather than on the network.
func setRawBuffers(fd, rcv, snd int) {
	if unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, rcv) != nil {
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, rcv); err != nil {
			log.Printf("warning: SO_RCVBUF(%d) failed: %v", rcv, err)
		}
	}
	if unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, snd) != nil {
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, snd); err != nil {
			log.Printf("warning: SO_SNDBUF(%d) failed: %v", snd, err)
		}
	}
}

// --- kernel packet filter --------------------------------------------------

// Classic-BPF opcodes, from linux/filter.h. Spelled out rather than pulled from a
// dependency: the program below is nine-ish instructions and a BPF assembler would be more
// code than the thing it assembles.
const (
	bpfLdxBMsh = 0xb1 // BPF_LDX|BPF_B|BPF_MSH  — X = 4 * (P[k] & 0xf)
	bpfLdBInd  = 0x50 // BPF_LD|BPF_B|BPF_IND   — A = P[X+k]
	bpfLdHInd  = 0x48 // BPF_LD|BPF_H|BPF_IND   — A = P[X+k], 16-bit big-endian
	bpfJeqK    = 0x15 // BPF_JMP|BPF_JEQ|BPF_K
	bpfRetK    = 0x06 // BPF_RET|BPF_K
)

// attachICMPFilter makes the kernel drop everything that is not this tunnel's traffic before
// it is ever queued to the socket.
//
// Without it the socket receives every ICMP message the host sees. That is not only wasted
// wakeups: the receive buffer is a fixed budget, and a ping flood aimed at this host — or
// simply a busy machine — evicts carrier packets that already crossed the network. The
// filter also removes the whole class of DPI-log noise from other people's pings.
//
// A raw socket's filter runs over the packet starting at the IP header, so the program reads
// the header length out of byte 0 and indexes the ICMP header from there.
func attachICMPFilter(fd int, ids []uint16) error {
	n := len(ids)
	prog := make([]unix.SockFilter, 0, 6+n)
	// 0: X = IPv4 header length
	prog = append(prog, unix.SockFilter{Code: bpfLdxBMsh, K: 0})
	// 1: A = ICMP type
	prog = append(prog, unix.SockFilter{Code: bpfLdBInd, K: 0})
	// 2: echo request, or reject. Reject sits at index 4+n, so the jump-if-false distance
	//    from the instruction after this one is (4+n) - 3 = n+1.
	prog = append(prog, unix.SockFilter{Code: bpfJeqK, Jt: 0, Jf: uint8(n + 1), K: icmpEchoRequest})
	// 3: A = ICMP identifier
	prog = append(prog, unix.SockFilter{Code: bpfLdHInd, K: 4})
	// 4..3+n: one comparison per identifier. Comparison i sits at index 4+i, so its jump is
	//         measured from 5+i; accept is at index 5+n, hence a distance of n-i. A miss
	//         falls through to the next comparison, and the last one falls through to
	//         reject at index 4+n.
	for i := range ids {
		prog = append(prog, unix.SockFilter{Code: bpfJeqK, Jt: uint8(n - i), Jf: 0, K: uint32(ids[i])})
	}
	prog = append(prog, unix.SockFilter{Code: bpfRetK, K: 0})           // reject
	prog = append(prog, unix.SockFilter{Code: bpfRetK, K: 0x0004_0000}) // accept, up to 256 KiB

	fprog := &unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	return unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, fprog)
}

// ---------------------------------------------------------------------------
// echo-reply suppression
// ---------------------------------------------------------------------------

// suppressReplies stops this host's kernel from answering the peer's data pings.
//
// Preferred form matches the ICMP identifier with iptables' u32 extension, so exactly this
// tunnel's pings go unanswered and an ordinary ping between the two servers still works.
// The u32 offset arithmetic reads: take the IP header length from byte 0 (0>>22&0x3C),
// read the 32-bit word at ICMP offset 4 (identifier and sequence), keep the top half (>>16)
// — the identifier — and compare. Where the extension is missing, fall back to dropping
// every echo reply to the peer, which costs the ping diagnostic but never the bandwidth.
// Where iptables is missing entirely, do the same two steps with nft.
//
// The returned function removes whatever was installed. runICMP calls it on SIGTERM as well
// as on a clean exit, so `systemctl stop aestun` leaves ping to the peer working again.
func suppressReplies(peer netip.Addr, ids []uint16) func() {
	dst := peer.String()
	if _, err := exec.LookPath("iptables"); err == nil {
		if undo := suppressIPTables(dst, ids); undo != nil {
			return undo
		}
	}
	if _, err := exec.LookPath("nft"); err == nil {
		if undo := suppressNFT(dst, ids); undo != nil {
			return undo
		}
	}
	log.Printf("warning: no usable firewall tool (iptables/nft) — the kernel will answer the " +
		"peer's data pings and echo the payload back, roughly doubling reverse-path traffic")
	return nil
}

func suppressIPTables(dst string, ids []uint16) func() {
	base := func(extra ...string) []string {
		spec := []string{"OUTPUT", "-p", "icmp", "--icmp-type", "echo-reply", "-d", dst}
		spec = append(spec, extra...)
		return append(spec, "-m", "comment", "--comment", "aestun icmp carrier", "-j", "DROP")
	}
	// Per-identifier rules first; the catch-all is the fallback for a kernel or build
	// without the u32 match.
	var specs [][]string
	for _, id := range ids {
		specs = append(specs, base("-m", "u32", "--u32", fmt.Sprintf("0>>22&0x3C@4>>16=0x%X", id)))
	}
	if applyIPTables(specs) {
		log.Printf("suppressing kernel echo replies to %s for %d identifier(s) "+
			"(ordinary ping to the peer still works)", dst, len(ids))
		return func() { removeIPTables(specs) }
	}
	all := [][]string{base()}
	if applyIPTables(all) {
		log.Printf("suppressing all kernel echo replies to %s — the u32 match was "+
			"unavailable, so ping between the two servers will not answer", dst)
		return func() { removeIPTables(all) }
	}
	return nil
}

// applyIPTables installs every rule in specs, undoing the ones it managed on any failure so
// a half-applied set is never left behind. A rule that is already present (systemd restarts
// leave the previous one in place) counts as installed rather than being appended twice.
func applyIPTables(specs [][]string) bool {
	var done [][]string
	for _, spec := range specs {
		if exec.Command("iptables", append([]string{"-w", "-C"}, spec...)...).Run() == nil {
			continue // already there from a previous run
		}
		if exec.Command("iptables", append([]string{"-w", "-A"}, spec...)...).Run() != nil {
			removeIPTables(done)
			return false
		}
		done = append(done, spec)
	}
	return true
}

func removeIPTables(specs [][]string) {
	for _, spec := range specs {
		if err := exec.Command("iptables", append([]string{"-w", "-D"}, spec...)...).Run(); err != nil {
			log.Printf("warning: removing echo-reply rule failed: %v", err)
		}
	}
}

// suppressNFT is the nftables path, for hosts that ship nft without the iptables wrappers.
// Everything goes in a table of our own, so cleanup is one command and cannot disturb
// anybody else's ruleset.
func suppressNFT(dst string, ids []uint16) func() {
	run := func(args ...string) error { return exec.Command("nft", args...).Run() }
	_ = run("delete", "table", "ip", "aestun") // clear a table left by a previous run
	if run("add", "table", "ip", "aestun") != nil {
		return nil
	}
	if run("add", "chain", "ip", "aestun", "output", "{ type filter hook output priority 0 ; }") != nil {
		_ = run("delete", "table", "ip", "aestun")
		return nil
	}
	ok := true
	for _, id := range ids {
		if run("add", "rule", "ip", "aestun", "output", "ip", "daddr", dst,
			"icmp", "type", "echo-reply", "icmp", "id", fmt.Sprintf("%d", id), "drop") != nil {
			ok = false
			break
		}
	}
	if !ok {
		// No per-identifier match available: one rule for every echo reply to the peer.
		_ = run("flush", "chain", "ip", "aestun", "output")
		if run("add", "rule", "ip", "aestun", "output", "ip", "daddr", dst,
			"icmp", "type", "echo-reply", "drop") != nil {
			_ = run("delete", "table", "ip", "aestun")
			return nil
		}
		log.Printf("suppressing all kernel echo replies to %s via nft — ping between the "+
			"two servers will not answer", dst)
	} else {
		log.Printf("suppressing kernel echo replies to %s via nft for %d identifier(s) "+
			"(ordinary ping to the peer still works)", dst, len(ids))
	}
	return func() {
		if err := run("delete", "table", "ip", "aestun"); err != nil {
			log.Printf("warning: removing the nft echo-reply table failed: %v", err)
		}
	}
}

// ---------------------------------------------------------------------------
// native desync for the ICMP carrier
// ---------------------------------------------------------------------------

// icmpDesyncAgent is the ICMP carrier's answer to zapret's --dpi-desync=fake, and to the
// UDP carrier's injector in desync.go.
//
// It exists because nfqws structurally cannot help here. zapret desyncs TCP and UDP flows
// through NFQUEUE; it has no ICMP mode, so on this carrier it arms rules that match nothing
// and reports itself active while doing nothing at all. The same is true of desync.go, which
// grafts a fake QUIC Initial onto the carrier's UDP 5-tuple — there is no such tuple here.
//
// What a fake should look like is also different. On a UDP carrier the decoy is a QUIC
// handshake, because that is what a plausible flow to that port would open with. On this
// carrier the flow *is* ping, and the anomaly is not its protocol but its shape: a real ping
// is 64 bytes on the wire at one packet a second, and this one is full-MTU packets at tens of
// thousands a second. So the decoy is an ordinary ping — the exact 56-byte payload iputils
// sends, with the same identifier as the carrier so it belongs to the same conversation.
//
// A stateful classifier watching from the first packet then sees an ordinary ping session
// that later grows, rather than one born at hundreds of megabits. The fakes carry a TTL tuned
// to expire a hop or two short of the peer (the hop count the DPI observer already learned
// from the peer's own packets), so they never arrive, cost the peer nothing, and cannot be
// confused with data. Off by default, like every desync module.
type icmpDesyncAgent struct {
	c   *icmpCarrier
	t   *Tunnel
	cfg DesyncConfig
	fd  int
	src netip.Addr
}

// newICMPDesyncAgent returns nil (with a log line) for any condition that makes injection
// impossible, so the caller can simply skip when it is nil.
func newICMPDesyncAgent(t *Tunnel, c *icmpCarrier, cfg *Config) *icmpDesyncAgent {
	peer, ok := t.getPeer()
	if !ok || !peer.Addr().Is4() {
		log.Printf("desync: no IPv4 peer yet; the ICMP fake injector is disabled")
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
	_ = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1)
	return &icmpDesyncAgent{c: c, t: t, cfg: cfg.Desync, fd: fd, src: src}
}

// ttlFor picks the TTL for a fake: derived from the peer's learned hop count when autottl is
// on and that count is known, otherwise the configured fixed value, otherwise a blind but
// conservative default. Identical policy to the UDP injector, so the two behave alike.
func (a *icmpDesyncAgent) ttlFor() uint8 {
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
	return 8
}

// pingPayload fills b with what iputils' ping sends: a timeval, then the incrementing byte
// pattern 0x10 0x11 0x12 ... that every default ping on the internet carries.
func pingPayload(b []byte) {
	now := time.Now()
	if len(b) >= 16 {
		binary.NativeEndian.PutUint64(b[0:8], uint64(now.Unix()))
		binary.NativeEndian.PutUint64(b[8:16], uint64(now.Nanosecond()/1000))
		for i := 16; i < len(b); i++ {
			b[i] = byte(i)
		}
		return
	}
	for i := range b {
		b[i] = byte(i)
	}
}

// icmpFakeBodyLen is ping's default payload size: `ping` sends -s 56, which is 64 bytes on
// the wire once the 8-byte ICMP header is added. Anything else would be the one measurement
// that separates the decoy from a real ping.
const icmpFakeBodyLen = 56

// sendBurst emits one round of decoy pings at the desync TTL.
func (a *icmpDesyncAgent) sendBurst() {
	if a == nil || a.fd < 0 {
		return
	}
	peer, ok := a.t.getPeer()
	if !ok {
		return
	}
	dst := peer.Addr().As4()
	sa := &unix.SockaddrInet4{Addr: dst}
	ttl := a.ttlFor()
	badsum := a.cfg.Badsum != nil && *a.cfg.Badsum

	const ipHdr = 20
	pkt := make([]byte, ipHdr+icmpHdrLen+icmpFakeBodyLen)
	src4 := a.src.As4()
	for i := 0; i < a.cfg.Repeats; i++ {
		// --- IPv4 header ---
		pkt[0], pkt[1] = 0x45, 0x00
		binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
		binary.BigEndian.PutUint16(pkt[4:6], uint16(1+randUint16()&0x7fff))
		pkt[6], pkt[7] = 0x00, 0x00 // no DF: a real ping does not set it either
		pkt[8] = ttl
		pkt[9] = unix.IPPROTO_ICMP
		pkt[10], pkt[11] = 0, 0
		copy(pkt[12:16], src4[:])
		copy(pkt[16:20], dst[:])
		binary.BigEndian.PutUint16(pkt[10:12], inetChecksum(pkt[:ipHdr]))

		// --- ICMP echo request, wearing the carrier's own identifier ---
		m := pkt[ipHdr:]
		m[0], m[1] = icmpEchoRequest, 0
		m[2], m[3] = 0, 0
		binary.BigEndian.PutUint16(m[4:6], a.c.currentID())
		binary.BigEndian.PutUint16(m[6:8], uint16(a.c.seq.Add(1)))
		pingPayload(m[icmpHdrLen:])
		sum := icmpChecksum(m)
		if badsum {
			// Defence in depth behind the TTL: if a fake ever does reach the peer, its
			// kernel drops it on the checksum before any socket sees it.
			sum ^= 0xbeef
		}
		binary.BigEndian.PutUint16(m[2:4], sum)

		if err := unix.Sendto(a.fd, pkt, 0, sa); err != nil {
			log.Printf("desync: raw send failed: %v", err)
			return
		}
	}
	log.Printf("desync: sent %d decoy ping(s) ttl=%d badsum=%v (id 0x%04X, %d-byte payload)",
		a.cfg.Repeats, ttl, badsum, a.c.currentID(), icmpFakeBodyLen)
}

// run drives the injector: one burst as the flow opens, a second once the peer hop count has
// actually been learned so autottl is precise, then an optional periodic re-burst.
func (a *icmpDesyncAgent) run() {
	if a == nil || a.fd < 0 {
		return
	}
	defer func() { unix.Close(a.fd); a.fd = -1 }()
	a.sendBurst()
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

// startICMPDesync is the ICMP carrier's entry point for the shared "desync" config block, so
// the module means the same thing on every carrier. It waits for the peer address the same
// way startDesync does and never blocks the data path.
func startICMPDesync(cfg *Config, t *Tunnel, c *icmpCarrier) {
	if !cfg.Desync.on() {
		return
	}
	go func() {
		for i := 0; i < 60; i++ {
			if _, ok := t.getPeer(); ok {
				break
			}
			time.Sleep(time.Second)
		}
		if a := newICMPDesyncAgent(t, c, cfg); a != nil {
			a.run()
		}
	}()
}

// ---------------------------------------------------------------------------
// run loop
// ---------------------------------------------------------------------------

// setICMPPeerFromConfig installs the peer with port 0. cfg.Peer is written host:port for
// every other transport and operators copy it across unchanged, so accept that form and
// drop the port rather than rejecting a config that is only cosmetically wrong.
func setICMPPeerFromConfig(cfg *Config, t *Tunnel) {
	if cfg.Peer == "" {
		return
	}
	host := cfg.Peer
	if h, _, err := net.SplitHostPort(cfg.Peer); err == nil {
		host = h
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		log.Fatalf("invalid peer %q: %v", cfg.Peer, err)
	}
	var v4 net.IP
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			v4 = ip4
			break
		}
	}
	if v4 == nil {
		log.Fatalf("peer %q has no IPv4 address; the ICMP carrier is IPv4-only", cfg.Peer)
	}
	addr, _ := netip.AddrFromSlice(v4)
	t.setPeer(netip.AddrPortFrom(addr.Unmap(), 0))
}

func runICMP(cfg *Config, t *Tunnel, tuns []*os.File) {
	tun := tuns[0]
	setICMPPeerFromConfig(cfg, t)

	c := newICMPCarrier(cfg, t)
	defer c.Close()

	// Only the peer's address can be suppressed, so a config that learns its peer from
	// traffic gets no rule. Role b with an empty peer is a legitimate setup, so this is a
	// warning about bandwidth, not an error.
	if derefOr2(cfg.ICMP.Suppress, true) {
		if peer, ok := t.getPeer(); ok {
			c.suppress = suppressReplies(peer.Addr(), c.ids)
		} else {
			log.Printf("warning: no peer in config, so kernel echo replies cannot be suppressed " +
				"yet; set \"peer\" on both ends for the ICMP carrier")
		}
	}
	// The firewall rule outlives the process, so a plain kill would leave ping to the peer
	// silently broken. Take it down on the signals systemd actually sends.
	stopOnSignal(c)

	log.Printf("icmp carrier up (identifier 0x%04X, %d in the set, mimic=%v, batch=%d) - traffic ready to flow.",
		c.currentID(), len(c.ids), c.mimic, c.batch)

	// The shared "desync" block, dispatched to the injector that fits this carrier: decoy
	// pings rather than the UDP injector's fake QUIC Initials, which have no 5-tuple to ride
	// on here. Same config, same meaning, different packet.
	startICMPDesync(cfg, t, c)
	startJunk(cfg, t, c)

	if *cfg.Keepalive > 0 {
		go keepaliveLoop(c, t, *cfg.Keepalive)
	}

	var probe *probeAgent
	if t.dpi.enabled() && t.dpi.cfg.Probe != nil && *t.dpi.cfg.Probe {
		probe = newProbeAgent(t, c, time.Duration(t.dpi.cfg.ProbeSec)*time.Second)
		go probe.run()
	}

	go pumpTUNToCarrier(c, t, tun)

	// One receive goroutine per core, not one in total.
	//
	// A raw socket has no equivalent of the UDP carrier's GRO, and on this carrier the same
	// goroutine that reads a packet then decrypts it and writes it to the TUN before it can
	// read again. Measured on the link this was written for, a single reader offered
	// 400 Mbit/s lost 22829 packets to receive-buffer overflow while the path itself
	// delivered 99.5% of them — the drops were all on this side of the wire, waiting for one
	// goroutine to come back around to the socket. recvmmsg cuts the syscalls; the goroutines
	// cut the time between them.
	//
	// Splitting it is safe rather than merely fast: the replay window takes its own lock, the
	// counters are atomic, os.File serialises the TUN write, and each reader owns the pieces
	// of scratch that are not shared — its buffers and its opener. Packets finish out of
	// order, which for IP on a tunnel interface is what the network does anyway, and the
	// replay window is 4096 wide, far more than a few cores can reorder.
	readers := cfg.ICMP.Readers
	if readers <= 0 {
		readers = runtime.GOMAXPROCS(0)
		if readers > 8 {
			readers = 8 // past this the socket lock, not the CPU, is what is left to win
		}
	}
	if readers < 1 {
		readers = 1
	}
	log.Printf("icmp receive path: %d reader goroutine(s), %d message(s) per recvmmsg", readers, c.batch)

	var wg sync.WaitGroup
	for n := 0; n < readers; n++ {
		wg.Add(1)
		// Spread the readers over the TUN queues so the writes fan out too; with one queue
		// they all share it, exactly as before.
		q := tuns[n%len(tuns)]
		go func() {
			defer wg.Done()
			icmpReadLoop(c, t, q, probe)
		}()
	}
	wg.Wait()
}

// stopOnSignal tears the carrier down on SIGTERM/SIGINT and exits. Without it the firewall
// rule survives the process and ordinary ping to the peer stays broken until the next start.
func stopOnSignal(c *icmpCarrier) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, unix.SIGTERM, unix.SIGINT)
	go func() {
		s := <-ch
		log.Printf("received %v, removing the echo-reply rule and shutting down", s)
		c.Close()
		os.Exit(0)
	}()
}

// icmpReadLoop is one receive goroutine: read a batch, authenticate each message, write it
// to the TUN. Several run at once; everything it touches is either owned by this goroutine
// (its buffers, its batch, its opener) or internally synchronised.
func icmpReadLoop(c *icmpCarrier, t *Tunnel, tun *os.File, probe *probeAgent) {
	op := newOpener()
	errs := 0

	// One arena, sliced into per-message buffers that the mmsg headers point at for the
	// life of the goroutine, so a receive allocates nothing.
	arena := make([]byte, c.batch*c.slotSize)
	bufs := make([][]byte, c.batch)
	for i := range bufs {
		bufs[i] = arena[i*c.slotSize : (i+1)*c.slotSize]
	}
	var mb *mmsgBatch
	if c.batch > 1 {
		mb = newMmsgBatch(c.batch)
	}

	fail := func(err error) bool {
		if c.closed.Load() {
			return true
		}
		if err == unix.EINTR {
			return false
		}
		errs++
		if errs >= maxReadErrors {
			log.Fatalf("ICMP read failing persistently: %v", err)
		}
		log.Printf("ICMP read error (%d/%d): %v", errs, maxReadErrors, err)
		time.Sleep(readErrBackoff)
		return false
	}

	for {
		if mb == nil {
			pkt, src, ttl, err := c.recvInto(bufs[0])
			if err != nil {
				if fail(err) {
					return
				}
				continue
			}
			errs = 0
			icmpDeliver(c, t, tun, probe, op, pkt, src, ttl)
			continue
		}

		for i := range bufs {
			mb.setRecv(i, bufs[i])
		}
		n, err := mb.recvmmsg(c.fd, c.batch)
		if err != nil {
			if err == unix.ENOSYS || err == unix.EINVAL {
				// No recvmmsg on this kernel: drop to one packet per syscall for good.
				log.Printf("recvmmsg unavailable (%v); falling back to one packet per syscall", err)
				mb = nil
				continue
			}
			if fail(err) {
				return
			}
			continue
		}
		errs = 0
		for i := 0; i < n; i++ {
			if mb.hdrs[i].hdr.Flags&unix.MSG_TRUNC != 0 {
				// The buffer was sized from the MTU; a packet that does not fit means the
				// two ends disagree about it. Count it — the health line reports the total.
				if c.truncs.Add(1) == 1 {
					log.Printf("warning: a carrier packet was truncated on receive — it did not fit "+
						"this end's %d-byte receive slot; the peer is sending more than this end's "+
						"mtu allows for, so set the same mtu on BOTH servers", c.slotSize)
				}
				continue
			}
			pkt, ttl, ok := c.parse(bufs[i], mb.msgLen(i))
			if !ok {
				continue
			}
			src := netip.AddrPortFrom(netip.AddrFrom4(mb.msgAddr(i)), 0)
			icmpDeliver(c, t, tun, probe, op, pkt, src, ttl)
		}
	}
}

// icmpDeliver is the per-packet half of the receive path, shared by the batched and the
// single-message loops.
func icmpDeliver(c *icmpCarrier, t *Tunnel, tun *os.File, probe *probeAgent, op *opener,
	pkt []byte, src netip.AddrPort, ttl uint8) {

	plain, seq, ok := t.openSeq(op, pkt)
	if !ok {
		// The same three cases the UDP loop separates: a replay of our own traffic, a
		// forgery wearing the peer's address, and background noise. Every ping on the host
		// reaches this socket, but the filter and parse have already dropped everything
		// without one of our identifiers, so what lands here is targeted rather than
		// incidental.
		if src.IsValid() {
			switch {
			case seq != 0:
				t.dpi.observeStranger(evProbeReplay, src, pkt, ttl, "")
			case t.samePeer(src):
				t.dpi.observeStranger(evInjectSpoof, src, pkt, ttl, "")
			default:
				t.dpi.observeStranger(evScanUnauth, src, pkt, ttl, "")
			}
		}
		return
	}

	if src.IsValid() {
		t.maybeRoam(src)
	}
	t.dpi.observePeerPacket(seq, ttl)

	if len(plain) == 0 {
		return // keepalive packet — not written to TUN
	}
	if probe != nil && probe.handle(plain) {
		return // in-tunnel measurement frame, not traffic
	}
	if _, err := tun.Write(plain); err != nil {
		log.Printf("writing to TUN: %v", err)
	}
}

// ---------------------------------------------------------------------------
// send path
// ---------------------------------------------------------------------------

// pumpICMPBatched is the ICMP carrier's TUN pump: one blocking read, a non-blocking drain of
// whatever else the device already has queued, then one sendmmsg for the whole run. It is
// the same shape as the UDP pump in main.go, and for the same reason — when the link is busy
// the drain fills the batch and the syscall cost is divided across it, and when the link is
// quiet the first drain attempt returns nothing and the packet goes out immediately, so
// batching never adds latency to a lone packet.
func pumpICMPBatched(c *icmpCarrier, t *Tunnel, tun *os.File) {
	buf := make([]byte, maxPktSize)
	s := newSealer()
	tr := newTunReader(tun)
	errs := 0

	arena := make([]byte, c.batch*c.slotSize)
	mb := newMmsgBatch(c.batch)
	n := 0     // messages prepared
	bytes := 0 // their total size on the wire, for the pacer

	flush := func() {
		if n == 0 {
			return
		}
		peer, ok := t.getPeer()
		if !ok {
			n, bytes = 0, 0
			return
		}
		a4 := peer.Addr().As4()
		for i := 0; i < n; i++ {
			mb.names[i].Addr = a4
		}
		c.pace(bytes)
		// sendmmsg reports how many it took, exactly like a short write. Anything it did
		// not take is dropped rather than requeued: it is a carrier datagram, the inner
		// protocols retransmit, and holding the pump to retry would build the queue that
		// caused the shortfall.
		sent, err := mb.sendmmsg(c.fd, n)
		if err != nil {
			log.Printf("carrier send failed: %v", err)
		} else if sent < n {
			log.Printf("carrier send: kernel took %d of %d messages", sent, n)
		}
		n, bytes = 0, 0
	}

	// add prepares one sealed datagram as a message in the batch. Returns false if it does
	// not fit in a slot, in which case the caller sends it on its own.
	add := func(pkt []byte) bool {
		if icmpHdrLen+len(pkt)+icmpMimicLen > c.slotSize {
			return false
		}
		slot := arena[n*c.slotSize : (n+1)*c.slotSize]
		msg := c.buildMessage(slot, pkt)
		mb.setSend(n, msg, [4]byte{})
		bytes += len(msg)
		n++
		return true
	}

	for {
		m, err := tr.read(buf)
		if err != nil {
			errs++
			if errs >= maxReadErrors {
				log.Fatalf("TUN read failing persistently: %v", err)
			}
			log.Printf("TUN read error (%d/%d): %v", errs, maxReadErrors, err)
			time.Sleep(readErrBackoff)
			continue
		}
		errs = 0
		if m == 0 {
			continue
		}
		// Seal once and reuse the result: sealInto burns a sequence number on every call,
		// and the slice it returns stays valid until the next call on the same sealer.
		sealed := t.sealInto(s, buf[:m])
		if !add(sealed) {
			if err := c.Send(sealed); err != nil {
				log.Printf("carrier send failed: %v", err)
			}
			continue
		}
		// Drain whatever else is already waiting, but never wait for it.
		for n < c.batch {
			k, err := tr.tryRead(buf)
			if err != nil || k == 0 {
				break
			}
			sealed = t.sealInto(s, buf[:k])
			if !add(sealed) {
				flush()
				if err := c.Send(sealed); err != nil {
					log.Printf("carrier send failed: %v", err)
				}
			}
		}
		flush()
	}
}
