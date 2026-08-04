//go:build linux

// aestun — entry point and Linux-specific part (TUN creation, interface config, main loop).
// The protocol and crypto core lives in tunnel.go (OS-independent and testable), the
// QUIC-shaped wire obfuscation in obfs.go, and the DPI/probe observability in dpilog.go.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// ---------------------------------------------------------------------------
// TUN (Linux) — no external dependency. The device is opened and attached in
// offload.go, which has to control the exact order of attach vs. poll registration.
// ---------------------------------------------------------------------------

type ifReq struct {
	Name  [16]byte
	Flags uint16
	_     [22]byte
}

const (
	iffTun    = 0x0001
	iffNoPI   = 0x1000
	tunSetIff = 0x400454ca
	devNetTun = "/dev/net/tun"
)

// Read-loop resilience: a transient read error must not tear the tunnel down.
// We log and continue on errors, backing off briefly, and only exit if they
// persist (a permanent condition such as a closed device/socket), letting
// systemd restart us cleanly.
const (
	maxReadErrors  = 32
	readErrBackoff = 50 * time.Millisecond
)

// ---------------------------------------------------------------------------
// Interface configuration via the ip command
// ---------------------------------------------------------------------------

func runCmd(args ...string) error {
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func configureIface(cfg *Config, ifname string) {
	if err := runCmd("ip", "link", "set", "dev", ifname, "mtu", strconv.Itoa(cfg.MTU)); err != nil {
		log.Printf("warning: setting MTU failed: %v", err)
	}
	if cfg.TxQueueLen > 0 {
		if err := runCmd("ip", "link", "set", "dev", ifname, "txqueuelen", strconv.Itoa(cfg.TxQueueLen)); err != nil {
			log.Printf("warning: setting txqueuelen failed: %v", err)
		}
	}
	if cfg.LocalIP != "" {
		if err := runCmd("ip", "addr", "add", cfg.LocalIP, "dev", ifname); err != nil {
			log.Printf("warning: adding address failed (may already exist): %v", err)
		}
	}
	if err := runCmd("ip", "link", "set", "dev", ifname, "up"); err != nil {
		log.Fatalf("bringing interface up failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Carrier — the transport under the tunnel. UDP and TCP differ only in how a
// sealed datagram gets to the peer, so both TUN pump loops are written once.
// ---------------------------------------------------------------------------

type carrier interface {
	// Send delivers one sealed datagram to the peer.
	Send(pkt []byte) error
	// Recv returns the next sealed datagram from the peer, blocking until one arrives,
	// along with the source address and the IP TTL of the datagram that carried it.
	// src is the zero value and ttl is 0 for transports that cannot supply them.
	Recv() (pkt []byte, src netip.AddrPort, ttl uint8, err error)
	Close() error
}

// --- UDP -------------------------------------------------------------------

type udpCarrier struct {
	conn *net.UDPConn
	t    *Tunnel
	buf  []byte
	oob  []byte
	gso  bool
	// Shapes bulk traffic only; keepalives and probes go out through Send untouched.
	pacer *pacer

	// When the kernel coalesces several datagrams into one recvmsg, the surplus waits
	// here and Recv hands it out a segment at a time. Keeping the split inside the
	// carrier means the receive loop above is identical whether GRO is on or off.
	pend    []byte
	pendSeg int
	pendSrc netip.AddrPort
	pendTTL uint8
}

func (u *udpCarrier) Send(pkt []byte) error {
	peer, ok := u.t.getPeer()
	if !ok {
		return nil // peer address not known yet; nothing to do but drop
	}
	// The AddrPort form, so the send path does not build a *net.UDPAddr per datagram.
	_, err := u.conn.WriteToUDPAddrPort(pkt, peer)
	return err
}

func (u *udpCarrier) Recv() ([]byte, netip.AddrPort, uint8, error) {
	// Anything the kernel coalesced on the previous call is handed out first, one
	// datagram at a time, before the socket is touched again.
	if len(u.pend) > 0 {
		n := u.pendSeg
		if n > len(u.pend) {
			n = len(u.pend) // the trailing segment may be shorter
		}
		pkt := u.pend[:n]
		u.pend = u.pend[n:]
		return pkt, u.pendSrc, u.pendTTL, nil
	}
	// ReadMsgUDPAddrPort rather than ReadFromUDP, for two reasons. It is the same recvmsg
	// syscall underneath but also returns the ancillary data carrying the datagram's IP
	// TTL — the one byte that lets the observer tell a packet the peer actually sent from
	// one a middlebox forged with the peer's address on it. And the AddrPort form returns
	// the source by value, where the *net.UDPAddr forms allocate a fresh address, with a
	// heap-allocated IP slice inside it, for every datagram received.
	n, oobn, _, src, err := u.conn.ReadMsgUDPAddrPort(u.buf, u.oob)
	if err != nil {
		return nil, netip.AddrPort{}, 0, err
	}
	oob := u.oob[:oobn]
	addr, ttl := normAddr(src), parseTTL(oob)
	// A segment size smaller than what arrived means the kernel merged several datagrams.
	if seg := parseGROSegment(oob); seg > 0 && seg < n {
		u.pend, u.pendSeg, u.pendSrc, u.pendTTL = u.buf[seg:n], seg, addr, ttl
		return u.buf[:seg], addr, ttl, nil
	}
	return u.buf[:n], addr, ttl, nil
}

// sendBatch delivers a run of equally sized datagrams in one syscall, letting the kernel
// split them apart again below IP. Falls back to a plain send for a batch of one, which is
// what a quiet link produces.
func (u *udpCarrier) sendBatch(b *txBatch) error {
	if b.count == 0 {
		return nil
	}
	peer, ok := u.t.getPeer()
	if !ok {
		b.reset()
		return nil
	}
	var err error
	if b.count == 1 || !u.gso {
		// Not a run: send each datagram on its own. Without GSO the batch never holds
		// more than one, so this is also the whole fallback path.
		for off := 0; off < b.n; off += b.segSize {
			end := off + b.segSize
			if end > b.n {
				end = b.n
			}
			if _, e := u.conn.WriteToUDPAddrPort(b.buf[off:end], peer); e != nil && err == nil {
				err = e
			}
		}
	} else {
		oob := gsoControl(b.oob, uint16(b.segSize))
		_, _, err = u.conn.WriteMsgUDPAddrPort(b.buf[:b.n], oob, peer)
	}
	b.reset()
	return err
}

// normAddr puts an address into one canonical form.
//
// A wildcard listen address makes Go open a dual-stack IPv6 socket, and such a socket
// reports IPv4 senders in the v4-mapped form (::ffff:1.2.3.4). A peer parsed from the
// config is a plain IPv4 address. The two are *not* equal as netip values, so without
// this every genuine peer packet would compare as coming from a stranger: the tunnel
// would still work, because roaming overwrites the peer after the first authenticated
// packet, but it would log a spurious roam on every start and mis-file the packets
// before it. Normalising once, here, keeps every consumer downstream comparing like
// with like — and keeps ::ffff: prefixes out of the log.
func normAddr(a netip.AddrPort) netip.AddrPort {
	if !a.IsValid() {
		return a
	}
	return netip.AddrPortFrom(a.Addr().Unmap(), a.Port())
}

func (u *udpCarrier) Close() error { return u.conn.Close() }

// parseTTL digs the hop count out of the recvmsg control messages. Returns 0 when the
// kernel did not supply one, which the callers treat as "unknown" rather than an anomaly.
func parseTTL(oob []byte) uint8 {
	if len(oob) == 0 {
		return 0
	}
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return 0
	}
	for _, m := range msgs {
		switch {
		case m.Header.Level == unix.IPPROTO_IP && m.Header.Type == unix.IP_TTL && len(m.Data) >= 1:
			return m.Data[0]
		case m.Header.Level == unix.IPPROTO_IPV6 && m.Header.Type == unix.IPV6_HOPLIMIT && len(m.Data) >= 4:
			return uint8(binary.LittleEndian.Uint32(m.Data[:4]))
		}
	}
	return 0
}

// enableTTLInfo asks the kernel to attach the hop count to every datagram it delivers.
// Both address families are requested and both failures are ignored: on a v4-only socket
// the v6 option simply does not apply, and on a kernel that refuses either one the observer
// degrades to "TTL unknown" rather than failing to start.
func enableTTLInfo(conn *net.UDPConn) {
	rc, err := conn.SyscallConn()
	if err != nil {
		return
	}
	rc.Control(func(fd uintptr) {
		unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVTTL, 1)
		unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVHOPLIMIT, 1)
	})
}

// --- TCP -------------------------------------------------------------------

// TCP is a stream, so datagram boundaries have to be restored explicitly:
// each sealed datagram goes out as a 2-byte big-endian length followed by the bytes.
type tcpCarrier struct {
	mu   sync.Mutex
	conn net.Conn
	// Closed when the connection it belongs to is retired, so the dialer can wait for
	// its own connection to end without racing against a replacement.
	done chan struct{}

	// tlsShape wraps each datagram in a TLS application-data record instead of the bare
	// 2-byte length prefix, and makes Recv skip the synthetic handshake records (tls.go).
	tlsShape bool

	hdr  [2]byte // length prefix, plain framing
	rhdr [5]byte // record header, TLS framing
	buf  []byte
}

// errTLSDesync means the record framing read a length that cannot be right, so the stream is
// out of sync and the only safe recovery is to drop the connection and start a fresh one.
var errTLSDesync = fmt.Errorf("tls framing desynchronised")

func setTCPOpts(c net.Conn) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return
	}
	// Nagle would coalesce small tunnel datagrams and add latency to every inner
	// connection's ACKs; keepalive lets a silently dropped path surface as an error
	// instead of a stall that never ends.
	tc.SetNoDelay(true)
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(30 * time.Second)
}

// set installs conn as the active connection (nil to clear) and returns the channel that
// closes when *this* connection is retired.
func (c *tcpCarrier) set(conn net.Conn) chan struct{} {
	c.mu.Lock()
	old, oldDone := c.conn, c.done
	c.conn = conn
	if conn != nil {
		c.done = make(chan struct{})
	} else {
		c.done = nil
	}
	newDone := c.done
	c.mu.Unlock()

	if oldDone != nil {
		close(oldDone)
	}
	if old != nil && old != conn {
		old.Close()
	}
	return newDone
}

func (c *tcpCarrier) current() net.Conn {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn
}

// rotatedOut reports whether conn has been superseded by a newer active connection — a
// rotation or a reconnect installed a replacement. A read error on a rotated-out connection is
// expected (the old socket was closed on purpose) and must not tear the carrier down; the
// reader just moves on to the new connection.
func (c *tcpCarrier) rotatedOut(conn net.Conn) bool {
	cur := c.current()
	return cur != nil && cur != conn
}

func (c *tcpCarrier) Send(pkt []byte) error {
	conn := c.current()
	if conn == nil {
		return nil // not connected yet; the inner protocols will retransmit
	}
	if len(pkt) > 65535 {
		return fmt.Errorf("datagram too large for framing: %d", len(pkt))
	}
	var hdr []byte
	if c.tlsShape {
		// TLS application-data record header: type 0x17, version 0x0303, 2-byte length.
		var h [tlsRecordHeaderLen]byte
		h[0], h[1], h[2] = tlsRecAppData, 0x03, 0x03
		binary.BigEndian.PutUint16(h[3:5], uint16(len(pkt)))
		hdr = h[:]
	} else {
		var h [2]byte
		binary.BigEndian.PutUint16(h[:], uint16(len(pkt)))
		hdr = h[:]
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != conn {
		return nil // replaced under us; drop rather than write to a dead socket
	}
	if _, err := c.conn.Write(hdr); err != nil {
		return err
	}
	_, err := c.conn.Write(pkt)
	return err
}

func (c *tcpCarrier) Recv() ([]byte, netip.AddrPort, uint8, error) {
	if c.tlsShape {
		return c.recvTLS()
	}
	for {
		conn := c.current()
		if conn == nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		if _, err := io.ReadFull(conn, c.hdr[:]); err != nil {
			if c.rotatedOut(conn) {
				continue
			}
			return nil, netip.AddrPort{}, 0, err
		}
		n := int(binary.BigEndian.Uint16(c.hdr[:]))
		if n == 0 {
			continue
		}
		if cap(c.buf) < n {
			c.buf = make([]byte, n)
		}
		if _, err := io.ReadFull(conn, c.buf[:n]); err != nil {
			if c.rotatedOut(conn) {
				continue
			}
			return nil, netip.AddrPort{}, 0, err
		}
		return c.buf[:n], netip.AddrPort{}, 0, nil
	}
}

// recvTLS reads TLS records, returning the payload of the next application-data record and
// silently consuming the synthetic handshake records (ClientHello/ServerHello/ChangeCipherSpec)
// the peer sends to open the connection.
func (c *tcpCarrier) recvTLS() ([]byte, netip.AddrPort, uint8, error) {
	for {
		conn := c.current()
		if conn == nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		if _, err := io.ReadFull(conn, c.rhdr[:]); err != nil {
			if c.rotatedOut(conn) {
				continue
			}
			return nil, netip.AddrPort{}, 0, err
		}
		n := int(binary.BigEndian.Uint16(c.rhdr[3:5]))
		// A length no real TLS record can carry means the framing has slipped; there is no
		// resynchronising a byte stream, so surface it and let the loop drop the connection.
		if n > tlsRecordReadCeiling {
			return nil, netip.AddrPort{}, 0, errTLSDesync
		}
		if n == 0 {
			continue
		}
		if cap(c.buf) < n {
			c.buf = make([]byte, n)
		}
		if _, err := io.ReadFull(conn, c.buf[:n]); err != nil {
			if c.rotatedOut(conn) {
				continue
			}
			return nil, netip.AddrPort{}, 0, err
		}
		if c.rhdr[0] == tlsRecAppData {
			return c.buf[:n], netip.AddrPort{}, 0, nil
		}
		// Handshake, ChangeCipherSpec or Alert: cover records, not tunnel data — skip.
	}
}

func (c *tcpCarrier) Close() error {
	if conn := c.current(); conn != nil {
		return conn.Close()
	}
	return nil
}

// ---------------------------------------------------------------------------
// Keepalive
// ---------------------------------------------------------------------------

// jitter returns d scaled by a random factor in [0.6, 1.4]. A keepalive that fires on
// an exact period is a clean clock signature in a flow that is otherwise shapeless —
// the interval itself identifies the tunnel regardless of what the packets contain.
func jitter(d time.Duration) time.Duration {
	n, err := rand.Int(rand.Reader, big.NewInt(800))
	if err != nil {
		return d
	}
	return time.Duration(float64(d) * (0.6 + float64(n.Int64())/1000.0))
}

func keepaliveLoop(c carrier, t *Tunnel, seconds int) {
	base := time.Duration(seconds) * time.Second
	s := newSealer()
	for {
		time.Sleep(jitter(base))
		if err := c.Send(t.sealInto(s, nil)); err != nil {
			log.Printf("keepalive send failed: %v", err)
		}
	}
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("[aestun] ")

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "keygen":
			k := make([]byte, 32)
			if _, err := rand.Read(k); err != nil {
				log.Fatalf("rand: %v", err)
			}
			fmt.Println(base64.StdEncoding.EncodeToString(k))
			return
		case "cipherinfo":
			// Used by the installer to pick a suite without the operator having to know
			// what AES-NI is. Prints the recommendation on its own line so a shell can
			// read it with a single command substitution.
			fmt.Printf("aes_hardware=%v\n", hasAESAccel())
			fmt.Printf("cpu=%s\n", cpuModel())
			fmt.Println(recommendedCipher())
			return
		case "probe":
			// Send the carrier port the kind of traffic a censor's active prober or a
			// scanner would, so the DPI observer on the far end can be checked against
			// real packets rather than trusted. It is a diagnostic for your own tunnel;
			// point it anywhere else and all you are doing is sending stray UDP.
			fs := flag.NewFlagSet("probe", flag.ExitOnError)
			target := fs.String("target", "", "carrier address to probe, host:port")
			sni := fs.String("sni", "www.google.com", "server name to put in the QUIC ClientHello")
			mode := fs.String("mode", "quic", "quic (a QUIC Initial) or junk (random datagrams)")
			count := fs.Int("count", 1, "how many datagrams to send")
			size := fs.Int("size", 64, "datagram size for junk mode")
			fs.Parse(os.Args[2:])
			if *target == "" {
				log.Fatalf("probe: -target is required")
			}
			conn, err := net.Dial("udp", *target)
			if err != nil {
				log.Fatalf("probe: %v", err)
			}
			defer conn.Close()
			for i := 0; i < *count; i++ {
				var pkt []byte
				switch *mode {
				case "quic":
					dcid := make([]byte, 8)
					scid := make([]byte, 8)
					rand.Read(dcid)
					rand.Read(scid)
					pkt, err = buildInitial(dcid, dcid, scid, buildClientHello(*sni), true)
					if err != nil || pkt == nil {
						log.Fatalf("probe: building the Initial failed: %v", err)
					}
				case "junk":
					pkt = make([]byte, *size)
					rand.Read(pkt)
				default:
					log.Fatalf("probe: -mode must be quic or junk")
				}
				if _, err := conn.Write(pkt); err != nil {
					log.Fatalf("probe: %v", err)
				}
			}
			fmt.Printf("sent %d %s datagram(s) to %s\n", *count, *mode, *target)
			return
		case "dpi-report":
			fs := flag.NewFlagSet("dpi-report", flag.ExitOnError)
			path := fs.String("log", "", "DPI log path (default: read it from the config)")
			cfgp := fs.String("config", "/etc/aestun/config.json", "config file, used to locate the log")
			hours := fs.Int("hours", 24, "how far back to summarise")
			fs.Parse(os.Args[2:])
			p := *path
			if p == "" {
				var c Config
				if raw, err := os.ReadFile(*cfgp); err == nil {
					json.Unmarshal(raw, &c)
				}
				c.DPILog.applyDefaults()
				p = c.DPILog.Path
			}
			if err := dpiReport(p, time.Duration(*hours)*time.Hour); err != nil {
				log.Fatalf("%v", err)
			}
			return
		}
	}

	cfgPath := flag.String("config", "/etc/aestun/config.json", "path to the JSON config file")
	flag.Parse()

	raw, err := os.ReadFile(*cfgPath)
	if err != nil {
		log.Fatalf("reading config: %v", err)
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		log.Fatalf("invalid config: %v", err)
	}
	cfg.applyDefaults()

	if cfg.Role != "a" && cfg.Role != "b" {
		log.Fatalf("role must be \"a\" or \"b\" (different on the two servers)")
	}
	if cfg.Transport != "udp" && cfg.Transport != "tcp" {
		log.Fatalf("transport must be \"udp\" or \"tcp\"")
	}
	if cfg.Obfs != "none" && cfg.Obfs != "quic" {
		log.Fatalf("obfs must be \"none\" or \"quic\"")
	}
	if cfg.Cipher != cipherAESGCM && cfg.Cipher != cipherChaCha {
		log.Fatalf("cipher must be %q or %q (and must match on both servers)", cipherAESGCM, cipherChaCha)
	}
	psk, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cfg.Key))
	if err != nil || len(psk) != 32 {
		log.Fatalf("key must be base64 of exactly 32 bytes (get one from `aestun keygen`)")
	}

	tuneRuntime(&cfg)

	// TUN
	tun, ifname, err := openTUNNonblock(cfg.TunName)
	if err != nil {
		log.Fatalf("%v", err)
	}
	defer tun.Close()
	log.Printf("interface %s created", ifname)

	if *cfg.ManageIP {
		configureIface(&cfg, ifname)
	}

	t := newTunnel(&cfg, psk)
	t.ifname = ifname
	go t.writeStats(cfg.StatsPath)
	t.dpi.run(t)

	log.Printf("%s", t.describe(&cfg))
	if cfg.Cipher == cipherAESGCM && !hasAESAccel() {
		log.Printf("warning: this CPU has no AES-NI, so AES-256-GCM runs in software and will "+
			"dominate CPU use at any real packet rate. Set \"cipher\": %q on BOTH servers.", cipherChaCha)
	}

	if cfg.Transport == "tcp" {
		runTCP(&cfg, t, tun)
	} else {
		runUDP(&cfg, t, tun)
	}
}

// tuneRuntime trims the Go runtime down to what a packet forwarder actually needs. With the
// packet path allocating nothing, the collector has almost no work to do, and the default
// settings mostly cost wakeups: a higher GC target keeps it from running on the little
// garbage that remains, and an explicit memory limit is what actually bounds RSS.
func tuneRuntime(cfg *Config) {
	if p := derefOr(cfg.GCPercent, 400); p > 0 {
		debug.SetGCPercent(p)
	}
	if cfg.MemLimit > 0 {
		debug.SetMemoryLimit(cfg.MemLimit)
	}
	if cfg.MaxProcs > 0 {
		runtime.GOMAXPROCS(cfg.MaxProcs)
	}
	startPprof(cfg.PprofAddr)
}

func cpuModel() string {
	b, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return runtime.GOARCH
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "model name") {
			if i := strings.Index(line, ":"); i >= 0 {
				return strings.TrimSpace(line[i+1:])
			}
		}
	}
	return runtime.GOARCH
}

// ---------------------------------------------------------------------------
// runUDP / runTCP
// ---------------------------------------------------------------------------

// setPeerFromConfig parses cfg.Peer (if set) and installs it as the tunnel peer, unmapped so a
// v4 peer compares equal to the v4-mapped form a dual-stack socket reports.
func setPeerFromConfig(cfg *Config, t *Tunnel) {
	if cfg.Peer == "" {
		return
	}
	paddr, err := net.ResolveUDPAddr("udp", cfg.Peer)
	if err != nil {
		log.Fatalf("invalid peer: %v", err)
	}
	ap, ok := netip.AddrFromSlice(paddr.IP)
	if !ok {
		log.Fatalf("invalid peer address: %s", cfg.Peer)
	}
	t.setPeer(netip.AddrPortFrom(ap.Unmap(), uint16(paddr.Port)))
}

// startDesync launches the native fake injector once the peer address is known (role b may
// learn it from the first authenticated packet rather than from config). It never blocks the
// data path — the whole thing runs in its own goroutine and disables itself on any problem.
func startDesync(cfg *Config, t *Tunnel) {
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
		if a := newDesyncAgent(t, cfg); a != nil {
			defer a.close()
			a.run()
		}
	}()
}

// startJunk sends flow-start cover traffic once the carrier can actually reach the peer, in its
// own goroutine so a jittered burst never delays bringing the tunnel up. "Can reach" differs by
// transport: UDP needs the peer address known; TCP needs a live connection (it never populates
// the peer address, so waiting on that would stall the burst for the whole timeout).
func startJunk(cfg *Config, t *Tunnel, c carrier) {
	if !cfg.Junk.on() {
		return
	}
	ready := func() bool {
		if tc, ok := c.(*tcpCarrier); ok {
			return tc.current() != nil
		}
		_, ok := t.getPeer()
		return ok
	}
	go func() {
		for i := 0; i < 60; i++ {
			if ready() {
				break
			}
			time.Sleep(time.Second)
		}
		junkBurst(t, c, &cfg.Junk)
	}()
}

// newUDPCarrier builds the ordinary single-socket carrier with its buffers, offload and pacer.
func newUDPCarrier(cfg *Config, t *Tunnel) *udpCarrier {
	laddr, err := net.ResolveUDPAddr("udp", cfg.Listen)
	if err != nil {
		log.Fatalf("invalid listen: %v", err)
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		log.Fatalf("UDP listen failed: %v", err)
	}

	// Enlarge the socket buffers so traffic bursts are absorbed instead of dropped
	// (kernel UDP RcvbufErrors). The kernel caps these at net.core.rmem_max / wmem_max.
	if err := conn.SetReadBuffer(cfg.RcvBuf); err != nil {
		log.Printf("warning: SetReadBuffer(%d) failed: %v", cfg.RcvBuf, err)
	}
	if err := conn.SetWriteBuffer(cfg.SndBuf); err != nil {
		log.Printf("warning: SetWriteBuffer(%d) failed: %v", cfg.SndBuf, err)
	}
	if t.dpi.enabled() {
		enableTTLInfo(conn)
	}

	c := &udpCarrier{
		conn: conn,
		t:    t,
		buf:  make([]byte, maxPktSize),
		oob:  make([]byte, 256),
	}
	if *cfg.Offload {
		c.gso = enableGSO(conn)
		gro := enableGRO(conn)
		log.Printf("kernel offload: udp_gso=%v udp_gro=%v", c.gso, gro)
	}
	if cfg.RateMbps > 0 {
		c.pacer = newPacer(cfg.RateMbps)
		log.Printf("carrier shaped to %.0f Mbit/s", cfg.RateMbps)
	}
	return c
}

func runUDP(cfg *Config, t *Tunnel, tun *os.File) {
	// The peer is needed by every carrier (hopping sends to peer.IP:hop_port, the single
	// socket sends to the whole AddrPort), so install it before either is built.
	setPeerFromConfig(cfg, t)

	// Carrier selection: keyed port hopping when configured, otherwise the single socket.
	// Port hopping trades the segmentation offload for the ability to move off a blocked
	// 5-tuple automatically, so it is opt-in.
	var c carrier
	if cfg.Hop.on() {
		hc, err := newHopCarrier(cfg, t, cfg.RcvBuf, cfg.SndBuf, t.dpi.enabled())
		if err != nil {
			// Do NOT fall back to a single socket. If this end quietly reverts to one port
			// while the peer keeps hopping, the peer sends to ports this end is not listening
			// on and the tunnel silently carries nothing while both services look "active" —
			// the worst possible failure. A clean fatal is diagnosable; the operator frees the
			// port (or drops it from hop.ports) and systemd restarts. The port set must be
			// bindable and identical on both ends.
			log.Fatalf("port hopping is enabled but a port could not be bound: %v\n"+
				"free that port (something else is using it) or remove it from hop.ports on BOTH servers.", err)
		}
		c = hc
	}
	if c == nil {
		c = newUDPCarrier(cfg, t)
	}
	defer c.Close()

	log.Printf("tunnel up - traffic ready to flow.")

	// Role a opens the flow, so it plays the client half of the synthetic handshake; role b
	// answers whatever Initial arrives (see the receive loop below).
	if t.obfs != nil && cfg.Role == "a" {
		if _, err := sendClientInitial(c, cfg.SNI); err != nil {
			log.Printf("warning: synthetic handshake failed: %v", err)
		} else {
			log.Printf("sent synthetic QUIC Initial (sni=%s)", cfg.SNI)
		}
	}

	// Anti-DPI extensions (all no-ops unless configured on).
	startDesync(cfg, t)
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

	op := newOpener()
	errs := 0
	var lastInitialReply time.Time
	for {
		pkt, src, ttl, err := c.Recv()
		if err != nil {
			errs++
			if errs >= maxReadErrors {
				log.Fatalf("UDP read failing persistently: %v", err)
			}
			log.Printf("UDP read error (%d/%d): %v", errs, maxReadErrors, err)
			time.Sleep(readErrBackoff)
			continue
		}
		errs = 0

		fromPeer := t.samePeer(src)

		// Handshake cover only ever appears with obfs on; without it the first byte is
		// random nonce material and this test would discard half of all real traffic.
		if t.obfs != nil && quicIsLongHeader(pkt) {
			v, _ := quicLongVersion(pkt)
			realQUIC := quicKnownVersion(v)
			switch {
			case !fromPeer && src.IsValid():
				// Nobody but the peer has any reason to send this port a QUIC handshake.
				// Whoever did is checking what this port really is, so record who, and
				// what host they claimed to be reaching for. Random junk that merely
				// happens to have the form bit set is filed as scanning instead, so the
				// probe class keeps its meaning.
				class, sni := evScanUnauth, ""
				if realQUIC {
					class, sni = evProbeQUIC, quicPeekInitialSNI(pkt)
				}
				t.dpi.observeStranger(class, src, pkt, ttl, sni)
			case fromPeer && !realQUIC:
				// Wearing the peer's address, but carrying a version the peer would never
				// send — this side only ever emits version 1. Forged traffic that happened
				// to land on the form bit used to be discarded here without a word, which
				// hid roughly half of any injection attempt from the log.
				t.dpi.observeStranger(evInjectSpoof, src, pkt, ttl, "")
			}
			// Continue the conversation under the connection ID the peer named, so the
			// 1-RTT packets belong to the handshake instead of looking unrelated to it.
			if _, scid, ok := quicParseLongCIDs(pkt); ok {
				t.obfs.adoptPeerCID(scid)
			}
			// Answer at most occasionally: an unauthenticated packet triggers this, so an
			// unthrottled reply would make the port an amplification source for anyone
			// willing to spray long-header datagrams at it.
			if cfg.Role == "b" && time.Since(lastInitialReply) > 30*time.Second {
				lastInitialReply = time.Now()
				if err := replyServerInitial(c, pkt); err != nil {
					log.Printf("warning: handshake reply failed: %v", err)
				}
			}
			continue
		}

		plain, seq, ok := t.openSeq(op, pkt)
		if !ok {
			// Everything that failed to authenticate is interesting to somebody. Tell
			// apart the three cases that mean different things: a replay (someone sent
			// our own captured traffic back), a forgery wearing the peer's address, and
			// ordinary background noise from a stranger.
			if src.IsValid() {
				switch {
				case seq != 0:
					// It decrypted, so it was genuinely ours — and it was rejected only
					// by the replay window. From anyone at all, that is a recording being
					// played back at us.
					t.dpi.observeStranger(evProbeReplay, src, pkt, ttl, "")
				case fromPeer:
					t.dpi.observeStranger(evInjectSpoof, src, pkt, ttl, "")
				default:
					t.dpi.observeStranger(evScanUnauth, src, pkt, ttl, "")
				}
			}
			continue
		}

		// Only now, after the packet has authenticated, is the source trusted enough
		// to move the tunnel to it.
		if src.IsValid() {
			t.maybeRoam(src)
		}
		t.dpi.observePeerPacket(seq, ttl)

		if len(plain) == 0 {
			continue // keepalive packet — not written to TUN
		}
		if probe != nil && probe.handle(plain) {
			continue // in-tunnel measurement frame, not traffic
		}
		if _, err := tun.Write(plain); err != nil {
			log.Printf("writing to TUN: %v", err)
		}
	}
}

func runTCP(cfg *Config, t *Tunnel, tun *os.File) {
	c := &tcpCarrier{buf: make([]byte, maxPktSize), tlsShape: t.tlsShape}
	if t.tlsShape {
		log.Printf("tcp carrier shaped as TLS (records + synthetic handshake, sni=%s)", cfg.SNI)
	}

	// Role a dials out, role b accepts. Whoever is behind the more restrictive network
	// should be the dialer; role a (the inside server) is that side by construction. The dial
	// loop optionally rotates the connection to dodge volumetric throttling (tcprotate.go).
	if cfg.Role == "a" {
		go tcpDialLoop(cfg, t, c)
	} else {
		ln, err := net.Listen("tcp", cfg.Listen)
		if err != nil {
			log.Fatalf("TCP listen failed: %v", err)
		}
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					log.Printf("tcp accept failed: %v", err)
					time.Sleep(time.Second)
					continue
				}
				setTCPOpts(conn)
				// Answer with a ServerHello + ChangeCipherSpec flight, so a record-level
				// inspector sees a TLS handshake being established rather than opaque bytes.
				if t.tlsShape {
					if _, err := conn.Write(buildTLSServerFlight()); err != nil {
						log.Printf("tcp: TLS ServerHello write failed: %v", err)
						conn.Close()
						continue
					}
				}
				log.Printf("tcp accepted: %s", conn.RemoteAddr())
				// A new connection supersedes the old one: after a peer restart the
				// stale socket may never produce an error on this side.
				c.set(conn)
			}
		}()
	}

	log.Printf("tunnel up - traffic ready to flow.")
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

	op := newOpener()
	for {
		pkt, _, _, err := c.Recv()
		if err != nil {
			// A stream error means the connection is gone; drop it and let the dialer
			// or the accept loop install a fresh one. Framing cannot resynchronise
			// mid-stream, so continuing on the same socket would corrupt every packet.
			c.set(nil)
			time.Sleep(readErrBackoff)
			continue
		}
		if t.obfs != nil && quicIsLongHeader(pkt) {
			continue
		}
		plain, seq, ok := t.openSeq(op, pkt)
		if !ok {
			continue
		}
		t.dpi.observePeerPacket(seq, 0)
		if len(plain) == 0 {
			continue
		}
		if probe != nil && probe.handle(plain) {
			continue
		}
		if _, err := tun.Write(plain); err != nil {
			log.Printf("writing to TUN: %v", err)
		}
	}
}

// pumpTUNToCarrier moves outbound IP packets from the TUN device onto the carrier.
//
// One blocking read, then a non-blocking drain of whatever else the device already has
// queued, then one send for the whole run. When the link is busy the drain fills a batch
// and the syscall cost is divided across it; when the link is quiet the first drain
// attempt returns nothing and the packet goes out immediately, so batching never adds
// latency to a lone packet.
func pumpTUNToCarrier(c carrier, t *Tunnel, tun *os.File) {
	buf := make([]byte, maxPktSize)
	s := newSealer()
	errs := 0

	bc, canBatch := c.(*udpCarrier)
	if !canBatch {
		// TCP carrier: the stream has its own framing and no segmentation to offload.
		for {
			n, err := tun.Read(buf)
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
			if n == 0 {
				continue
			}
			if err := c.Send(t.sealInto(s, buf[:n])); err != nil {
				log.Printf("carrier send failed: %v", err)
			}
		}
	}

	tr := newTunReader(tun)
	batch := newTxBatch(bc.gso)
	pace := bc.pacer
	flush := func() {
		// Shape before the syscall, on the byte count that actually goes on the wire.
		pace.wait(batch.n)
		if err := bc.sendBatch(batch); err != nil {
			log.Printf("carrier send failed: %v", err)
		}
	}
	for {
		n, err := tr.read(buf)
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
		if n == 0 {
			continue
		}
		pkt := t.sealInto(s, buf[:n])
		if !batch.wants(pkt) {
			flush()
		}
		full := batch.add(pkt)
		if full {
			flush()
			continue
		}
		// Drain whatever else is already waiting, but never wait for it.
		for {
			m, err := tr.tryRead(buf)
			if err != nil || m == 0 {
				break
			}
			pkt = t.sealInto(s, buf[:m])
			if !batch.wants(pkt) {
				flush()
			}
			if batch.add(pkt) {
				break
			}
		}
		flush()
	}
}
