// Protocol and crypto core of the tunnel — OS-independent (testable on any platform).
//
// Anti-fingerprint (anti-DPI) design:
//   - No handshake and no fixed/signature bytes on the wire.
//   - Every datagram = [12-byte random nonce][ciphertext][16-byte tag]; the whole
//     thing is high-entropy and indistinguishable from random data.
//   - Sequence number (anti-replay) and padding live inside the encryption; invisible on the wire.
//   - Separate keys per direction + optional time-based key rotation (no exchange needed).
//
// Performance design: the packet path allocates nothing. seal and open take a caller-owned
// scratch struct (sealer/opener) that is reused for the life of the goroutine, the AEADs for
// the current epoch are reached through lock-free atomics, and randomness is drawn from a
// buffered CSPRNG instead of a syscall per packet. On a tunnel doing thousands of packets a
// second those three things were costing more than the cipher.
package main

import (
	"crypto/cipher"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// The largest datagram the tunnel will read or build. Defined here rather than in the
// Linux-only file so the OS-independent core can size its own buffers.
const maxPktSize = 65535

// innerHeaderLen is the plaintext framing that precedes the inner IP packet:
// 8 bytes of sequence number and 2 bytes of padding length.
const innerHeaderLen = 10

// aeadOverhead is the tag length. Both supported ciphers use 16, and both use a 12-byte
// nonce, which is what makes the suite invisible on the wire.
const aeadOverhead = 16

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

type Config struct {
	Role      string `json:"role"`      // "a" or "b" (must differ on the two servers)
	Key       string `json:"key"`       // shared key, base64 of 32 bytes (from the keygen subcommand)
	Cipher    string `json:"cipher"`    // "aes-gcm" (default) or "chacha20-poly1305"; must match on both ends
	Listen    string `json:"listen"`    // listen address, e.g. 0.0.0.0:51820
	Peer      string `json:"peer"`      // peer address host:port (optional; learned from traffic if empty)
	Transport string `json:"transport"` // carrier: "udp" (default), "tcp", or "icmp" — see icmp.go

	Obfs          string `json:"obfs"`           // "none" (default), "quic", "quic2" or "dtls" — see obfs.go / dtlsobfs.go
	Shape         *bool  `json:"shape"`          // quantise datagram sizes when obfs is on; default true
	SNI           string `json:"sni"`            // server name in the synthetic QUIC handshake
	TunName       string `json:"tun_name"`       // interface name, default tun0
	LocalIP       string `json:"local_ip"`       // local tunnel IP of this server as CIDR, e.g. 10.8.0.1/24
	PeerIP        string `json:"peer_ip"`        // peer tunnel IP (informational / for connectivity test)
	MTU           int    `json:"mtu"`            // interface MTU, default 1300
	TxQueueLen    int    `json:"txqueuelen"`     // interface tx queue length, default 1000
	RcvBuf        int    `json:"rcvbuf"`         // UDP socket receive buffer in bytes (0 = 2 MiB); a queue, so bigger is not better — see applyDefaults
	SndBuf        int    `json:"sndbuf"`         // UDP socket send buffer in bytes (0 = 2 MiB); oversizing this is bufferbloat
	PadMax        *int   `json:"pad_max"`        // max random padding bytes per packet (explicit 0 = disabled; omitted = 64)
	RekeyInterval uint64 `json:"rekey_interval"` // key rotation interval in seconds (0 = static key)
	ManageIP      *bool  `json:"manage_ip"`      // whether the program runs the ip commands itself; default true
	StatsPath     string `json:"stats_path"`     // stats file path for monitoring (empty = disabled)
	Keepalive     *int   `json:"keepalive"`      // keepalive interval in seconds (explicit 0 = disabled; omitted = 25)

	// --- performance ---
	Offload  *bool   `json:"offload"`   // use kernel UDP segmentation/coalescing; default true
	RateMbps float64 `json:"rate_mbps"` // shape the carrier to this rate; 0 = unlimited. See pacer.go —
	//                                      set it from a measurement of your own path, below any policer.
	GCPercent *int `json:"gc_percent"` // Go GC target; omitted = 100. The packet path allocates
	//                                          nothing, so there is no garbage to amortise and a
	//                                          higher target would only inflate RSS for no gain.
	MemLimit  int64  `json:"mem_limit"`  // soft heap limit in bytes; 0 = 64 MiB
	MaxProcs  int    `json:"max_procs"`  // GOMAXPROCS override; 0 = leave to the runtime
	PprofAddr string `json:"pprof_addr"` // e.g. 127.0.0.1:6060 to expose net/http/pprof; empty = off

	// --- observability ---
	DPILog DPILogConfig `json:"dpi_log"`

	// --- anti-DPI extensions (all off by default; see desync.go/junk.go/hop.go/split.go) ---
	Desync    DesyncConfig    `json:"desync"`     // native in-process fake injector (zapret nfqws, but ours)
	Junk      JunkConfig      `json:"junk"`       // flow-start cover traffic
	Hop       HopConfig       `json:"hop"`        // keyed synchronised port hopping
	Split     SplitConfig     `json:"split"`      // IP-fragment the disposable desync fakes
	TCPRotate TCPRotateConfig `json:"tcp_rotate"` // rotate the TCP carrier connection to dodge volumetric throttling

	// --- ICMP carrier (only consulted when transport is "icmp"; see icmp.go) ---
	ICMP ICMPConfig `json:"icmp"`
}

// ICMPConfig tunes the ICMP carrier (icmp.go).
//
// Read the two groups differently. Readers, Batch and KernelFilter are local performance
// choices: they change how this host talks to its own kernel and nothing on the wire, so the
// two ends may differ and the defaults are already right for a busy link. ID, IDPool,
// IDRotateSec and MimicPing change what the packets look like, so they are not negotiated
// and must be set identically on BOTH servers or every packet fails to authenticate.
type ICMPConfig struct {
	ID          int `json:"id"`            // fixed echo identifier (1-65535); 0 = derive it from the key
	IDPool      int `json:"id_pool"`       // identifiers to rotate through; default 1 (no rotation), max 8
	IDRotateSec int `json:"id_rotate_sec"` // seconds per identifier epoch; default 60

	Readers      int   `json:"readers"`          // receive goroutines; 0 = one per core, capped at 8
	Batch        *int  `json:"batch"`            // messages per sendmmsg/recvmmsg; default 32, 1 = off
	KernelFilter *bool `json:"kernel_filter"`    // attach the BPF filter to the raw socket; default true
	Suppress     *bool `json:"suppress_replies"` // install the echo-reply drop rule; default true

	// MimicPing prepends the 16-byte timeval that ping(8) puts at the start of its payload,
	// so a dissector renders the flow as ordinary pings with a plausible round-trip time
	// rather than as echo requests full of opaque bytes. It costs 16 bytes per packet and it
	// changes the wire, so it is off by default and must match on both ends.
	MimicPing *bool `json:"mimic_ping"`
}

func (c *ICMPConfig) applyDefaults() {
	if c.IDPool == 0 {
		c.IDPool = 1
	}
	if c.IDRotateSec == 0 {
		c.IDRotateSec = 60
	}
	if c.Batch == nil {
		v := 32
		c.Batch = &v
	}
	if c.KernelFilter == nil {
		v := true
		c.KernelFilter = &v
	}
	if c.Suppress == nil {
		v := true
		c.Suppress = &v
	}
	if c.MimicPing == nil {
		v := false
		c.MimicPing = &v
	}
}

// ---------------------------------------------------------------------------
// anti-DPI extension config. The runtime for each lives in its own file; the types and their
// defaults live here, next to Config, so the OS-independent core never depends on the
// Linux-only files that implement them.
// ---------------------------------------------------------------------------

// DesyncConfig configures the native fake injector (desync.go).
type DesyncConfig struct {
	Enabled  *bool  `json:"enabled"`   // master switch; default false
	Repeats  int    `json:"repeats"`   // fakes per burst; default 4
	TTL      int    `json:"ttl"`       // fixed TTL for fakes; 0 = use autottl
	AutoTTL  *bool  `json:"autottl"`   // derive TTL from the learned peer hop count; default true
	Delta    int    `json:"delta"`     // autottl delta added to the hop count; default -1 (die one hop early)
	MinTTL   int    `json:"min_ttl"`   // autottl clamp floor; default 3
	MaxTTL   int    `json:"max_ttl"`   // autottl clamp ceiling; default 20
	Badsum   *bool  `json:"badsum"`    // corrupt the fake's UDP checksum; default false
	SNI      string `json:"sni"`       // server name inside the fake Initials; default = top-level sni
	EverySec int    `json:"every_sec"` // periodic re-burst interval; 0 = only at start
}

func (c *DesyncConfig) applyDefaults() {
	if c.Enabled == nil {
		v := false
		c.Enabled = &v
	}
	if c.Repeats == 0 {
		c.Repeats = 4
	}
	if c.AutoTTL == nil {
		v := true
		c.AutoTTL = &v
	}
	if c.Delta == 0 {
		c.Delta = -1
	}
	if c.MinTTL == 0 {
		c.MinTTL = 3
	}
	if c.MaxTTL == 0 {
		c.MaxTTL = 20
	}
	if c.Badsum == nil {
		v := false
		c.Badsum = &v
	}
}

func (c *DesyncConfig) on() bool { return c != nil && c.Enabled != nil && *c.Enabled }

// JunkConfig configures flow-start cover traffic (junk.go).
type JunkConfig struct {
	Enabled *bool `json:"enabled"` // master switch; default false
	Count   int   `json:"count"`   // cover packets at flow start; default 8
	MinMs   int   `json:"min_ms"`  // minimum gap between cover packets; default 5
	MaxMs   int   `json:"max_ms"`  // maximum gap between cover packets; default 50
}

func (c *JunkConfig) applyDefaults() {
	if c.Enabled == nil {
		v := false
		c.Enabled = &v
	}
	if c.Count == 0 {
		c.Count = 8
	}
	if c.MinMs == 0 {
		c.MinMs = 5
	}
	if c.MaxMs == 0 {
		c.MaxMs = 50
	}
}

func (c *JunkConfig) on() bool { return c != nil && c.Enabled != nil && *c.Enabled }

// HopConfig configures keyed port hopping (hop.go).
type HopConfig struct {
	Enabled  *bool  `json:"enabled"`  // master switch; default false
	Ports    []int  `json:"ports"`    // the port set, identical and in the same order on both ends
	Interval uint64 `json:"interval"` // seconds per hop epoch; default 30
}

func (c *HopConfig) applyDefaults() {
	if c.Enabled == nil {
		v := false
		c.Enabled = &v
	}
	if c.Interval == 0 {
		c.Interval = 30
	}
	if len(c.Ports) == 0 {
		// A small set of common TLS-alternate ports, so opening them in a firewall draws
		// no attention. Both ends must carry the same list; the installer writes both.
		c.Ports = []int{443, 8443, 2053, 2083, 2087, 2096}
	}
}

func (c *HopConfig) on() bool { return c != nil && c.Enabled != nil && *c.Enabled }

// SplitConfig configures IP fragmentation of the desync fakes (split.go).
type SplitConfig struct {
	Enabled *bool `json:"enabled"`  // master switch; default false
	FragPos int   `json:"frag_pos"` // fragment position, bytes from the transport header (multiple of 8); default 24
}

func (c *SplitConfig) applyDefaults() {
	if c.Enabled == nil {
		v := false
		c.Enabled = &v
	}
	if c.FragPos == 0 {
		c.FragPos = 24
	}
}

func (c *SplitConfig) on() bool { return c != nil && c.Enabled != nil && *c.Enabled }

// TCPRotateConfig configures periodic rotation of the TCP carrier connection (tcprotate.go).
// It is the answer to Problem 3 from the field test: a single long-lived, high-rate TLS
// connection is volumetrically throttled by the DPI no matter how well it is disguised, because
// the throttle keys on the flow's rate and lifetime, not its bytes. Rotating the connection
// (a fresh 5-tuple, make-before-break) every interval keeps any one flow below whatever
// volume/duration the throttle is watching for. Only consulted when transport is tcp.
type TCPRotateConfig struct {
	Enabled     *bool `json:"enabled"`      // master switch; default false
	IntervalSec int   `json:"interval_sec"` // seconds a connection lives before it is rotated; default 15
}

func (c *TCPRotateConfig) applyDefaults() {
	if c.Enabled == nil {
		v := false
		c.Enabled = &v
	}
	if c.IntervalSec == 0 {
		c.IntervalSec = 15
	}
}

func (c *TCPRotateConfig) on() bool { return c != nil && c.Enabled != nil && *c.Enabled }

func (c *Config) applyDefaults() {
	if c.TunName == "" {
		c.TunName = "tun0"
	}
	if c.Transport == "" {
		c.Transport = "udp"
	}
	if c.Cipher == "" {
		// Unset means an existing deployment written before the field existed, and those
		// are all AES-GCM. Changing the default would silently break every such link.
		c.Cipher = cipherAESGCM
	}
	if c.Obfs == "" {
		c.Obfs = obfsNone
	}
	if c.SNI == "" {
		// Something ordinary and high-volume, so the name itself draws no attention.
		c.SNI = "www.cloudflare.com"
	}
	if c.Shape == nil {
		v := true
		c.Shape = &v // only consulted when obfs is enabled
	}
	if c.Listen == "" {
		c.Listen = "0.0.0.0:51820"
	}
	if c.MTU == 0 {
		c.MTU = 1300
	}
	if c.TxQueueLen == 0 {
		c.TxQueueLen = 1000
	}
	if c.RcvBuf == 0 {
		// 2 MiB. A socket buffer is a queue, and sizing it for peak throughput sizes it
		// for latency too — which on a tunnel carrying interactive traffic is the wrong
		// trade. Measured on the reference 650 Mbit/s link, saturated, ping across the
		// tunnel:
		//
		//	16 MiB both ways : 669 Mbit/s, +109 ms of queueing delay, 55 ms jitter
		//	 2 MiB both ways : 611 Mbit/s,  +22 ms,                    11 ms jitter
		//
		// So the old 16 MiB default bought 9% more peak throughput and paid five times
		// the delay for it. Both directions matter: an oversized *receive* buffer is just
		// as much of a backlog when the reader falls behind, and asymmetric sizing
		// (2 MiB send, 16 MiB receive) measured in between at +70 ms.
		//
		// Raise it if this link only ever moves bulk data and nothing interactive; the
		// kernel clamps the request to net.core.rmem_max either way.
		c.RcvBuf = 2 << 20
	}
	if c.SndBuf == 0 {
		c.SndBuf = 2 << 20
	}
	if c.PadMax == nil {
		v := 64
		c.PadMax = &v // omitted -> 64; an explicit 0 in config is preserved (padding disabled)
	}
	if c.ManageIP == nil {
		v := true
		c.ManageIP = &v
	}
	if c.StatsPath == "" {
		c.StatsPath = "/run/aestun/stats.json"
	}
	if c.Keepalive == nil {
		v := 25
		c.Keepalive = &v // omitted -> 25; an explicit 0 in config is preserved (keepalive disabled)
	}
	if c.Offload == nil {
		v := true
		c.Offload = &v
	}
	if c.GCPercent == nil {
		v := 100
		c.GCPercent = &v
	}
	if c.MemLimit == 0 {
		c.MemLimit = 64 << 20
	}
	c.DPILog.applyDefaults()
	c.Desync.applyDefaults()
	c.Junk.applyDefaults()
	c.Hop.applyDefaults()
	c.Split.applyDefaults()
	c.TCPRotate.applyDefaults()
	c.ICMP.applyDefaults()
}

// derefOr returns *p, or def when p is nil (for callers reached before applyDefaults ran).
func derefOr(p *int, def int) int {
	if p == nil {
		return def
	}
	return *p
}

// derefOr2 is derefOr for the *bool fields, which are pointers so that an explicit false in
// the config survives a default of true.
func derefOr2(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

// ---------------------------------------------------------------------------
// Anti-replay window (IPsec-style, circular)
// ---------------------------------------------------------------------------

type replayWindow struct {
	mu   sync.Mutex
	bits []uint64
	size uint64
	last uint64
	init bool
}

func newReplayWindow(size uint64) *replayWindow {
	if size%64 != 0 {
		size = (size/64 + 1) * 64
	}
	if size == 0 {
		size = 4096
	}
	return &replayWindow{bits: make([]uint64, size/64), size: size}
}

func (r *replayWindow) idx(seq uint64) (uint64, uint64) {
	i := seq % r.size
	return i / 64, i % 64
}
func (r *replayWindow) set(seq uint64)      { a, b := r.idx(seq); r.bits[a] |= 1 << b }
func (r *replayWindow) clr(seq uint64)      { a, b := r.idx(seq); r.bits[a] &^= 1 << b }
func (r *replayWindow) get(seq uint64) bool { a, b := r.idx(seq); return r.bits[a]&(1<<b) != 0 }

// check returns true and records the packet if it is fresh; false if replayed or too old.
func (r *replayWindow) check(seq uint64) bool {
	if seq == 0 {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.init {
		r.init = true
		r.last = seq
		r.set(seq)
		return true
	}
	if seq > r.last {
		diff := seq - r.last
		if diff >= r.size {
			for i := range r.bits {
				r.bits[i] = 0
			}
		} else {
			for s := r.last + 1; s < seq; s++ {
				r.clr(s)
			}
		}
		r.set(seq)
		r.last = seq
		return true
	}
	if r.last-seq >= r.size {
		return false // too old
	}
	if r.get(seq) {
		return false // duplicate
	}
	r.set(seq)
	return true
}

// ---------------------------------------------------------------------------
// Tunnel core: encrypt / decrypt
// ---------------------------------------------------------------------------

type Tunnel struct {
	psk     []byte
	suite   string // cipher suite name; see cipher.go
	sendDir string // "a->b" or "b->a"
	recvDir string
	rekey   uint64 // seconds; 0 = static
	padMax  int

	// display / monitoring info
	role      string
	transport string // "udp", "tcp" or "icmp"; the observer picks its kernel counters from it
	ifname    string
	listen    string
	startAt   time.Time

	cacheMu sync.Mutex
	cache   map[aeadKey]cipher.AEAD
	// Lock-free fast paths for the AEADs the packet loops need. The epoch changes once
	// per rekey interval (an hour by default), so these hit on effectively every packet
	// and the map+mutex path runs only at the boundary.
	sendCache atomic.Pointer[aeadEntry]
	recvCache atomic.Pointer[aeadEntry]

	// nil when obfs is disabled, in which case the wire format stays the plain
	// 12-byte-random-nonce one and remains compatible with peers that predate this layer.
	obfs *obfuscator

	// When port hopping is on the peer's port changes every epoch by design, so peer identity
	// is matched by IP alone; otherwise every hop would look like a roam. Set once at startup.
	hopMode bool

	// TCP-only: obfs=quic over a TCP carrier is shaped as TLS instead of QUIC (see tls.go),
	// because QUIC is a UDP protocol. When set, obfs is nil (the seal stays the plain format)
	// and the TLS disguise lives entirely at the tcpCarrier's framing layer.
	tlsShape bool

	// Which QUIC version the synthetic handshake cover claims. Only meaningful when obfs is
	// a QUIC mode; see quicinit.go for why this is configurable rather than fixed at v1.
	coverVer quicVer

	sendSeq uint64
	replay  *replayWindow

	// Last epoch a packet successfully opened under. Atomics, not a mutex: this is read
	// on every received packet and written once an hour.
	lastEpoch atomic.Uint64
	haveLast  atomic.Bool

	// The peer address, held as a netip.AddrPort behind an atomic pointer. A value type
	// rather than a *net.UDPAddr because the receive path compares against it on every
	// single packet: net.UDPAddr carries a heap-allocated IP slice, and the socket call
	// that produces one allocates it fresh per datagram. netip.AddrPort is comparable,
	// allocation-free, and reduces the whole check to a load and an equality test.
	peer atomic.Pointer[netip.AddrPort]

	// DPI / probe observer; never nil (a disabled one is a no-op).
	dpi *dpiLogger

	// atomic counters for monitoring
	txPackets  uint64
	txBytes    uint64
	rxPackets  uint64
	rxBytes    uint64
	authFail   uint64
	replayDrop uint64
	lastRxUnix int64
}

func newTunnel(cfg *Config, psk []byte) *Tunnel {
	sendDir, recvDir := "a->b", "b->a"
	if cfg.Role == "b" {
		sendDir, recvDir = "b->a", "a->b"
	}
	suite := cfg.Cipher
	if suite == "" {
		suite = cipherAESGCM
	}
	t := &Tunnel{
		psk:     psk,
		suite:   suite,
		sendDir: sendDir,
		recvDir: recvDir,
		rekey:   cfg.RekeyInterval,
		padMax:  derefOr(cfg.PadMax, 64),
		role:    cfg.Role,
		listen:  cfg.Listen,
		startAt: time.Now(),
		cache:   make(map[aeadKey]cipher.AEAD),
		// applyDefaults has already filled this in; read it here so the observer does not
		// need a second reference to Config.
		transport: cfg.Transport,
		// seq starts from the current time so that after a restart it does not
		// collide with the peer's replay window (real time only moves forward).
		sendSeq: uint64(time.Now().UnixMicro()),
		replay:  newReplayWindow(4096),
		dpi:     newDPILogger(&cfg.DPILog),
		hopMode: cfg.Hop.on(),
	}
	if obfsIsQUIC(cfg.Obfs) || cfg.Obfs == obfsDTLS {
		t.coverVer = quicVerFor(cfg.Obfs)
		if cfg.Transport == "tcp" && cfg.Obfs != obfsDTLS {
			// QUIC is a UDP protocol; over TCP the coherent disguise is TLS. The seal stays
			// the plain format (obfs nil) and the tcpCarrier wraps each datagram in a TLS
			// application-data record, opening with a synthetic TLS handshake (tls.go).
			t.tlsShape = true
		} else {
			shape := true
			if cfg.Shape != nil {
				shape = *cfg.Shape
			}
			wire := wireQUIC
			if cfg.Obfs == obfsDTLS {
				wire = wireDTLS
			}
			o, err := newObfuscator(psk, sendDir, recvDir, shape, wire)
			if err != nil {
				log.Fatalf("obfs init: %v", err)
			}
			t.obfs = o
		}
	}
	// Fail at startup rather than on the first packet if the suite name is wrong.
	if _, err := newAEAD(t.suite, hkdf(psk, nil, []byte("probe"), 32)); err != nil {
		log.Fatalf("cipher: %v", err)
	}
	return t
}

func (t *Tunnel) epochNow() uint64 {
	if t.rekey == 0 {
		return 0
	}
	return uint64(time.Now().Unix()) / t.rekey
}

// aeadKey identifies a derived cipher by direction and epoch. A struct key means the map
// lookup on the packet path allocates nothing, unlike the old "dir|epoch" string key which
// built a fresh string for every packet.
type aeadKey struct {
	send  bool
	epoch uint64
}

// aeadEntry is the lock-free cache payload: the AEAD for one epoch.
type aeadEntry struct {
	epoch uint64
	aead  cipher.AEAD
}

func (t *Tunnel) aead(send bool, epoch uint64) cipher.AEAD {
	k := aeadKey{send, epoch}
	t.cacheMu.Lock()
	defer t.cacheMu.Unlock()
	if a, ok := t.cache[k]; ok {
		return a
	}
	dir := t.recvDir
	if send {
		dir = t.sendDir
	}
	info := append([]byte("aestun-v1 "+dir+" "), make([]byte, 8)...)
	binary.BigEndian.PutUint64(info[len(info)-8:], epoch)
	kk := hkdf(t.psk, nil, info, 32)
	a, err := newAEAD(t.suite, kk)
	if err != nil {
		log.Fatalf("cipher: %v", err)
	}
	if len(t.cache) > 64 { // avoid unbounded growth over long uptime
		t.cache = make(map[aeadKey]cipher.AEAD)
	}
	t.cache[k] = a
	return a
}

// sendAEAD returns the AEAD for the current send epoch via the lock-free cache, falling back
// to aead() (which locks and derives) only when the epoch has rolled over.
func (t *Tunnel) sendAEAD(epoch uint64) cipher.AEAD {
	if e := t.sendCache.Load(); e != nil && e.epoch == epoch {
		return e.aead
	}
	a := t.aead(true, epoch)
	t.sendCache.Store(&aeadEntry{epoch: epoch, aead: a})
	return a
}

// recvAEAD is the read half of the same idea. It deliberately does not populate the cache
// on a miss: open() walks several candidate epochs and only one of them is the real one,
// so the cache is updated from the success path instead of thrashed by the failures.
func (t *Tunnel) recvAEAD(epoch uint64) cipher.AEAD {
	if e := t.recvCache.Load(); e != nil && e.epoch == epoch {
		return e.aead
	}
	return t.aead(false, epoch)
}

func (t *Tunnel) rememberEpoch(e uint64, a cipher.AEAD) {
	t.lastEpoch.Store(e)
	t.haveLast.Store(true)
	// Store only across a rollover, so the steady state does not allocate an entry per packet.
	if c := t.recvCache.Load(); c == nil || c.epoch != e {
		t.recvCache.Store(&aeadEntry{epoch: e, aead: a})
	}
}

// recvEpochs fills buf with the epochs to try when opening a packet, most-likely first, and
// returns the count. It allocates nothing and takes no locks: the old version built a map and
// a slice on every received packet and took a mutex to read the last epoch, which at tunnel
// packet rates was a steady stream of garbage and contention for the GC and scheduler.
// The candidate set is tiny (<=4) so deduping with a linear scan is cheaper than a map anyway.
func (t *Tunnel) recvEpochs(buf *[4]uint64) int {
	if t.rekey == 0 {
		buf[0] = 0
		return 1
	}
	cur := t.epochNow()
	have := t.haveLast.Load()
	last := t.lastEpoch.Load()

	n := 0
	// Inlined add-if-absent, deliberately not a closure: a closure over n/buf would escape
	// to the heap and reintroduce the per-packet allocation this change removes.
	if have {
		buf[n] = last
		n++
	}
	for _, e := range [3]uint64{cur, cur - 1, cur + 1} {
		if cur == 0 && e == cur-1 { // cur-1 underflows to a huge value; skip as before
			continue
		}
		dup := false
		for i := 0; i < n; i++ {
			if buf[i] == e {
				dup = true
				break
			}
		}
		if !dup {
			buf[n] = e
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// sealer / opener — per-goroutine scratch so the packet path allocates nothing
// ---------------------------------------------------------------------------

// A sealer holds the scratch buffers and the randomness source for one sending goroutine.
// It is not safe for concurrent use; the TUN pump and the keepalive loop own one each.
type sealer struct {
	inner []byte
	out   []byte
	rng   *csprng
	hdr   [obfsHeaderLen]byte
	nonce [12]byte
	hp    hpScratch
}

func newSealer() *sealer {
	// Sized for the largest datagram the tunnel will ever build, so the make() calls in
	// sealInto never fire in practice and the path is allocation-free from the first packet.
	const room = maxPktSize + obfsHeaderLen + innerHeaderLen + aeadOverhead + 256
	return &sealer{
		inner: make([]byte, room),
		out:   make([]byte, room),
		rng:   newCSPRNG(),
	}
}

// An opener holds the scratch buffer for one receiving goroutine. The slice returned by
// openInto aliases that buffer and stays valid only until the next call on the same opener.
type opener struct {
	plain []byte
	nonce [12]byte
	hp    hpScratch
}

func newOpener() *opener {
	return &opener{plain: make([]byte, maxPktSize+256)}
}

// sealInto takes an IP packet and returns the encrypted datagram ready to send. The result
// aliases s.out and is only valid until the next call with the same sealer.
func (t *Tunnel) sealInto(s *sealer, plain []byte) []byte {
	epoch := t.epochNow()
	aead := t.sendAEAD(epoch)

	// With obfs on, the header doubles as the nonce (connection ID + packet number);
	// with it off, the header *is* a random nonce and the format is byte-identical to
	// what peers running the pre-obfs build expect.
	var hdrLen int
	if t.obfs != nil {
		t.obfs.nextHeader(&s.hdr, &s.nonce)
		hdrLen = obfsHeaderLen
	} else {
		s.rng.read(s.nonce[:])
		copy(s.hdr[:12], s.nonce[:])
		hdrLen = 12
	}

	pad := t.padFor(hdrLen, len(plain), s.rng)

	seq := atomic.AddUint64(&t.sendSeq, 1)
	need := innerHeaderLen + len(plain) + pad
	if cap(s.inner) < need {
		s.inner = make([]byte, need)
	}
	inner := s.inner[:need]
	binary.BigEndian.PutUint64(inner[0:8], seq)
	binary.BigEndian.PutUint16(inner[8:10], uint16(pad))
	copy(inner[innerHeaderLen:], plain)
	if pad > 0 {
		s.rng.read(inner[innerHeaderLen+len(plain):])
	}

	if cap(s.out) < hdrLen+need+aeadOverhead {
		s.out = make([]byte, hdrLen+need+aeadOverhead)
	}
	out := s.out[:hdrLen]
	copy(out, s.hdr[:hdrLen])
	// Seal appends into out's spare capacity, so no allocation happens here.
	out = aead.Seal(out, s.nonce[:], inner, nil)
	if t.obfs != nil {
		// Applied last: the mask is derived from the finished ciphertext.
		t.obfs.protect(out, &s.hp)
	}

	atomic.AddUint64(&t.txPackets, 1)
	atomic.AddUint64(&t.txBytes, uint64(len(out)))
	return out
}

// padFor decides how much padding to add inside the encryption. Shaping mode targets the
// size buckets so the datagram lands on one of a handful of lengths; otherwise it adds a
// random amount up to pad_max.
func (t *Tunnel) padFor(hdrLen, plainLen int, rng *csprng) int {
	if t.obfs != nil && t.obfs.shape {
		base := hdrLen + innerHeaderLen + plainLen + aeadOverhead
		if pad := obfsPadTo(base); pad > 0 && pad <= 65535 {
			return pad
		}
		return 0
	}
	if t.padMax <= 0 {
		return 0
	}
	// Drawn from the buffered CSPRNG. The previous version reused the first two nonce
	// bytes, which is fine when the nonce is random but silently degenerates with obfs
	// enabled: there those bytes are the connection ID, constant for the whole connection,
	// so every packet got the *same* padding length and the shaping it was meant to
	// provide disappeared.
	return int(rng.uint16()) % (t.padMax + 1)
}

// openSeq decrypts, authenticates, replay-checks, and hands back
// the inner sequence number along with the packet. The sequence number costs nothing to
// return — it was parsed anyway — and it is the only signal available that distinguishes
// packets the network dropped from packets that were never sent, which is what the DPI
// observer needs to measure loss and reordering on the authenticated stream.
func (t *Tunnel) openSeq(o *opener, pkt []byte) (plain []byte, seq uint64, ok bool) {
	var nonce, ct []byte
	if t.obfs != nil {
		if len(pkt) < obfsHeaderLen+aeadOverhead {
			return nil, 0, false
		}
		if !t.obfs.unprotectInto(pkt, &o.nonce, &o.hp) {
			return nil, 0, false
		}
		nonce = o.nonce[:]
		ct = pkt[obfsHeaderLen:]
	} else {
		if len(pkt) < 12+aeadOverhead {
			return nil, 0, false
		}
		nonce = pkt[:12]
		ct = pkt[12:]
	}
	if cap(o.plain) < len(ct) {
		o.plain = make([]byte, len(ct))
	}
	var epochs [4]uint64
	nEpochs := t.recvEpochs(&epochs)
	for _, epoch := range epochs[:nEpochs] {
		aead := t.recvAEAD(epoch)
		inner, err := aead.Open(o.plain[:0], nonce, ct, nil)
		if err != nil {
			continue
		}
		if len(inner) < innerHeaderLen {
			return nil, 0, false
		}
		s := binary.BigEndian.Uint64(inner[0:8])
		pad := int(binary.BigEndian.Uint16(inner[8:10]))
		if innerHeaderLen+pad > len(inner) {
			return nil, 0, false
		}
		if !t.replay.check(s) {
			atomic.AddUint64(&t.replayDrop, 1)
			return nil, s, false
		}
		t.rememberEpoch(epoch, aead)
		atomic.AddUint64(&t.rxPackets, 1)
		atomic.AddUint64(&t.rxBytes, uint64(len(pkt)))
		atomic.StoreInt64(&t.lastRxUnix, time.Now().Unix())
		return inner[innerHeaderLen : len(inner)-pad], s, true
	}
	atomic.AddUint64(&t.authFail, 1)
	return nil, 0, false
}

func (t *Tunnel) setPeer(a netip.AddrPort) {
	t.peer.Store(&a)
}

// getPeer returns the current peer and whether one is known.
func (t *Tunnel) getPeer() (netip.AddrPort, bool) {
	p := t.peer.Load()
	if p == nil {
		return netip.AddrPort{}, false
	}
	return *p, true
}

// samePeer reports whether src is the address the tunnel is currently talking to. On the
// receive path this runs for every datagram, so it is deliberately a pointer load and a
// value comparison and nothing else. Under port hopping the port is expected to change every
// epoch, so identity is matched by IP alone.
func (t *Tunnel) samePeer(src netip.AddrPort) bool {
	p := t.peer.Load()
	if p == nil {
		return false
	}
	if t.hopMode {
		return p.Addr() == src.Addr()
	}
	return *p == src
}

func (t *Tunnel) maybeRoam(src netip.AddrPort) {
	p := t.peer.Load()
	if p != nil {
		if t.hopMode {
			// Same host, different port each epoch — expected, not a roam. Keep the stored
			// port in step (so getPeer stays current for any non-hopping consumer) silently.
			if p.Addr() == src.Addr() {
				if *p != src {
					t.setPeer(src)
				}
				return
			}
		} else if *p == src {
			return
		}
	}
	old := ""
	if p != nil {
		old = p.String()
	}
	t.setPeer(src)
	t.dpi.peerRoamed(old, src.String())
}

// writeStats writes the current stats to disk as JSON every 2 seconds (for the monitor menu).
func (t *Tunnel) writeStats(path string) {
	if path == "" {
		return
	}
	os.MkdirAll(filepath.Dir(path), 0o755)
	tmp := path + ".tmp"
	for {
		time.Sleep(2 * time.Second)
		peer := ""
		if p, ok := t.getPeer(); ok {
			peer = p.String()
		}
		s := map[string]any{
			"role":           t.role,
			"cipher":         t.suite,
			"iface":          t.ifname,
			"listen":         t.listen,
			"peer":           peer,
			"rekey_interval": t.rekey,
			"uptime_seconds": int64(time.Since(t.startAt).Seconds()),
			"tx_packets":     atomic.LoadUint64(&t.txPackets),
			"tx_bytes":       atomic.LoadUint64(&t.txBytes),
			"rx_packets":     atomic.LoadUint64(&t.rxPackets),
			"rx_bytes":       atomic.LoadUint64(&t.rxBytes),
			"auth_fail":      atomic.LoadUint64(&t.authFail),
			"replay_drop":    atomic.LoadUint64(&t.replayDrop),
			"last_rx_unix":   atomic.LoadInt64(&t.lastRxUnix),
			"now_unix":       time.Now().Unix(),
		}
		t.dpi.addStats(s)
		b, err := json.MarshalIndent(s, "", "  ")
		if err != nil {
			continue
		}
		if os.WriteFile(tmp, b, 0o644) == nil {
			os.Rename(tmp, path)
		}
	}
}

// describe is the one-line startup banner.
func (t *Tunnel) describe(cfg *Config) string {
	rekeyDesc := "static"
	if cfg.RekeyInterval > 0 {
		rekeyDesc = fmt.Sprintf("every %ds", cfg.RekeyInterval)
	}
	rate := "unlimited"
	if cfg.RateMbps > 0 {
		rate = fmt.Sprintf("%.0f Mbit/s", cfg.RateMbps)
	}
	return fmt.Sprintf("role=%s transport=%s cipher=%s obfs=%s listen=%s peer=%s mtu=%d pad_max=%d keepalive=%d rekey=%s dpi_log=%v rate=%s",
		cfg.Role, cfg.Transport, t.suite, cfg.Obfs, cfg.Listen, cfg.Peer, cfg.MTU,
		derefOr(cfg.PadMax, 64), derefOr(cfg.Keepalive, 25), rekeyDesc, t.dpi.enabled(), rate)
}
