// Protocol and crypto core of the tunnel — OS-independent (testable on any platform).
//
// Anti-fingerprint (anti-DPI) design:
//   - No handshake and no fixed/signature bytes on the wire.
//   - Every datagram = [12-byte random nonce][ciphertext][16-byte tag]; the whole
//     thing is high-entropy and indistinguishable from random data.
//   - Sequence number (anti-replay) and padding live inside the encryption; invisible on the wire.
//   - Separate keys per direction + optional time-based key rotation (no exchange needed).
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

type Config struct {
	Role          string `json:"role"`           // "a" or "b" (must differ on the two servers)
	Key           string `json:"key"`            // shared key, base64 of 32 bytes (from the keygen subcommand)
	Listen        string `json:"listen"`         // listen address, e.g. 0.0.0.0:51820
	Peer          string `json:"peer"`           // peer address host:port (optional; learned from traffic if empty)
	Transport     string `json:"transport"`      // carrier: "udp" (default) or "tcp"
	Obfs          string `json:"obfs"`           // "none" (default) or "quic" — see obfs.go
	Shape         *bool  `json:"shape"`          // quantise datagram sizes when obfs is on; default true
	SNI           string `json:"sni"`            // server name in the synthetic QUIC handshake
	TunName       string `json:"tun_name"`       // interface name, default tun0
	LocalIP       string `json:"local_ip"`       // local tunnel IP of this server as CIDR, e.g. 10.8.0.1/24
	PeerIP        string `json:"peer_ip"`        // peer tunnel IP (informational / for connectivity test)
	MTU           int    `json:"mtu"`            // interface MTU, default 1300
	TxQueueLen    int    `json:"txqueuelen"`     // interface tx queue length, default 1000
	RcvBuf        int    `json:"rcvbuf"`         // UDP socket receive buffer in bytes (0 = 8 MiB); needs net.core.rmem_max >= this
	SndBuf        int    `json:"sndbuf"`         // UDP socket send buffer in bytes (0 = 8 MiB); needs net.core.wmem_max >= this
	PadMax        *int   `json:"pad_max"`        // max random padding bytes per packet (explicit 0 = disabled; omitted = 64)
	RekeyInterval uint64 `json:"rekey_interval"` // key rotation interval in seconds (0 = static key)
	ManageIP      *bool  `json:"manage_ip"`      // whether the program runs the ip commands itself; default true
	StatsPath     string `json:"stats_path"`     // stats file path for monitoring (empty = disabled)
	Keepalive     *int   `json:"keepalive"`      // keepalive interval in seconds (explicit 0 = disabled; omitted = 25)
}

func (c *Config) applyDefaults() {
	if c.TunName == "" {
		c.TunName = "tun0"
	}
	if c.Transport == "" {
		c.Transport = "udp"
	}
	if c.Obfs == "" {
		c.Obfs = "none"
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
		c.RcvBuf = 8 << 20 // 8 MiB — absorbs traffic bursts so the kernel doesn't drop (RcvbufErrors)
	}
	if c.SndBuf == 0 {
		c.SndBuf = 8 << 20
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
}

// derefOr returns *p, or def when p is nil (for callers that skip applyDefaults, e.g. tests).
func derefOr(p *int, def int) int {
	if p == nil {
		return def
	}
	return *p
}

// ---------------------------------------------------------------------------
// HKDF (RFC 5869) over HMAC-SHA256 — short, dependency-free implementation
// ---------------------------------------------------------------------------

func hkdf(secret, salt, info []byte, n int) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	// Extract
	m := hmac.New(sha256.New, salt)
	m.Write(secret)
	prk := m.Sum(nil)
	// Expand
	var out, t []byte
	for i := 1; len(out) < n; i++ {
		h := hmac.New(sha256.New, prk)
		h.Write(t)
		h.Write(info)
		h.Write([]byte{byte(i)})
		t = h.Sum(nil)
		out = append(out, t...)
	}
	return out[:n]
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
	sendDir string // "a->b" or "b->a"
	recvDir string
	rekey   uint64 // seconds; 0 = static
	padMax  int

	// display / monitoring info
	role    string
	ifname  string
	listen  string
	startAt time.Time

	cacheMu sync.Mutex
	cache   map[aeadKey]cipher.AEAD
	// Lock-free fast path for the send AEAD, which every outgoing packet needs. The epoch
	// changes once per rekey interval (an hour by default), so this hits on effectively
	// every packet and the map+mutex path runs only at the boundary.
	sendCache atomic.Pointer[aeadEntry]

	// nil when obfs is disabled, in which case the wire format stays the plain
	// 12-byte-random-nonce one and remains compatible with peers that predate this layer.
	obfs *obfuscator

	sendSeq uint64
	replay  *replayWindow

	epMu      sync.Mutex
	lastEpoch uint64
	haveLast  bool

	peerMu sync.RWMutex
	peer   *net.UDPAddr

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
	t := &Tunnel{
		psk:     psk,
		sendDir: sendDir,
		recvDir: recvDir,
		rekey:   cfg.RekeyInterval,
		padMax:  derefOr(cfg.PadMax, 64),
		role:    cfg.Role,
		listen:  cfg.Listen,
		startAt: time.Now(),
		cache:   make(map[aeadKey]cipher.AEAD),
		// seq starts from the current time so that after a restart it does not
		// collide with the peer's replay window (real time only moves forward).
		sendSeq: uint64(time.Now().UnixMicro()),
		replay:  newReplayWindow(4096),
	}
	if cfg.Obfs == "quic" {
		shape := true
		if cfg.Shape != nil {
			shape = *cfg.Shape
		}
		o, err := newObfuscator(psk, sendDir, recvDir, shape)
		if err != nil {
			log.Fatalf("obfs init: %v", err)
		}
		t.obfs = o
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

// aeadEntry is the lock-free send-cache payload: the AEAD for one epoch.
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
	blk, err := aes.NewCipher(kk)
	if err != nil {
		log.Fatalf("aes: %v", err)
	}
	a, err := cipher.NewGCM(blk)
	if err != nil {
		log.Fatalf("gcm: %v", err)
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

func (t *Tunnel) rememberEpoch(e uint64) {
	t.epMu.Lock()
	t.lastEpoch = e
	t.haveLast = true
	t.epMu.Unlock()
}

// recvEpochs fills buf with the epochs to try when opening a packet, most-likely first, and
// returns the count. It allocates nothing: the old version built a map and a slice on every
// received packet, which at tunnel packet rates was a steady stream of garbage for the GC.
// The candidate set is tiny (≤4) so deduping with a linear scan is cheaper than a map anyway.
func (t *Tunnel) recvEpochs(buf *[4]uint64) int {
	if t.rekey == 0 {
		buf[0] = 0
		return 1
	}
	cur := t.epochNow()
	t.epMu.Lock()
	last, have := t.lastEpoch, t.haveLast
	t.epMu.Unlock()

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

// seal takes an IP packet and returns the encrypted datagram ready to send.
func (t *Tunnel) seal(plain []byte) []byte {
	epoch := t.epochNow()
	aead := t.sendAEAD(epoch)

	// With obfs on, the header doubles as the nonce (connection ID + packet number);
	// with it off, the header *is* a random nonce and the format is byte-identical to
	// what peers running the pre-obfs build expect.
	var hdr, nonce []byte
	if t.obfs != nil {
		hdr, nonce, _ = t.obfs.nextHeader()
	} else {
		nonce = make([]byte, 12)
		if _, err := rand.Read(nonce); err != nil {
			log.Fatalf("rand: %v", err)
		}
		hdr = nonce
	}

	pad := t.padFor(len(hdr), len(plain), nonce)

	seq := atomic.AddUint64(&t.sendSeq, 1)
	inner := make([]byte, 10+len(plain)+pad)
	binary.BigEndian.PutUint64(inner[0:8], seq)
	binary.BigEndian.PutUint16(inner[8:10], uint16(pad))
	copy(inner[10:], plain)
	if pad > 0 {
		rand.Read(inner[10+len(plain):])
	}

	out := make([]byte, len(hdr), len(hdr)+len(inner)+16)
	copy(out, hdr)
	out = aead.Seal(out, nonce, inner, nil)
	if t.obfs != nil {
		// Applied last: the mask is derived from the finished ciphertext.
		t.obfs.protect(out)
	}

	atomic.AddUint64(&t.txPackets, 1)
	atomic.AddUint64(&t.txBytes, uint64(len(out)))
	return out
}

// padFor decides how much padding to add inside the encryption. Shaping mode targets the
// size buckets so the datagram lands on one of a handful of lengths; otherwise it keeps the
// original behaviour of a random amount up to pad_max.
func (t *Tunnel) padFor(hdrLen, plainLen int, nonce []byte) int {
	if t.obfs != nil && t.obfs.shape {
		// 10 bytes of inner header, 16 bytes of GCM tag.
		base := hdrLen + 10 + plainLen + 16
		if pad := obfsPadTo(base); pad > 0 && pad <= 65535 {
			return pad
		}
		return 0
	}
	if t.padMax <= 0 {
		return 0
	}
	return (int(nonce[0])<<8 | int(nonce[1])) % (t.padMax + 1) // reuse nonce entropy
}

// open decrypts and authenticates a received datagram, returning the inner IP packet.
func (t *Tunnel) open(pkt []byte) ([]byte, bool) {
	var nonce, ct []byte
	if t.obfs != nil {
		if len(pkt) < obfsHeaderLen+16 {
			return nil, false
		}
		var ok bool
		if nonce, ok = t.obfs.unprotect(pkt); !ok {
			return nil, false
		}
		ct = pkt[obfsHeaderLen:]
	} else {
		if len(pkt) < 12+16 {
			return nil, false
		}
		nonce = pkt[:12]
		ct = pkt[12:]
	}
	var epochs [4]uint64
	nEpochs := t.recvEpochs(&epochs)
	for _, epoch := range epochs[:nEpochs] {
		aead := t.aead(false, epoch)
		inner, err := aead.Open(nil, nonce, ct, nil)
		if err != nil {
			continue // wrong key/epoch or forged packet
		}
		if len(inner) < 10 {
			return nil, false
		}
		seq := binary.BigEndian.Uint64(inner[0:8])
		pad := int(binary.BigEndian.Uint16(inner[8:10]))
		if 10+pad > len(inner) {
			return nil, false
		}
		if !t.replay.check(seq) {
			atomic.AddUint64(&t.replayDrop, 1)
			return nil, false // replayed packet
		}
		t.rememberEpoch(epoch)
		atomic.AddUint64(&t.rxPackets, 1)
		atomic.AddUint64(&t.rxBytes, uint64(len(pkt)))
		atomic.StoreInt64(&t.lastRxUnix, time.Now().Unix())
		return inner[10 : len(inner)-pad], true
	}
	atomic.AddUint64(&t.authFail, 1)
	return nil, false
}

func (t *Tunnel) setPeer(a *net.UDPAddr) {
	t.peerMu.Lock()
	t.peer = a
	t.peerMu.Unlock()
}
func (t *Tunnel) getPeer() *net.UDPAddr {
	t.peerMu.RLock()
	defer t.peerMu.RUnlock()
	return t.peer
}
func (t *Tunnel) maybeRoam(src *net.UDPAddr) {
	cur := t.getPeer()
	if cur == nil || !cur.IP.Equal(src.IP) || cur.Port != src.Port {
		t.setPeer(src)
	}
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
		if p := t.getPeer(); p != nil {
			peer = p.String()
		}
		s := map[string]any{
			"role":           t.role,
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
		b, err := json.MarshalIndent(s, "", "  ")
		if err != nil {
			continue
		}
		if os.WriteFile(tmp, b, 0o644) == nil {
			os.Rename(tmp, path)
		}
	}
}
