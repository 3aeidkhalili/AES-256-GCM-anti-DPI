package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

func tunPair(t testing.TB, suite string, obfs string, rekey uint64) (*Tunnel, *Tunnel) {
	t.Helper()
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}
	mk := func(role string) *Tunnel {
		c := &Config{Role: role, Cipher: suite, Obfs: obfs, RekeyInterval: rekey}
		c.applyDefaults()
		c.Obfs = obfs
		c.Cipher = suite
		off := false
		c.DPILog.Enabled = &off // no background goroutines or log files in tests
		return newTunnel(c, psk)
	}
	return mk("a"), mk("b")
}

// ---------------------------------------------------------------------------
// cipher suites
// ---------------------------------------------------------------------------

func TestBothCipherSuitesRoundTrip(t *testing.T) {
	for _, suite := range []string{cipherAESGCM, cipherChaCha} {
		for _, obfs := range []string{"none", "quic"} {
			a, b := tunPair(t, suite, obfs, 3600)
			for _, n := range []int{0, 1, 40, 576, 1300, 1400, 4000} {
				msg := bytes.Repeat([]byte{byte(n)}, n)
				got, ok := b.open(a.seal(msg))
				if !ok {
					t.Fatalf("%s/%s size %d: did not authenticate", suite, obfs, n)
				}
				if !bytes.Equal(got, msg) {
					t.Fatalf("%s/%s size %d: payload mismatch", suite, obfs, n)
				}
			}
		}
	}
}

// The two suites must not interoperate — a silent mismatch would look like a dead tunnel
// with no explanation, so it is worth asserting that it fails cleanly rather than partially.
func TestCipherMismatchFailsClosed(t *testing.T) {
	psk := make([]byte, 32)
	rand.Read(psk)
	mk := func(role, suite string) *Tunnel {
		c := &Config{Role: role, Cipher: suite, Obfs: "quic", RekeyInterval: 0}
		c.applyDefaults()
		c.Obfs = "quic"
		c.Cipher = suite
		off := false
		c.DPILog.Enabled = &off
		return newTunnel(c, psk)
	}
	a := mk("a", cipherAESGCM)
	b := mk("b", cipherChaCha)
	if _, ok := b.open(a.seal([]byte("hello"))); ok {
		t.Fatal("a packet sealed with AES-GCM must not open under ChaCha20-Poly1305")
	}
}

// The wire layout must not depend on the suite: same header, same overhead. If it did, the
// choice would be visible to an observer, which is the one thing this project cannot accept.
func TestCipherChoiceIsNotVisibleOnTheWire(t *testing.T) {
	payload := bytes.Repeat([]byte{7}, 600)
	sizes := map[string]int{}
	for _, suite := range []string{cipherAESGCM, cipherChaCha} {
		a, _ := tunPair(t, suite, "quic", 0)
		sizes[suite] = len(a.seal(payload))
	}
	if sizes[cipherAESGCM] != sizes[cipherChaCha] {
		t.Fatalf("datagram size differs by cipher: aes=%d chacha=%d", sizes[cipherAESGCM], sizes[cipherChaCha])
	}
}

// ---------------------------------------------------------------------------
// allocation behaviour — the point of the sealer/opener rework
// ---------------------------------------------------------------------------

func TestSealIntoDoesNotAllocate(t *testing.T) {
	a, _ := tunPair(t, cipherChaCha, "quic", 3600)
	s := newSealer()
	p := bytes.Repeat([]byte{1}, 1300)
	// Warm the epoch caches and the CSPRNG buffer first; the very first packet legitimately
	// derives a key and draws a page of randomness.
	for i := 0; i < 64; i++ {
		a.sealInto(s, p)
	}
	if n := testing.AllocsPerRun(500, func() { a.sealInto(s, p) }); n != 0 {
		t.Fatalf("sealInto allocated %.1f objects per call, want 0", n)
	}
}

func TestOpenIntoDoesNotAllocate(t *testing.T) {
	a, b := tunPair(t, cipherChaCha, "quic", 3600)
	s := newSealer()
	o := newOpener()
	p := bytes.Repeat([]byte{2}, 1300)

	// Build a batch up front so the measured loop only decrypts.
	pkts := make([][]byte, 512)
	for i := range pkts {
		out := a.sealInto(s, p)
		pkts[i] = append([]byte(nil), out...)
	}
	for i := 0; i < 8; i++ {
		b.openInto(o, pkts[i])
	}
	i := 8
	if n := testing.AllocsPerRun(400, func() {
		b.openInto(o, pkts[i%len(pkts)])
		i++
	}); n != 0 {
		t.Fatalf("openInto allocated %.1f objects per call, want 0", n)
	}
}

// ---------------------------------------------------------------------------
// padding
// ---------------------------------------------------------------------------

// With obfs on and shaping off, padding used to be derived from the first two nonce bytes —
// which under obfs are the connection ID, constant for the whole connection. Every packet
// therefore got identical padding and the size randomisation silently did nothing.
func TestPaddingVariesWithObfsAndShapingOff(t *testing.T) {
	psk := make([]byte, 32)
	rand.Read(psk)
	shape := false
	c := &Config{Role: "a", Obfs: "quic", Shape: &shape, RekeyInterval: 0}
	c.applyDefaults()
	c.Obfs = "quic"
	c.Shape = &shape
	off := false
	c.DPILog.Enabled = &off
	a := newTunnel(c, psk)

	s := newSealer()
	p := bytes.Repeat([]byte{3}, 200)
	seen := map[int]bool{}
	for i := 0; i < 200; i++ {
		seen[len(a.sealInto(s, p))] = true
	}
	if len(seen) < 8 {
		t.Fatalf("expected a spread of datagram sizes from random padding, saw only %d distinct", len(seen))
	}
}

// Shaping must still land packets on the declared buckets.
func TestShapingHitsBuckets(t *testing.T) {
	a, _ := tunPair(t, cipherAESGCM, "quic", 0)
	s := newSealer()
	for _, n := range []int{1, 50, 200, 400, 700, 900} {
		got := len(a.sealInto(s, bytes.Repeat([]byte{9}, n)))
		ok := false
		for _, b := range obfsBuckets {
			if got == b {
				ok = true
			}
		}
		if !ok {
			t.Fatalf("payload %d produced a %d-byte datagram, which is not a shaping bucket", n, got)
		}
	}
}

// ---------------------------------------------------------------------------
// buffered randomness
// ---------------------------------------------------------------------------

func TestCSPRNGRefillsAndDoesNotRepeat(t *testing.T) {
	r := newCSPRNG()
	seen := map[string]bool{}
	buf := make([]byte, 12)
	// Draw well past one buffer's worth so the refill path is exercised.
	for i := 0; i < csprngBufSize/12*3; i++ {
		r.read(buf)
		k := string(buf)
		if seen[k] {
			t.Fatalf("repeated 12-byte draw after %d iterations — the buffer is not advancing", i)
		}
		seen[k] = true
	}
}

func TestCSPRNGZeroesWhatItHandedOut(t *testing.T) {
	r := newCSPRNG()
	buf := make([]byte, 64)
	r.read(buf)
	if allZero(r.buf[:64]) == false {
		t.Fatal("consumed bytes must be zeroed after being handed out")
	}
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// control frames
// ---------------------------------------------------------------------------

// A control frame must never be confused with a real IP packet, in either direction.
func TestControlFrameNeverLooksLikeIP(t *testing.T) {
	buf := make([]byte, ctrlFrameLen)
	f := buildCtrl(buf, ctrlPing, time.Now().UnixNano(), 0)
	if !isControlFrame(f) {
		t.Fatal("a freshly built control frame must be recognised")
	}
	// Minimal IPv4 and IPv6 headers.
	v4 := make([]byte, 20)
	v4[0] = 0x45
	v6 := make([]byte, 40)
	v6[0] = 0x60
	if isControlFrame(v4) {
		t.Fatal("an IPv4 packet must not be taken for a control frame")
	}
	if isControlFrame(v6) {
		t.Fatal("an IPv6 packet must not be taken for a control frame")
	}
	// Too short to be a frame, even with the right first byte.
	if isControlFrame([]byte{0x00, ctrlPing}) {
		t.Fatal("a truncated frame must be rejected")
	}
}

func TestControlFrameRoundTripThroughTunnel(t *testing.T) {
	a, b := tunPair(t, cipherChaCha, "quic", 0)
	buf := make([]byte, ctrlFrameLen)
	now := time.Now().UnixNano()
	f := buildCtrl(buf, ctrlPing, now, 0)
	got, ok := b.open(a.seal(f))
	if !ok {
		t.Fatal("control frame did not survive the tunnel")
	}
	if !isControlFrame(got) {
		t.Fatal("control frame was not recognised after decryption")
	}
	if int64(binary.BigEndian.Uint64(got[2:10])) != now {
		t.Fatal("timestamp did not survive")
	}
}

// ---------------------------------------------------------------------------
// DPI observer
// ---------------------------------------------------------------------------

func testLogger(t testing.TB) *dpiLogger {
	t.Helper()
	on := true
	cfg := &DPILogConfig{Enabled: &on, Path: t.TempDir() + "/dpi.jsonl"}
	cfg.applyDefaults()
	return newDPILogger(cfg)
}

// The TTL detector must learn the peer's hop count before it starts making accusations,
// and must then fire on a packet that disagrees.
func TestTTLAnomalyDetection(t *testing.T) {
	d := testLogger(t)
	for i := 0; i < 8; i++ {
		d.observePeerPacket(uint64(i+1), 52)
	}
	if got := d.peerTTL.Load(); got != 52 {
		t.Fatalf("expected the peer TTL to be learned as 52, got %d", got)
	}
	if n := d.cTTLAnom.Load(); n != 0 {
		t.Fatalf("no anomaly should have been raised while learning, got %d", n)
	}
	d.observePeerPacket(100, 64) // an injector, guessing the hop count wrong
	if n := d.cTTLAnom.Load(); n != 1 {
		t.Fatalf("expected exactly one TTL anomaly, got %d", n)
	}
}

func TestTTLLearningResistsASingleForgedPacket(t *testing.T) {
	d := testLogger(t)
	// One odd packet first, then the real ones. The baseline must come from the majority,
	// not from whichever packet happened to arrive first.
	d.observePeerPacket(1, 200)
	for i := 0; i < 8; i++ {
		d.observePeerPacket(uint64(i+2), 52)
	}
	if got := d.peerTTL.Load(); got == 200 {
		t.Fatal("a single forged packet must not become the TTL baseline")
	}
}

func TestReorderAccounting(t *testing.T) {
	d := testLogger(t)
	for _, s := range []uint64{1, 2, 3, 7, 5, 8, 6} {
		d.observePeerPacket(s, 0)
	}
	if got := d.seqReorder.Load(); got != 2 {
		t.Fatalf("expected 2 out-of-order packets (5 after 7, and 6 after 8), got %d", got)
	}
	if got := d.seqMax.Load(); got != 8 {
		t.Fatalf("expected the high-water sequence number to be 8, got %d", got)
	}
}

// A replayed packet must be reported as a probe, not lost in the generic auth-fail count.
func TestReplayIsReportedAsProbe(t *testing.T) {
	a, b := tunPair(t, cipherChaCha, "quic", 0)
	on := true
	cfg := &DPILogConfig{Enabled: &on, Path: t.TempDir() + "/dpi.jsonl"}
	cfg.applyDefaults()
	b.dpi = newDPILogger(cfg)

	o := newOpener()
	pkt := a.seal([]byte("real traffic"))
	if _, _, ok := b.openSeq(o, pkt); !ok {
		t.Fatal("the original packet must authenticate")
	}
	// Now send the very same bytes again, as a third party replaying a capture would.
	_, seq, ok := b.openSeq(o, pkt)
	if ok {
		t.Fatal("a replayed packet must be rejected")
	}
	if seq == 0 {
		t.Fatal("openSeq must report the sequence number of a packet that decrypted but replayed, so the caller can tell a replay from a forgery")
	}
	b.dpi.observeStranger(evProbeReplay, netip.MustParseAddrPort("203.0.113.9:40000"), pkt, 55, "")
	if n := b.dpi.cReplayed.Load(); n != 1 {
		t.Fatalf("expected the replay to be counted as a probe, got %d", n)
	}
}

func TestStrangerAggregationCollapsesAScan(t *testing.T) {
	d := testLogger(t)
	src := netip.MustParseAddrPort("198.51.100.7:12345")
	junk := bytes.Repeat([]byte{0xab}, 64)
	for i := 0; i < 5000; i++ {
		d.observeStranger(evScanUnauth, src, junk, 60, "")
	}
	d.mu.Lock()
	n := len(d.sources)
	total := d.sources["198.51.100.7:12345"].classes[evScanUnauth]
	d.mu.Unlock()
	if n != 1 {
		t.Fatalf("5000 packets from one source must collapse to one entry, got %d", n)
	}
	if total != 5000 {
		t.Fatalf("expected all 5000 counted, got %d", total)
	}
}

func TestStrangerTableIsCapped(t *testing.T) {
	on := true
	cfg := &DPILogConfig{Enabled: &on, Path: t.TempDir() + "/dpi.jsonl", MaxSources: 10}
	cfg.applyDefaults()
	d := newDPILogger(cfg)
	junk := []byte{1, 2, 3, 4}
	for i := 0; i < 100; i++ {
		d.observeStranger(evScanUnauth, netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, byte(i)}), 1000), junk, 0, "")
	}
	d.mu.Lock()
	n, over := len(d.sources), d.overCap
	d.mu.Unlock()
	if n > 10 {
		t.Fatalf("source table exceeded its cap: %d entries", n)
	}
	if over == 0 {
		t.Fatal("sources dropped past the cap must be counted, otherwise a spoofed flood looks like silence")
	}
}

// A disabled observer must cost nothing and touch nothing.
func TestDisabledObserverIsInert(t *testing.T) {
	off := false
	cfg := &DPILogConfig{Enabled: &off}
	cfg.applyDefaults()
	d := newDPILogger(cfg)
	if d.enabled() {
		t.Fatal("observer should be disabled")
	}
	if n := testing.AllocsPerRun(200, func() {
		d.observePeerPacket(1, 64)
		d.observeStranger(evScanUnauth, netip.MustParseAddrPort("1.2.3.4:5"), []byte{1}, 64, "")
	}); n != 0 {
		t.Fatalf("a disabled observer allocated %.1f per call", n)
	}
}

// The hot path with the observer *enabled* must also stay allocation-free.
func TestEnabledObserverPeerPathDoesNotAllocate(t *testing.T) {
	d := testLogger(t)
	for i := 0; i < 8; i++ {
		d.observePeerPacket(uint64(i+1), 52)
	}
	var seq uint64 = 100
	if n := testing.AllocsPerRun(500, func() {
		seq++
		d.observePeerPacket(seq, 52)
	}); n != 0 {
		t.Fatalf("observePeerPacket allocated %.1f per call on the peer path", n)
	}
}

// ---------------------------------------------------------------------------
// reading a stranger's QUIC Initial
// ---------------------------------------------------------------------------

func TestPeekInitialSNI(t *testing.T) {
	dcid := make([]byte, 8)
	scid := make([]byte, 8)
	rand.Read(dcid)
	rand.Read(scid)
	const want = "www.example.org"
	pkt, err := buildInitial(dcid, dcid, scid, buildClientHello(want), true)
	if err != nil || pkt == nil {
		t.Fatalf("building the Initial failed: %v", err)
	}
	if got := quicPeekInitialSNI(pkt); got != want {
		t.Fatalf("expected to read back SNI %q, got %q", want, got)
	}
}

// It parses attacker-controlled bytes in the packet loop, so the only behaviour that really
// matters is that nothing it is given can make it panic.
func TestPeekInitialSNISurvivesGarbage(t *testing.T) {
	dcid := make([]byte, 8)
	rand.Read(dcid)
	good, _ := buildInitial(dcid, dcid, dcid, buildClientHello("a.example"), true)

	cases := [][]byte{nil, {}, {0xc0}, {0x80, 0, 0, 0, 1}, bytes.Repeat([]byte{0xff}, 100)}
	// Every truncation of a valid packet.
	for i := 0; i <= len(good); i += 7 {
		cases = append(cases, good[:i])
	}
	// Every single-byte corruption at a spread of offsets.
	for i := 0; i < len(good); i += 13 {
		c := append([]byte(nil), good...)
		c[i] ^= 0xff
		cases = append(cases, c)
	}
	// Random noise of assorted lengths.
	for _, n := range []int{1, 7, 64, 1200, 4095, 4096, 8192} {
		b := make([]byte, n)
		rand.Read(b)
		cases = append(cases, b)
	}
	for i, c := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("case %d panicked: %v", i, r)
				}
			}()
			quicPeekInitialSNI(c)
		}()
	}
}

func TestSanitiseName(t *testing.T) {
	if got := sanitiseName("ok.example.com"); got != "ok.example.com" {
		t.Fatalf("a clean name must pass through, got %q", got)
	}
	if got := sanitiseName("bad\nname\x00here"); got != "bad.name.here" {
		t.Fatalf("control characters must be replaced, got %q", got)
	}
	long := sanitiseName(string(bytes.Repeat([]byte{'x'}, 500)))
	if len(long) != 96 {
		t.Fatalf("an over-long name must be truncated, got %d bytes", len(long))
	}
}

// ---------------------------------------------------------------------------
// kernel counter parsing
// ---------------------------------------------------------------------------

func TestReadUDPCounters(t *testing.T) {
	c := readUDPCounters()
	if c == nil {
		t.Skip("/proc/net/snmp not available on this machine")
	}
	if _, ok := c["InDatagrams"]; !ok {
		t.Fatalf("expected an InDatagrams counter, got keys: %v", c)
	}
	if _, ok := c["InCsumErrors"]; !ok {
		t.Fatal("expected an InCsumErrors counter — it is the one that reveals forged packets")
	}
}

// ---------------------------------------------------------------------------
// benchmarks for the reworked path
// ---------------------------------------------------------------------------

func benchSealInto(b *testing.B, suite, obfs string) {
	a, _ := tunPair(b, suite, obfs, 3600)
	s := newSealer()
	p := make([]byte, 1300)
	rand.Read(p)
	b.SetBytes(int64(len(p)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.sealInto(s, p)
	}
}

func BenchmarkSealIntoAESGCM(b *testing.B) { benchSealInto(b, cipherAESGCM, "quic") }
func BenchmarkSealIntoChaCha(b *testing.B) { benchSealInto(b, cipherChaCha, "quic") }

func benchOpenInto(b *testing.B, suite string) {
	ta, tb := tunPair(b, suite, "quic", 3600)
	s := newSealer()
	o := newOpener()
	p := make([]byte, 1300)
	rand.Read(p)
	pkts := make([][]byte, 1024)
	for i := range pkts {
		pkts[i] = append([]byte(nil), ta.sealInto(s, p)...)
	}
	b.SetBytes(int64(len(p)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if i%1024 == 0 {
			tb.replay = newReplayWindow(4096)
		}
		if _, ok := tb.openInto(o, pkts[i%1024]); !ok {
			b.Fatal("open failed")
		}
	}
}

func BenchmarkOpenIntoAESGCM(b *testing.B) { benchOpenInto(b, cipherAESGCM) }
func BenchmarkOpenIntoChaCha(b *testing.B) { benchOpenInto(b, cipherChaCha) }

// Classification of unsolicited traffic must not treat random noise as a QUIC probe:
// half of all random first bytes have the long-header form bit set.
func TestKnownVersionFiltersRandomNoise(t *testing.T) {
	misread := 0
	pkt := make([]byte, 64)
	for i := 0; i < 20000; i++ {
		rand.Read(pkt)
		if v, ok := quicLongVersion(pkt); ok && quicKnownVersion(v) {
			misread++
		}
	}
	// ~half will have the form bit set; essentially none should survive the version test.
	if misread > 5 {
		t.Fatalf("%d/20000 random datagrams were classified as QUIC probes", misread)
	}
}

func TestKnownVersionAcceptsRealInitials(t *testing.T) {
	dcid := make([]byte, 8)
	rand.Read(dcid)
	pkt, err := buildInitial(dcid, dcid, dcid, buildClientHello("x.example"), true)
	if err != nil || pkt == nil {
		t.Fatalf("building the Initial failed: %v", err)
	}
	v, ok := quicLongVersion(pkt)
	if !ok || !quicKnownVersion(v) {
		t.Fatalf("a genuine v1 Initial must be recognised, got version=%#x ok=%v", v, ok)
	}
}

// A dual-stack listener reports IPv4 senders in the v4-mapped form, while a peer parsed
// from the config is plain IPv4. Unless both are normalised the two never compare equal.
func TestNormAddrCanonicalisesV4Mapped(t *testing.T) {
	mapped := netip.MustParseAddrPort("[::ffff:180.149.44.196]:443")
	plain := netip.MustParseAddrPort("180.149.44.196:443")
	if mapped == plain {
		t.Fatal("precondition: the two forms should differ before normalisation")
	}
	if normAddr(mapped) != plain {
		t.Fatalf("normAddr(%v) = %v, want %v", mapped, normAddr(mapped), plain)
	}
	if normAddr(plain) != plain {
		t.Fatal("an already-plain address must pass through unchanged")
	}
	if got := normAddr(netip.AddrPort{}); got.IsValid() {
		t.Fatal("the zero address must stay invalid")
	}
	// And a real IPv6 peer must not be mangled.
	v6 := netip.MustParseAddrPort("[2001:db8::1]:443")
	if normAddr(v6) != v6 {
		t.Fatal("a genuine IPv6 address must be left alone")
	}
}

// A tunnel that has never received anything is the case most worth reporting, and the
// original guard excluded exactly that case.
func TestSilenceRefFallsBackToStartup(t *testing.T) {
	start := time.Now().Add(-10 * time.Minute)
	if got := silenceRef(start, 0); !got.Equal(start) {
		t.Fatalf("with no packet ever received, silence must be measured from start-up; got %v", got)
	}
	last := time.Now().Add(-30 * time.Second)
	if got := silenceRef(start, last.Unix()); got.Unix() != last.Unix() {
		t.Fatalf("with a previous receive, silence must be measured from it; got %v", got)
	}
}

// The pacer must actually hold the long-run rate, and must not throttle a link that is
// under its limit. A shaper that is wrong in either direction is worse than none.
func TestPacerHoldsItsRate(t *testing.T) {
	const mbps = 100.0
	p := newPacer(mbps)
	// Drain the initial burst so the measurement reflects the steady state.
	p.tokens = 0
	const pkt = 1500
	const n = 2000 // 3 MB at 100 Mbit/s ~= 240 ms
	start := time.Now()
	for i := 0; i < n; i++ {
		p.wait(pkt)
	}
	elapsed := time.Since(start).Seconds()
	got := float64(n*pkt) * 8 / elapsed / 1e6
	if got > mbps*1.25 || got < mbps*0.75 {
		t.Fatalf("paced rate %.1f Mbit/s is not close to the configured %.0f", got, mbps)
	}
}

func TestPacerDoesNotDelayUnderTheLimit(t *testing.T) {
	p := newPacer(1000)
	start := time.Now()
	for i := 0; i < 50; i++ {
		p.wait(1500) // 75 kB, far inside a 12.5 MB/s burst
	}
	if d := time.Since(start); d > 20*time.Millisecond {
		t.Fatalf("pacer delayed traffic that was well under its limit by %v", d)
	}
}

func TestPacerDisabledIsANoOp(t *testing.T) {
	var p *pacer = newPacer(0)
	if p != nil {
		t.Fatal("a zero rate must mean no pacer at all")
	}
	start := time.Now()
	for i := 0; i < 10000; i++ {
		p.wait(65535) // nil receiver must be safe and free
	}
	if d := time.Since(start); d > 20*time.Millisecond {
		t.Fatalf("a disabled pacer cost %v", d)
	}
}

// A peer restart makes its sequence numbers jump forward by ~10^9, because they start from
// the wall clock in microseconds. Treated as a gap, that one event reported 99.5% loss on a
// link that was dropping nothing, and made the next path check raise a loss burst that never
// happened.
func TestPeerRestartRebasesLossAccounting(t *testing.T) {
	d := testLogger(t)
	base := uint64(1785000000000000)
	for i := uint64(0); i < 100; i++ {
		d.observePeerPacket(base+i, 0)
	}
	if got := lossPct(d); got != 0 {
		t.Fatalf("a clean run must show no loss, got %.2f%%", got)
	}
	epochBefore := d.seqEpoch.Load()

	// The peer restarts: numbering resumes from a much later microsecond clock.
	restart := base + 900_000_000
	for i := uint64(0); i < 50; i++ {
		d.observePeerPacket(restart+i, 0)
	}
	if d.seqEpoch.Load() == epochBefore {
		t.Fatal("the restart must be recognised and bump the sequence epoch")
	}
	if got := lossPct(d); got != 0 {
		t.Fatalf("after a peer restart the loss figure must restart too, got %.2f%%", got)
	}
	if got := d.seqCount.Load(); got != 50 {
		t.Fatalf("packet accounting should have restarted at the rebase, got %d", got)
	}
}

// An ordinary gap must still be counted as loss — the rebase must not swallow real drops.
func TestOrdinaryGapIsStillCountedAsLoss(t *testing.T) {
	d := testLogger(t)
	base := uint64(1785000000000000)
	for i := uint64(0); i < 100; i++ {
		if i >= 40 && i < 50 {
			continue // ten packets genuinely lost
		}
		d.observePeerPacket(base+i, 0)
	}
	got := lossPct(d)
	if got < 9 || got > 11 {
		t.Fatalf("expected about 10%% loss to be reported, got %.2f%%", got)
	}
}

func lossPct(d *dpiLogger) float64 {
	s := map[string]any{}
	d.addStats(s)
	if v, ok := s["loss_pct"].(float64); ok {
		return v
	}
	return 0
}
