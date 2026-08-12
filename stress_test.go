package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// config values that used to take the process down
// ---------------------------------------------------------------------------

// Every numeric field in dpi_log ends up as either a ticker interval or a slice bound. A
// negative one used to panic — flush_sec and probe_sec inside time.NewTicker, sample_bytes
// as pkt[:n] on the receive path, which an unauthenticated datagram reaches.
func TestNegativeDPIConfigIsClamped(t *testing.T) {
	var c Config
	raw := `{"dpi_log":{"flush_sec":-1,"probe_sec":-5,"sample_bytes":-16,
	          "max_sources":-1,"silence_sec":-1,"max_per_min":-1,"max_size_mb":-1,"keep":-1}}`
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		t.Fatal(err)
	}
	c.applyDefaults()
	d := &c.DPILog
	for name, v := range map[string]int{
		"flush_sec": d.FlushSec, "probe_sec": d.ProbeSec, "sample_bytes": d.SampleBytes,
		"max_sources": d.MaxSources, "silence_sec": d.SilenceSec, "max_per_min": d.MaxPerMin,
		"max_size_mb": d.MaxSizeMB, "keep": d.Keep,
	} {
		if v <= 0 {
			t.Fatalf("%s stayed non-positive after defaults: %d", name, v)
		}
	}

	// The two that become ticker intervals must be safe to hand to time.NewTicker.
	for _, iv := range []int{d.FlushSec, d.ProbeSec} {
		tk := time.NewTicker(time.Duration(iv) * time.Second)
		tk.Stop()
	}

	// And the receive path must survive the pathological config on a real packet.
	lg := newDPILogger(d)
	lg.observeStranger(evScanUnauth, netip.MustParseAddrPort("192.0.2.1:9"), []byte{1, 2, 3}, 40, "")
}

func TestNegativeMTUIsClamped(t *testing.T) {
	for _, tc := range []struct{ in, want int }{
		{0, 1300}, {-1500, 1300}, {100, 576}, {1300, 1300}, {1 << 20, maxPktSize - 256},
	} {
		c := Config{MTU: tc.in}
		c.applyDefaults()
		if c.MTU != tc.want {
			t.Fatalf("mtu %d -> %d, want %d", tc.in, c.MTU, tc.want)
		}
	}
}

// health_sec is documented as "negative = off" and pathWatch keys on > 0, so a negative
// value has to survive as a disable rather than being turned back into the default.
func TestHealthSecCanBeDisabled(t *testing.T) {
	c := Config{}
	c.DPILog.HealthSec = -1
	c.applyDefaults()
	if c.DPILog.HealthSec > 0 {
		t.Fatalf("a negative health_sec must disable the heartbeat, got %d", c.DPILog.HealthSec)
	}
	c2 := Config{}
	c2.applyDefaults()
	if c2.DPILog.HealthSec != 300 {
		t.Fatalf("an omitted health_sec must default to 300, got %d", c2.DPILog.HealthSec)
	}
}

// ---------------------------------------------------------------------------
// rate_mbps must reach every carrier that can shape
// ---------------------------------------------------------------------------

// rate_mbps used to be wired into the plain UDP carrier only, so setting it on a TCP or
// port-hopping tunnel parsed cleanly and then did nothing — a rate limit that silently is
// not one is worse than no option at all.
func TestCarrierPacerIsWiredForEveryShapedCarrier(t *testing.T) {
	p := newPacer(50)
	if got := carrierPacer(&udpCarrier{pacer: p}); got != p {
		t.Fatal("the udp carrier's pacer must be visible to the pump")
	}
	if got := carrierPacer(&tcpCarrier{pacer: p}); got != p {
		t.Fatal("the tcp carrier's pacer must be visible to the pump")
	}
	if got := carrierPacer(&hopCarrier{pacer: p}); got != p {
		t.Fatal("the hopping carrier's pacer must be visible to the pump")
	}
	// No pacer configured must stay nil, and pacer.wait must tolerate that.
	if got := carrierPacer(&udpCarrier{}); got != nil {
		t.Fatal("an unshaped carrier must report no pacer")
	}
	carrierPacer(&udpCarrier{}).wait(1400)
}

// ---------------------------------------------------------------------------
// concurrency: the packet path under several goroutines at once
// ---------------------------------------------------------------------------

// The ICMP carrier runs one receive goroutine per core against a single Tunnel, and the
// keepalive, probe and junk loops all seal concurrently with the TUN pump. Each goroutine
// owns its own sealer/opener; everything else on the Tunnel has to be safe to share.
func TestConcurrentSealOpenAcrossGoroutines(t *testing.T) {
	for _, obfs := range []string{obfsNone, obfsQUIC, obfsDTLS} {
		t.Run(obfs, func(t *testing.T) {
			a, b := tunPair(t, cipherChaCha, obfs, 3600)

			const senders, receivers, perSender = 4, 4, 500
			pkts := make(chan []byte, 1024)
			var sealed, opened, failed atomic.Uint64

			var sw sync.WaitGroup
			for s := 0; s < senders; s++ {
				sw.Add(1)
				go func(id int) {
					defer sw.Done()
					sl := newSealer()
					payload := bytes.Repeat([]byte{byte(id)}, 900+id)
					for i := 0; i < perSender; i++ {
						out := sl.copyOf(a.sealInto(sl, payload))
						sealed.Add(1)
						pkts <- out
					}
				}(s)
			}
			go func() { sw.Wait(); close(pkts) }()

			var rw sync.WaitGroup
			for r := 0; r < receivers; r++ {
				rw.Add(1)
				go func() {
					defer rw.Done()
					op := newOpener()
					for pkt := range pkts {
						if _, ok := b.openInto(op, pkt); ok {
							opened.Add(1)
						} else {
							failed.Add(1)
						}
					}
				}()
			}
			rw.Wait()

			if want := uint64(senders * perSender); sealed.Load() != want {
				t.Fatalf("sealed %d packets, want %d", sealed.Load(), want)
			}
			// Every packet carries a distinct inner sequence number and a distinct nonce, so
			// all of them must authenticate: any failure here is a shared-state bug, not loss.
			if failed.Load() != 0 {
				t.Fatalf("%d of %d packets failed to open under concurrency", failed.Load(), sealed.Load())
			}
			if opened.Load() != sealed.Load() {
				t.Fatalf("opened %d of %d", opened.Load(), sealed.Load())
			}
		})
	}
}

// Nonce uniqueness is what AEAD security rests on, and under obfs the nonce is the header:
// connection ID plus packet number. Several goroutines sealing at once must never produce
// the same one twice.
func TestNoncesAreUniqueUnderConcurrency(t *testing.T) {
	a, _ := tunPair(t, cipherAESGCM, obfsQUIC, 0)
	const goroutines, each = 8, 2000

	var mu sync.Mutex
	seen := make(map[string]struct{}, goroutines*each)
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sl := newSealer()
			local := make([][12]byte, 0, each)
			p := bytes.Repeat([]byte{7}, 100)
			for i := 0; i < each; i++ {
				a.sealInto(sl, p)
				local = append(local, sl.nonce)
			}
			mu.Lock()
			defer mu.Unlock()
			for _, n := range local {
				k := string(n[:])
				if _, dup := seen[k]; dup {
					t.Errorf("nonce %x was issued twice", n)
					return
				}
				seen[k] = struct{}{}
			}
		}()
	}
	wg.Wait()
	if len(seen) != goroutines*each {
		t.Fatalf("collected %d distinct nonces, want %d", len(seen), goroutines*each)
	}
}

// The replay window is shared by every receive goroutine. Feeding the same packets from
// several of them at once must accept each exactly once in total.
func TestReplayWindowAcceptsEachSequenceExactlyOnce(t *testing.T) {
	w := newReplayWindow(4096)
	const n = 3000
	var accepted atomic.Uint64
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for s := uint64(1); s <= n; s++ {
				if w.check(s) {
					accepted.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != n {
		t.Fatalf("accepted %d of %d sequence numbers exactly once", accepted.Load(), n)
	}
}

// ---------------------------------------------------------------------------
// sustained-load behaviour
// ---------------------------------------------------------------------------

// A long run must not grow the heap: the packet path is allocation-free by design, and the
// epoch cache is the one structure that could leak over a long uptime.
func TestEpochCacheDoesNotGrowUnbounded(t *testing.T) {
	a, _ := tunPair(t, cipherChaCha, obfsQUIC, 1)
	s := newSealer()
	p := bytes.Repeat([]byte{5}, 1200)
	// Rekey every second, so this walks a fresh epoch every time round.
	for i := 0; i < 200; i++ {
		a.sealInto(s, p)
		a.aead(true, uint64(i))
		a.aead(false, uint64(i))
	}
	a.cacheMu.Lock()
	n := len(a.cache)
	a.cacheMu.Unlock()
	if n > 65 {
		t.Fatalf("the epoch cache grew to %d entries; it must be bounded", n)
	}
}

// A full-rate soak over the real seal/open pair, checking that nothing drifts: every packet
// must still authenticate after hundreds of thousands of them, across a rekey boundary.
func TestSoakRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("soak test skipped under -short")
	}
	a, b := tunPair(t, cipherChaCha, obfsQUIC, 1) // rekey every second, so epochs roll mid-run
	s, o := newSealer(), newOpener()
	payload := make([]byte, 1300)
	rand.Read(payload)

	const n = 200_000
	for i := 0; i < n; i++ {
		got, ok := b.openInto(o, a.sealInto(s, payload))
		if !ok {
			t.Fatalf("packet %d failed to authenticate", i)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("packet %d came back altered", i)
		}
	}
	if got := b.rxPackets; got != n {
		t.Fatalf("receiver counted %d packets, want %d", got, n)
	}
	if b.authFail != 0 || b.replayDrop != 0 {
		t.Fatalf("soak produced auth_fail=%d replay_drop=%d, both must be 0", b.authFail, b.replayDrop)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// copyOf returns an independent copy of a slice that aliases the sealer's scratch.
func (s *sealer) copyOf(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
