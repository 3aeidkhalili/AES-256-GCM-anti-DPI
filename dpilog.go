// DPI and probe observability.
//
// The tunnel already tells you how much traffic crossed it. What it never told you is what
// *else* arrived at the carrier port, or what the path did to the packets in flight — and
// those are the two things that matter when an ISP's DPI starts taking an interest in a
// link. This file adds both, and it is written so that watching costs almost nothing when
// nothing is happening.
//
// Two distinct questions, answered separately:
//
//  1. "Who is talking to this port that is not the peer?"  Every datagram that arrives and
//     is not authenticated peer traffic gets classified and aggregated per source address.
//     A port scan collapses into one record. The interesting cases are the ones that are
//     not scans:
//
//     - a QUIC Initial from a stranger — the obfuscation layer answers Initials, so an
//     active prober checking whether this port "really" speaks QUIC shows up here;
//     - a datagram that decrypts but replays a sequence number we have already seen —
//     that is someone who captured our traffic and sent it back, which is the classic
//     way a censor confirms what a suspicious flow is;
//     - a datagram carrying the peer's source address that fails authentication — an
//     on-path injector forging packets into the flow;
//     - a packet from the peer whose IP TTL does not match the peer's established one —
//     an injector is nearly always fewer hops away than the real peer, so the TTL it
//     has to guess is the thing it most often gets wrong.
//
//  2. "Is the path mistreating our packets?"  The inner sequence numbers are already there
//     for anti-replay, and they measure loss and reordering for free. On top of that the
//     module watches for the flow going silent while we are still sending (a block), for
//     throughput collapsing against its own recent baseline (a throttle), for RTT spikes,
//     and for the kernel's own UDP error counters — bad checksums in particular, because
//     forged and desynced packets die in the kernel and are otherwise invisible.
//
// Cost. Authenticated peer packets — which is to say all of them, almost all of the time —
// touch nothing here but a handful of atomic increments. Everything expensive happens on
// the stranger path, which is rare by construction, or on a timer in a separate goroutine.
// Events are handed to a writer goroutine through a buffered channel with a non-blocking
// send, so a flood of probes can never slow or block the packet loops; it just increments a
// dropped counter.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------------------
// configuration
// ---------------------------------------------------------------------------

type DPILogConfig struct {
	Enabled     *bool  `json:"enabled"`      // default true
	Path        string `json:"path"`         // JSONL output; default /var/log/aestun/dpi.jsonl
	MaxSizeMB   int    `json:"max_size_mb"`  // rotate past this size; default 16
	Keep        int    `json:"keep"`         // rotated generations to keep; default 2
	MaxPerMin   int    `json:"max_per_min"`  // event rate limit; default 240
	FlushSec    int    `json:"flush_sec"`    // how often per-source aggregates are emitted; default 60
	HealthSec   int    `json:"health_sec"`   // flow-health heartbeat interval; default 300 (0 = off)
	Probe       *bool  `json:"probe"`        // send in-tunnel RTT probes; default true
	ProbeSec    int    `json:"probe_sec"`    // probe interval; default 20
	SilenceSec  int    `json:"silence_sec"`  // silence before a blackhole is declared; default 60
	MaxSources  int    `json:"max_sources"`  // per-source table cap; default 2048
	SampleBytes int    `json:"sample_bytes"` // header bytes recorded from a stranger; default 16
	Stdout      *bool  `json:"stdout"`       // also write events to the journal; default true
}

func (c *DPILogConfig) applyDefaults() {
	if c.Enabled == nil {
		v := true
		c.Enabled = &v
	}
	if c.Path == "" {
		c.Path = "/var/log/aestun/dpi.jsonl"
	}
	if c.MaxSizeMB == 0 {
		c.MaxSizeMB = 16
	}
	if c.Keep == 0 {
		c.Keep = 2
	}
	if c.MaxPerMin == 0 {
		c.MaxPerMin = 240
	}
	if c.FlushSec == 0 {
		c.FlushSec = 60
	}
	if c.HealthSec == 0 {
		c.HealthSec = 300
	}
	if c.Probe == nil {
		v := true
		c.Probe = &v
	}
	if c.ProbeSec == 0 {
		c.ProbeSec = 20
	}
	if c.SilenceSec == 0 {
		c.SilenceSec = 60
	}
	if c.MaxSources == 0 {
		c.MaxSources = 2048
	}
	if c.SampleBytes == 0 {
		c.SampleBytes = 16
	}
	if c.Stdout == nil {
		v := true
		c.Stdout = &v
	}
}

// ---------------------------------------------------------------------------
// event classes
// ---------------------------------------------------------------------------

const (
	// unsolicited ingress
	evProbeQUIC   = "probe.quic_initial"  // a stranger sent a QUIC long-header packet
	evProbeReplay = "probe.replay"        // a stranger replayed one of our own packets
	evScanUnauth  = "scan.unauth"         // unauthenticated datagram from a stranger
	evInjectSpoof = "inject.spoofed_peer" // unauthenticated datagram claiming the peer's address
	evTTLAnomaly  = "anomaly.ttl"         // peer-addressed packet with the wrong hop count
	evPeerRoam    = "peer.roam"           // authenticated peer moved to a new address

	// path behaviour
	evLossBurst  = "path.loss_burst"
	evBlackhole  = "path.blackhole"
	evRecovered  = "path.recovered"
	evThrottle   = "path.throttle"
	evRTTSpike   = "path.rtt_spike"
	evKernelDrop = "kernel.udp_errors"

	// periodic
	evHealth = "flow.health"
)

// seqRebaseGap is the forward jump in the peer's sequence numbers beyond which the only
// sane explanation is that the peer restarted rather than that we lost that many packets.
// A million packets is minutes of total blackout at this tunnel's rates, and rebasing is
// the right response to that too.
const seqRebaseGap = 1 << 20

const (
	sevInfo   = "info"
	sevNotice = "notice"
	sevWarn   = "warn"
	sevHigh   = "high"
)

type dpiEvent struct {
	TS       string         `json:"ts"`
	Event    string         `json:"event"`
	Severity string         `json:"severity"`
	Src      string         `json:"src,omitempty"`
	Count    uint64         `json:"count,omitempty"`
	Bytes    uint64         `json:"bytes,omitempty"`
	Detail   map[string]any `json:"detail,omitempty"`
	Message  string         `json:"msg,omitempty"`
}

// ---------------------------------------------------------------------------
// per-source aggregation
// ---------------------------------------------------------------------------

type srcAgg struct {
	first, last time.Time
	classes     map[string]uint64
	bytes       uint64
	minSize     int
	maxSize     int
	ttlSeen     map[uint8]uint64
	sample      string // hex of the first bytes of the first datagram
	sni         string // if a ClientHello was parseable out of a probe
	pending     bool   // has unreported activity
}

// ---------------------------------------------------------------------------
// the logger
// ---------------------------------------------------------------------------

type dpiLogger struct {
	cfg     DPILogConfig
	on      bool
	events  chan dpiEvent
	dropped atomic.Uint64

	mu      sync.Mutex
	sources map[string]*srcAgg
	overCap uint64

	// counters surfaced in stats.json
	cProbes    atomic.Uint64
	cScans     atomic.Uint64
	cInject    atomic.Uint64
	cReplayed  atomic.Uint64
	cTTLAnom   atomic.Uint64
	cEvents    atomic.Uint64
	cBlackhole atomic.Uint64

	// authenticated-flow health, updated from the receive path with atomics only
	seqMax     atomic.Uint64
	seqCount   atomic.Uint64
	seqReorder atomic.Uint64
	seqFirst   atomic.Uint64
	// Bumped whenever the peer's sequence numbering restarts; see observePeerPacket.
	seqEpoch atomic.Uint64

	// peer TTL learning: the modal hop count seen from the peer
	peerTTL     atomic.Uint32 // 0 = not yet learned
	peerTTLSeen atomic.Uint64

	// RTT, in microseconds
	rttLast atomic.Uint64
	rttMin  atomic.Uint64
	rttEWMA atomic.Uint64
	rttN    atomic.Uint64

	blackholed atomic.Bool

	// Inode of the ICMP carrier's raw socket, published by the carrier once it is open so
	// icmpWatch can find that socket's line in /proc/net/raw. Atomic because the observer's
	// goroutines are already running by the time the carrier exists. 0 = not applicable.
	rawInode atomic.Uint64
}

func newDPILogger(cfg *DPILogConfig) *dpiLogger {
	c := *cfg
	c.applyDefaults()
	d := &dpiLogger{
		cfg:     c,
		on:      c.Enabled != nil && *c.Enabled,
		events:  make(chan dpiEvent, 1024),
		sources: make(map[string]*srcAgg),
	}
	return d
}

// enabled is the guard every hot-path hook starts with.
func (d *dpiLogger) enabled() bool { return d != nil && d.on }

// emit hands an event to the writer without ever blocking the caller. A packet loop must
// not be able to stall because a disk is slow or a prober is loud.
func (d *dpiLogger) emit(e dpiEvent) {
	if !d.enabled() {
		return
	}
	if e.TS == "" {
		e.TS = time.Now().UTC().Format(time.RFC3339)
	}
	select {
	case d.events <- e:
		d.cEvents.Add(1)
	default:
		d.dropped.Add(1)
	}
}

// ---------------------------------------------------------------------------
// hot-path hooks
// ---------------------------------------------------------------------------

// observePeerPacket is called for every datagram that authenticated as peer traffic. It is
// on the hottest path in the program, so it does nothing but a few atomics.
func (d *dpiLogger) observePeerPacket(seq uint64, ttl uint8) {
	if !d.enabled() {
		return
	}
	d.seqCount.Add(1)
	for {
		cur := d.seqMax.Load()
		if seq <= cur {
			d.seqReorder.Add(1)
			break
		}
		// A peer that restarts begins numbering from the current time in microseconds, so
		// its first packet after a restart is ~10^9 ahead of its last one before. Counted
		// as a gap that is "loss", which is what the arithmetic below would otherwise do,
		// one restart poisons every loss figure for the life of the process — it reported
		// 99.5% loss on a link that was not dropping anything at all — and makes the next
		// pathWatch tick raise a loss burst that never happened. Treat an implausible jump
		// as what it is and start the accounting again.
		if cur != 0 && seq > cur+seqRebaseGap {
			d.seqMax.Store(seq)
			d.seqFirst.Store(seq)
			d.seqCount.Store(1)
			d.seqEpoch.Add(1)
			break
		}
		if d.seqMax.CompareAndSwap(cur, seq) {
			if cur == 0 {
				d.seqFirst.Store(seq)
			}
			break
		}
	}
	if ttl != 0 {
		d.checkPeerTTL(ttl)
	}
}

// checkPeerTTL learns the peer's hop count from the first packets and then flags anything
// that disagrees. An on-path injector has to guess this value, and a guess that is wrong by
// even one hop is a reliable tell that the packet did not come from the peer.
func (d *dpiLogger) checkPeerTTL(ttl uint8) {
	known := d.peerTTL.Load()
	if known == 0 {
		// Learn from the first few packets; require a couple of agreeing samples so a
		// single injected packet cannot become the baseline.
		if d.peerTTLSeen.Add(1) >= 4 {
			d.peerTTL.CompareAndSwap(0, uint32(ttl))
		}
		return
	}
	if uint32(ttl) == known {
		return
	}
	d.cTTLAnom.Add(1)
	d.emit(dpiEvent{
		Event:    evTTLAnomaly,
		Severity: sevHigh,
		Detail: map[string]any{
			"expected_ttl": known,
			"observed_ttl": ttl,
		},
		Message: "packet from the peer address arrived with an unexpected hop count — consistent with an on-path injector",
	})
	// Do not relearn: if the path genuinely changed, the restart or a roam event will
	// re-establish it, and relearning here would let an injector move the baseline.
}

// observeStranger is called for any datagram that is not authenticated peer traffic.
// It aggregates by source; the writer emits at most one record per source per flush window.
func (d *dpiLogger) observeStranger(class string, src netip.AddrPort, pkt []byte, ttl uint8, sni string) {
	if !d.enabled() {
		return
	}
	switch class {
	case evProbeQUIC:
		d.cProbes.Add(1)
	case evProbeReplay:
		d.cReplayed.Add(1)
	case evInjectSpoof:
		d.cInject.Add(1)
	default:
		d.cScans.Add(1)
	}

	key := src.String()
	now := time.Now()

	d.mu.Lock()
	a := d.sources[key]
	if a == nil {
		if len(d.sources) >= d.cfg.MaxSources {
			d.overCap++
			d.mu.Unlock()
			return
		}
		n := d.cfg.SampleBytes
		if n > len(pkt) {
			n = len(pkt)
		}
		a = &srcAgg{
			first:   now,
			classes: make(map[string]uint64, 2),
			ttlSeen: make(map[uint8]uint64, 2),
			minSize: len(pkt),
			maxSize: len(pkt),
			sample:  hex.EncodeToString(pkt[:n]),
		}
		d.sources[key] = a
	}
	a.last = now
	a.classes[class]++
	a.bytes += uint64(len(pkt))
	a.pending = true
	if len(pkt) < a.minSize {
		a.minSize = len(pkt)
	}
	if len(pkt) > a.maxSize {
		a.maxSize = len(pkt)
	}
	if ttl != 0 {
		a.ttlSeen[ttl]++
	}
	if sni != "" && a.sni == "" {
		a.sni = sni
	}
	d.mu.Unlock()
}

func (d *dpiLogger) peerRoamed(from, to string) {
	if !d.enabled() {
		return
	}
	d.emit(dpiEvent{
		Event:    evPeerRoam,
		Severity: sevNotice,
		Src:      to,
		Detail:   map[string]any{"from": from},
		Message:  "authenticated peer address changed",
	})
	// The hop count belongs to the old path; forget it so the new one is learned cleanly.
	d.peerTTL.Store(0)
	d.peerTTLSeen.Store(0)
}

// noteRTT records a round-trip sample from the in-tunnel probe exchange.
func (d *dpiLogger) noteRTT(us uint64) {
	if !d.enabled() || us == 0 {
		return
	}
	d.rttLast.Store(us)
	n := d.rttN.Add(1)
	if m := d.rttMin.Load(); m == 0 || us < m {
		d.rttMin.Store(us)
	}
	prev := d.rttEWMA.Load()
	if prev == 0 {
		d.rttEWMA.Store(us)
		return
	}
	// 1/8 weight, the usual smoothing for a path estimate.
	next := (prev*7 + us) / 8
	d.rttEWMA.Store(next)
	// Flag a spike only once there is enough history for "normal" to mean something, and
	// only when it is large enough not to be ordinary jitter.
	if n > 8 && us > prev*3 && us > prev+50_000 {
		d.emit(dpiEvent{
			Event:    evRTTSpike,
			Severity: sevWarn,
			Detail: map[string]any{
				"rtt_ms":      float64(us) / 1000,
				"baseline_ms": float64(prev) / 1000,
			},
			Message: "round-trip time spiked well above its own baseline — congestion, or a middlebox delaying the flow",
		})
	}
}

// ---------------------------------------------------------------------------
// background goroutines
// ---------------------------------------------------------------------------

// run starts the writer and the periodic analysers. t may be nil in tests.
func (d *dpiLogger) run(t *Tunnel) {
	if !d.enabled() {
		return
	}
	go d.writer()
	go d.flushLoop()
	go d.pathWatch(t)
	// Which kernel counters are worth reading depends on what the carrier is. Watching
	// the UDP block while the tunnel runs on ICMP reports on whatever else the host
	// happens to be doing and says nothing at all about this flow.
	if t != nil && t.transport == "icmp" {
		go d.icmpWatch()
	} else {
		go d.kernelWatch()
	}
}

func (d *dpiLogger) flushLoop() {
	tick := time.NewTicker(time.Duration(d.cfg.FlushSec) * time.Second)
	defer tick.Stop()
	for range tick.C {
		d.flushSources()
	}
}

// flushSources emits one aggregated record per source that has been active since the last
// flush, then forgets sources that have gone quiet.
func (d *dpiLogger) flushSources() {
	type rec struct {
		key string
		a   srcAgg
	}
	var out []rec
	cutoff := time.Now().Add(-10 * time.Minute)

	d.mu.Lock()
	over := d.overCap
	d.overCap = 0
	for k, a := range d.sources {
		if a.pending {
			cp := *a
			cp.classes = make(map[string]uint64, len(a.classes))
			for c, n := range a.classes {
				cp.classes[c] = n
			}
			cp.ttlSeen = make(map[uint8]uint64, len(a.ttlSeen))
			for tv, n := range a.ttlSeen {
				cp.ttlSeen[tv] = n
			}
			out = append(out, rec{k, cp})
			a.pending = false
			a.classes = make(map[string]uint64, 2)
			a.ttlSeen = make(map[uint8]uint64, 2)
		} else if a.last.Before(cutoff) {
			delete(d.sources, k)
		}
	}
	d.mu.Unlock()

	if over > 0 {
		d.emit(dpiEvent{
			Event:    evScanUnauth,
			Severity: sevWarn,
			Count:    over,
			Message:  "per-source table full; additional distinct sources were counted but not detailed (likely a spoofed-source flood)",
		})
	}

	for _, r := range out {
		// The dominant class decides how the record is labelled and how loud it is.
		class, n := "", uint64(0)
		var total uint64
		for c, cn := range r.a.classes {
			total += cn
			if cn > n {
				class, n = c, cn
			}
		}
		det := map[string]any{
			"classes":    r.a.classes,
			"first_seen": r.a.first.UTC().Format(time.RFC3339),
			"last_seen":  r.a.last.UTC().Format(time.RFC3339),
			"size_min":   r.a.minSize,
			"size_max":   r.a.maxSize,
			"head_hex":   r.a.sample,
		}
		if len(r.a.ttlSeen) > 0 {
			det["ttl"] = r.a.ttlSeen
		}
		if r.a.sni != "" {
			det["sni"] = r.a.sni
		}
		d.emit(dpiEvent{
			Event:    class,
			Severity: severityFor(class, total),
			Src:      r.key,
			Count:    total,
			Bytes:    r.a.bytes,
			Detail:   det,
			Message:  messageFor(class),
		})
	}
}

func severityFor(class string, n uint64) string {
	switch class {
	case evProbeReplay:
		return sevHigh
	case evInjectSpoof:
		return sevHigh
	case evProbeQUIC:
		if n > 3 {
			return sevHigh
		}
		return sevWarn
	case evTTLAnomaly:
		return sevHigh
	default:
		if n > 1000 {
			return sevNotice
		}
		return sevInfo
	}
}

func messageFor(class string) string {
	switch class {
	case evProbeReplay:
		return "a third party replayed captured tunnel packets back at us — active probing, and it means the flow is under specific suspicion"
	case evInjectSpoof:
		return "unauthenticated datagrams arrived carrying the peer's source address — on-path injection, or the peer's own desync fakes"
	case evProbeQUIC:
		return "a stranger sent QUIC handshake packets to the carrier port — someone is checking whether this port really speaks QUIC"
	case evScanUnauth:
		return "unauthenticated datagrams from a source that is not the peer — background scanning, unless the rate or timing says otherwise"
	default:
		return ""
	}
}

// pathWatch turns the authenticated flow's own counters into blackhole, loss and throttle
// findings. Everything here runs on a timer, never on the packet path.
func (d *dpiLogger) pathWatch(t *Tunnel) {
	if t == nil {
		return
	}
	const tick = 10 * time.Second
	var (
		lastRxBytes, lastTxBytes uint64
		lastCount, lastMax       uint64
		rateHistory              []float64
		lastHealth               = time.Now()
		lastEpoch                = d.seqEpoch.Load()
	)
	for {
		time.Sleep(tick)

		rxB := atomic.LoadUint64(&t.rxBytes)
		txB := atomic.LoadUint64(&t.txBytes)
		cnt := d.seqCount.Load()
		mx := d.seqMax.Load()
		lastRx := atomic.LoadInt64(&t.lastRxUnix)

		// --- blackhole: we are transmitting, nothing is coming back ---
		// The reference point is the last authenticated packet, or — when there has never
		// been one — the moment this process started. Requiring a previous receive would
		// mean the one case you most want reported, a link that never comes up at all,
		// is the one case that stays silent.
		since := silenceRef(t.startAt, lastRx)
		silent := time.Since(since) > time.Duration(d.cfg.SilenceSec)*time.Second
		sending := txB > lastTxBytes
		if silent && sending {
			if d.blackholed.CompareAndSwap(false, true) {
				d.cBlackhole.Add(1)
				det := map[string]any{
					"silent_seconds": int(time.Since(since).Seconds()),
					"tx_bytes_since": txB - lastTxBytes,
				}
				msg := "still sending, nothing received for the whole silence window — the carrier flow looks blocked"
				if lastRx == 0 {
					det["ever_received"] = false
					msg = "sending since start-up and nothing has ever come back — the carrier flow is blocked, or the peer address, port, key or cipher does not match"
				}
				d.emit(dpiEvent{Event: evBlackhole, Severity: sevHigh, Detail: det, Message: msg})
			}
		} else if !silent && d.blackholed.CompareAndSwap(true, false) {
			d.emit(dpiEvent{
				Event:    evRecovered,
				Severity: sevNotice,
				Message:  "traffic from the peer resumed",
			})
		}

		// A rebase means the two ends of this interval are not comparable; skip it rather
		// than report the discontinuity as loss.
		epoch := d.seqEpoch.Load()
		rebased := epoch != lastEpoch
		lastEpoch = epoch

		// --- loss on the authenticated stream ---
		// Inner sequence numbers are contiguous per direction, so expected-minus-received
		// over an interval is the loss the path inflicted, with no extra packets sent.
		if !rebased && lastCount > 0 && mx > lastMax {
			expected := mx - lastMax
			got := cnt - lastCount
			if expected > 200 && got < expected {
				lossPct := float64(expected-got) * 100 / float64(expected)
				if lossPct >= 5 {
					sev := sevWarn
					if lossPct >= 20 {
						sev = sevHigh
					}
					d.emit(dpiEvent{
						Event:    evLossBurst,
						Severity: sev,
						Detail: map[string]any{
							"loss_pct": round2(lossPct),
							"expected": expected,
							"received": got,
							"window_s": int(tick.Seconds()),
						},
						Message: "sustained packet loss on the authenticated stream",
					})
				}
			}
		}

		// --- throughput collapse against the flow's own recent baseline ---
		rate := float64(rxB-lastRxBytes) / tick.Seconds()
		rateHistory = append(rateHistory, rate)
		if len(rateHistory) > 30 {
			rateHistory = rateHistory[1:]
		}
		if len(rateHistory) >= 12 {
			peak := 0.0
			for _, r := range rateHistory[:len(rateHistory)-3] {
				if r > peak {
					peak = r
				}
			}
			recent := (rateHistory[len(rateHistory)-1] + rateHistory[len(rateHistory)-2] + rateHistory[len(rateHistory)-3]) / 3
			// Only meaningful if the link was actually busy: 250 kB/s of baseline keeps
			// idle links from generating findings every time a user closes a tab.
			if peak > 250_000 && recent < peak*0.15 && txB > lastTxBytes {
				d.emit(dpiEvent{
					Event:    evThrottle,
					Severity: sevWarn,
					Detail: map[string]any{
						"recent_bytes_s": int64(recent),
						"peak_bytes_s":   int64(peak),
					},
					Message: "receive throughput collapsed to a small fraction of this link's own recent peak while it kept sending — consistent with volumetric throttling",
				})
				rateHistory = rateHistory[:0] // do not re-fire every tick
			}
		}

		// --- periodic health line ---
		if d.cfg.HealthSec > 0 && time.Since(lastHealth) >= time.Duration(d.cfg.HealthSec)*time.Second {
			lastHealth = time.Now()
			d.emitHealth(t)
		}

		lastRxBytes, lastTxBytes = rxB, txB
		lastCount, lastMax = cnt, mx
	}
}

// silenceRef is the instant that "how long have we heard nothing" is measured from: the
// last authenticated packet, or start-up when there has never been one.
func silenceRef(startAt time.Time, lastRxUnix int64) time.Time {
	if lastRxUnix > 0 {
		return time.Unix(lastRxUnix, 0)
	}
	return startAt
}

func (d *dpiLogger) emitHealth(t *Tunnel) {
	det := map[string]any{
		"tx_packets":  atomic.LoadUint64(&t.txPackets),
		"rx_packets":  atomic.LoadUint64(&t.rxPackets),
		"auth_fail":   atomic.LoadUint64(&t.authFail),
		"replay_drop": atomic.LoadUint64(&t.replayDrop),
		"reordered":   d.seqReorder.Load(),
		"probes":      d.cProbes.Load(),
		"scans":       d.cScans.Load(),
		"injections":  d.cInject.Load(),
		"ttl_anomaly": d.cTTLAnom.Load(),
		"events_lost": d.dropped.Load(),
	}
	if r := d.rttEWMA.Load(); r > 0 {
		det["rtt_ms"] = round2(float64(r) / 1000)
		det["rtt_min_ms"] = round2(float64(d.rttMin.Load()) / 1000)
	}
	if first, mx, cnt := d.seqFirst.Load(), d.seqMax.Load(), d.seqCount.Load(); mx > first && cnt > 0 {
		expected := mx - first + 1
		if expected >= cnt {
			det["loss_pct_lifetime"] = round2(float64(expected-cnt) * 100 / float64(expected))
		}
	}
	d.emit(dpiEvent{Event: evHealth, Severity: sevInfo, Detail: det})
}

// kernelWatch reports the kernel's own UDP error counters. Packets the kernel throws away
// never reach this process, so this is the only place they can be seen — and the checksum
// counter in particular is where forged and desynced datagrams land.
func (d *dpiLogger) kernelWatch() {
	prev := readUDPCounters()
	for {
		time.Sleep(30 * time.Second)
		cur := readUDPCounters()
		if cur == nil || prev == nil {
			prev = cur
			continue
		}
		det := map[string]any{}
		sev := sevInfo
		for _, k := range []string{"InCsumErrors", "RcvbufErrors", "NoPorts", "InErrors", "SndbufErrors"} {
			if delta := cur[k] - prev[k]; delta > 0 && cur[k] >= prev[k] {
				det[k] = delta
				switch k {
				case "InCsumErrors":
					sev = sevWarn
				case "RcvbufErrors", "SndbufErrors":
					if sev == sevInfo {
						sev = sevNotice
					}
				}
			}
		}
		prev = cur
		if len(det) == 0 {
			continue
		}
		msg := "kernel UDP error counters moved"
		if _, ok := det["InCsumErrors"]; ok {
			msg = "the kernel discarded UDP datagrams with bad checksums — forged or desynced packets are reaching this host"
		}
		if _, ok := det["RcvbufErrors"]; ok {
			msg += "; receive buffer overflowed, so the socket is not being drained fast enough (raise rcvbuf or net.core.rmem_max)"
		}
		d.emit(dpiEvent{Event: evKernelDrop, Severity: sev, Detail: det, Message: msg})
	}
}

// icmpWatch is the ICMP carrier's equivalent of kernelWatch.
//
// Two sources, because neither alone tells the whole story. /proc/net/snmp's Icmp: block
// counts what the host's ICMP layer rejected — bad checksums, unreachables and time-exceeded
// coming back — which is where forged or truncated carrier packets die. And /proc/net/raw
// carries a per-socket drop counter, which is the *only* place a raw socket's receive-buffer
// overflow is visible: those packets crossed the network fine and were then thrown away on
// this host for want of a reader. On the link this was written for that number was 22829 in
// a single 400 Mbit/s run, and nothing in the program could see it.
func (d *dpiLogger) icmpWatch() {
	prev := readSNMPBlock("Icmp:")
	prevDrops, haveDrops := d.rawSocketDrops()
	for {
		time.Sleep(30 * time.Second)

		det := map[string]any{}
		sev := sevInfo

		cur := readSNMPBlock("Icmp:")
		if cur != nil && prev != nil {
			for _, k := range []string{"InErrors", "InCsumErrors", "InDestUnreachs", "InTimeExcds", "OutErrors"} {
				if delta := cur[k] - prev[k]; delta > 0 && cur[k] >= prev[k] {
					det[k] = delta
					if k == "InErrors" || k == "InCsumErrors" {
						sev = sevWarn
					}
				}
			}
		}
		if cur != nil {
			prev = cur
		}

		if drops, ok := d.rawSocketDrops(); ok {
			if haveDrops && drops > prevDrops {
				det["RawRcvbufDrops"] = drops - prevDrops
				if sev == sevInfo {
					sev = sevNotice
				}
			}
			prevDrops, haveDrops = drops, true
		}

		if len(det) == 0 {
			continue
		}
		msg := "kernel ICMP counters moved"
		if _, ok := det["RawRcvbufDrops"]; ok {
			msg = "the kernel dropped ICMP carrier packets at the raw socket — they arrived and were " +
				"discarded here for want of a reader (raise rcvbuf/net.core.rmem_max, or icmp.readers)"
		} else if _, ok := det["InCsumErrors"]; ok {
			msg = "the kernel discarded ICMP messages with bad checksums — forged or corrupted packets are reaching this host"
		}
		d.emit(dpiEvent{Event: evKernelDrop, Severity: sev, Detail: det, Message: msg})
	}
}

// rawSocketDrops reads the drop counter of the carrier's own raw socket out of
// /proc/net/raw, matched by the socket inode the ICMP carrier published. Returns ok=false
// until that inode is known, or if the line cannot be found.
func (d *dpiLogger) rawSocketDrops() (uint64, bool) {
	ino := d.rawInode.Load()
	if ino == 0 {
		return 0, false
	}
	want := strconv.FormatUint(ino, 10)
	b, err := os.ReadFile("/proc/net/raw")
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(b), "\n")[1:] {
		f := strings.Fields(line)
		// sl local rem st tx_queue:rx_queue tr tm->when retrnsmt uid timeout inode ... drops
		if len(f) < 13 || f[9] != want {
			continue
		}
		v, err := strconv.ParseUint(f[len(f)-1], 10, 64)
		if err != nil {
			return 0, false
		}
		return v, true
	}
	return 0, false
}

// readUDPCounters parses the Udp: line pair out of /proc/net/snmp.
func readUDPCounters() map[string]uint64 { return readSNMPBlock("Udp:") }

// readSNMPBlock parses one header/value line pair out of /proc/net/snmp, which stores each
// protocol as a line of column names followed by a line of numbers under the same prefix.
func readSNMPBlock(prefix string) map[string]uint64 {
	b, err := os.ReadFile("/proc/net/snmp")
	if err != nil {
		return nil
	}
	lines := strings.Split(string(b), "\n")
	for i := 0; i+1 < len(lines); i++ {
		if !strings.HasPrefix(lines[i], prefix) || !strings.HasPrefix(lines[i+1], prefix) {
			continue
		}
		keys := strings.Fields(lines[i])[1:]
		vals := strings.Fields(lines[i+1])[1:]
		if len(keys) != len(vals) {
			return nil
		}
		out := make(map[string]uint64, len(keys))
		for j := range keys {
			v, err := strconv.ParseUint(vals[j], 10, 64)
			if err == nil {
				out[keys[j]] = v
			}
		}
		return out
	}
	return nil
}

// ---------------------------------------------------------------------------
// writer: JSONL with size-based rotation and a rate limit
// ---------------------------------------------------------------------------

func (d *dpiLogger) writer() {
	os.MkdirAll(filepath.Dir(d.cfg.Path), 0o750)
	var (
		f       *os.File
		size    int64
		minute  = time.Now().Truncate(time.Minute)
		inMin   int
		limited bool
	)
	open := func() {
		var err error
		f, err = os.OpenFile(d.cfg.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
		if err != nil {
			f = nil
			return
		}
		if st, err := f.Stat(); err == nil {
			size = st.Size()
		}
	}
	open()

	for e := range d.events {
		// Rate limit per wall-clock minute so a probe flood cannot fill the disk.
		if m := time.Now().Truncate(time.Minute); m != minute {
			if limited {
				// Say so in the log itself, otherwise the gap looks like quiet.
				line, _ := json.Marshal(dpiEvent{
					TS: time.Now().UTC().Format(time.RFC3339), Event: "log.rate_limited",
					Severity: sevNotice, Count: uint64(inMin - d.cfg.MaxPerMin),
					Message: "events suppressed by the per-minute rate limit",
				})
				if f != nil {
					n, _ := f.Write(append(line, '\n'))
					size += int64(n)
				}
			}
			minute, inMin, limited = m, 0, false
		}
		inMin++
		if inMin > d.cfg.MaxPerMin {
			limited = true
			continue
		}

		line, err := json.Marshal(e)
		if err != nil {
			continue
		}
		if d.cfg.Stdout != nil && *d.cfg.Stdout && e.Severity != sevInfo {
			fmt.Printf("[dpi] %s %s %s %s\n", e.Severity, e.Event, e.Src, e.Message)
		}
		if f == nil {
			open()
			if f == nil {
				continue
			}
		}
		n, err := f.Write(append(line, '\n'))
		if err != nil {
			f.Close()
			f = nil
			continue
		}
		size += int64(n)
		if size > int64(d.cfg.MaxSizeMB)<<20 {
			f.Close()
			d.rotate()
			open()
		}
	}
}

func (d *dpiLogger) rotate() {
	base := d.cfg.Path
	// Drop the oldest, shuffle the rest up.
	os.Remove(fmt.Sprintf("%s.%d", base, d.cfg.Keep))
	for i := d.cfg.Keep - 1; i >= 1; i-- {
		os.Rename(fmt.Sprintf("%s.%d", base, i), fmt.Sprintf("%s.%d", base, i+1))
	}
	os.Rename(base, base+".1")
}

// addStats folds the observer's counters into the monitor's stats file.
func (d *dpiLogger) addStats(s map[string]any) {
	if !d.enabled() {
		s["dpi_enabled"] = false
		return
	}
	s["dpi_enabled"] = true
	s["dpi_probes"] = d.cProbes.Load()
	s["dpi_scans"] = d.cScans.Load()
	s["dpi_injections"] = d.cInject.Load()
	s["dpi_replays"] = d.cReplayed.Load()
	s["dpi_ttl_anomalies"] = d.cTTLAnom.Load()
	s["dpi_events"] = d.cEvents.Load()
	s["dpi_events_dropped"] = d.dropped.Load()
	s["dpi_blackholes"] = d.cBlackhole.Load()
	s["dpi_reordered"] = d.seqReorder.Load()
	s["dpi_blackholed_now"] = d.blackholed.Load()
	if r := d.rttEWMA.Load(); r > 0 {
		s["rtt_ms"] = round2(float64(r) / 1000)
		s["rtt_min_ms"] = round2(float64(d.rttMin.Load()) / 1000)
		s["rtt_last_ms"] = round2(float64(d.rttLast.Load()) / 1000)
	}
	if p := d.peerTTL.Load(); p > 0 {
		s["peer_ttl"] = p
	}
	if first, mx, cnt := d.seqFirst.Load(), d.seqMax.Load(), d.seqCount.Load(); mx > first && cnt > 0 {
		expected := mx - first + 1
		if expected >= cnt {
			s["loss_pct"] = round2(float64(expected-cnt) * 100 / float64(expected))
		}
	}
}

func round2(f float64) float64 {
	return float64(int64(f*100+0.5)) / 100
}

// ---------------------------------------------------------------------------
// report: summarise the JSONL for the management menu
// ---------------------------------------------------------------------------

// dpiReport prints a human summary of a DPI log file.
func dpiReport(path string, since time.Duration) error {
	files := []string{path}
	for i := 1; i <= 4; i++ {
		p := fmt.Sprintf("%s.%d", path, i)
		if _, err := os.Stat(p); err == nil {
			files = append(files, p)
		}
	}
	type srcStat struct {
		src      string
		count    uint64
		classes  map[string]uint64
		last     string
		severity string
	}
	byClass := map[string]uint64{}
	bySrc := map[string]*srcStat{}
	var health []dpiEvent
	var notable []dpiEvent
	cutoff := time.Now().Add(-since)
	total := 0

	for _, fp := range files {
		b, err := os.ReadFile(fp)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var e dpiEvent
			if json.Unmarshal([]byte(line), &e) != nil {
				continue
			}
			if ts, err := time.Parse(time.RFC3339, e.TS); err == nil && ts.Before(cutoff) {
				continue
			}
			total++
			n := e.Count
			if n == 0 {
				n = 1
			}
			byClass[e.Event] += n
			if e.Src != "" {
				s := bySrc[e.Src]
				if s == nil {
					s = &srcStat{src: e.Src, classes: map[string]uint64{}}
					bySrc[e.Src] = s
				}
				s.count += n
				s.classes[e.Event] += n
				s.last = e.TS
				if e.Severity == sevHigh || (e.Severity == sevWarn && s.severity != sevHigh) {
					s.severity = e.Severity
				}
			}
			switch e.Event {
			case evHealth:
				health = append(health, e)
			default:
				if e.Severity == sevHigh || e.Severity == sevWarn {
					notable = append(notable, e)
				}
			}
		}
	}

	fmt.Printf("DPI report — last %s, %d records from %s\n\n", since, total, path)
	if total == 0 {
		fmt.Println("No events recorded in this window. Nothing has probed the carrier port and the path has behaved.")
		return nil
	}

	fmt.Println("Events by class")
	type kv struct {
		k string
		v uint64
	}
	var cls []kv
	for k, v := range byClass {
		cls = append(cls, kv{k, v})
	}
	sort.Slice(cls, func(i, j int) bool { return cls[i].v > cls[j].v })
	for _, c := range cls {
		fmt.Printf("  %-24s %8d\n", c.k, c.v)
	}

	if len(bySrc) > 0 {
		fmt.Println("\nTop sources (outside the tunnel-to-tunnel conversation)")
		var ss []*srcStat
		for _, s := range bySrc {
			ss = append(ss, s)
		}
		sort.Slice(ss, func(i, j int) bool { return ss[i].count > ss[j].count })
		if len(ss) > 15 {
			ss = ss[:15]
		}
		fmt.Printf("  %-24s %9s  %-8s %s\n", "SOURCE", "PACKETS", "WORST", "CLASSES")
		for _, s := range ss {
			var parts []string
			for c, n := range s.classes {
				parts = append(parts, fmt.Sprintf("%s=%d", strings.TrimPrefix(c, "probe."), n))
			}
			sort.Strings(parts)
			sev := s.severity
			if sev == "" {
				sev = sevInfo
			}
			fmt.Printf("  %-24s %9d  %-8s %s\n", s.src, s.count, sev, strings.Join(parts, " "))
		}
	}

	if len(notable) > 0 {
		fmt.Println("\nNotable findings (most recent last)")
		if len(notable) > 20 {
			notable = notable[len(notable)-20:]
		}
		for _, e := range notable {
			src := e.Src
			if src == "" {
				src = "-"
			}
			fmt.Printf("  %s  %-6s %-22s %-22s %s\n", e.TS, e.Severity, e.Event, src, e.Message)
		}
	}

	if len(health) > 0 {
		h := health[len(health)-1]
		fmt.Println("\nLatest flow health")
		keys := make([]string, 0, len(h.Detail))
		for k := range h.Detail {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("  %-20s %v\n", k, h.Detail[k])
		}
	}
	return nil
}
