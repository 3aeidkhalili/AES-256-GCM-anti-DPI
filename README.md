# aestun — AES-256-GCM anti-DPI server-to-server tunnel

A small tunnel between two Ubuntu servers. It carries IP traffic over a TUN interface with
**private/local IPs**, encrypts every packet with **AES-256-GCM** (or **ChaCha20-Poly1305**
on CPUs without AES-NI — see section 6, it is worth checking), and is designed so the wire
traffic is **indistinguishable from random data**: no handshake, no fixed header, no protocol
signature for DPI to match. It also **watches for DPI**, logging who probes the carrier port
and what the path does to the packets in flight (section 9).

Written in Go and vendored, so it still builds offline into a single static binary with no
runtime dependencies. The only third-party code is `golang.org/x/crypto/chacha20poly1305`
(upstream's audited AEAD — see section 6 for why hand-rolling one was not worth the risk) and
`golang.org/x/sys/unix`, both committed under `vendor/`.

---

## 1. How it works

```
[ server A: 10.8.0.1 ] <== encrypted UDP over the Internet ==> [ server B: 10.8.0.2 ]
        tun0                                                            tun0
```

Each server gets a `tun0` interface with a private IP (default `10.8.0.1` and
`10.8.0.2`). Anything sent to the peer's tunnel IP is captured from `tun0`,
encrypted, and shipped as a UDP datagram to the peer, where it is decrypted and
written back to its `tun0`. From the OS's point of view the two servers are on the
same small LAN.

### Wire format (per packet)

```
[ 12-byte random nonce ] [ AES-256-GCM ciphertext ] [ 16-byte GCM tag ]

plaintext inside the ciphertext:
[ 8-byte seq ] [ 2-byte pad-len ] [ inner IP packet ] [ random padding ]
```

* The nonce is random, the ciphertext/tag are random-looking → **the entire datagram
  is high-entropy** with no fixed bytes. There is nothing for DPI to fingerprint.
* The **sequence number** (anti-replay) and **random padding** live *inside* the
  encryption, so they never appear on the wire and size correlation is broken.
* There is **no handshake** and **no key exchange** — a passive observer sees only
  featureless UDP datagrams. Keys come from a pre-shared secret.

### Anti-fingerprint / security properties

| Property | How |
|---|---|
| Confidentiality + integrity | AES-256-GCM or ChaCha20-Poly1305 (AEAD); tampered packets are dropped |
| Per-direction keys | HKDF-SHA256 splits the PSK into A→B and B→A keys (no nonce reuse across directions) |
| Anti-replay | 4096-entry sliding window over the sequence number |
| Forward-ish secrecy | optional time-based key rotation (`rekey_interval`), no handshake required — both sides derive the same epoch key from the clock |
| Looks like random | no handshake, no fixed offsets, random nonce + random padding |
| NAT / roaming | peer address is learned/updated from any authenticated packet; keepalive keeps the mapping warm |

**Honest limitations:** this is a **pre-shared-key** tunnel. Anyone with the PSK can
read all traffic; epoch rotation limits nonce reuse and gives coarse key hygiene, but
it is *not* full forward secrecy (a leaked PSK compromises past and future traffic).
Keep the key secret (the config is `chmod 600`). With a static key, rotate the PSK
periodically for very high-volume, long-lived links (GCM random-nonce safety bound is
~2³² packets per key; epoch rotation keeps you far below it automatically).

---

## 2. Files

| File | Purpose |
|---|---|
| `tunnel.go` | protocol + crypto core (OS-independent, unit-tested) |
| `cipher.go` | cipher suite selection (AES-GCM / ChaCha20-Poly1305) + CPU capability detection |
| `csprng.go` | buffered randomness, so the packet path never calls `crypto/rand` |
| `dpilog.go` | DPI and probe observability — unsolicited ingress, path interference, reporting |
| `probe.go` | in-tunnel round-trip probes (latency, inside the encryption) |
| `offload.go` | UDP segmentation/coalescing, batched TUN reads, TUN attach ordering |
| `pacer.go` | optional carrier rate shaping (off by default; see section 7) |
| `obfs.go` | QUIC-shaped wire obfuscation — headers, header protection, size shaping |
| `quicinit.go` | synthetic QUIC handshake (RFC 9001 Initial packets + TLS ClientHello) |
| `hkdf.go` | HKDF-SHA256 key derivation (RFC 5869) |
| `main.go` | Linux TUN device, UDP/TCP carriers, main loop (build-tagged `linux`) |
| `pprof_on.go` / `pprof_off.go` | profiling endpoints, behind the `pprof` build tag |
| `*_test.go` | unit tests, allocation assertions and benchmarks (`go test`) |
| `vendor/` | the two vendored dependencies, so the build works offline |
| `aestun.sh` | one script: installer, management TUI, live monitor, zapret, network tuning, build, and the systemd-invoked NFQUEUE helper (`zap-rule`) |
| `aestun.service` | reference systemd unit |
| `config.server-a.json` / `config.server-b.json` | example configs |
| `aestun-linux-amd64` / `aestun-linux-arm64` | prebuilt binaries (if shipped) |

---

## 3. Quick start (recommended)

On **each** server, copy this whole folder over, then:

```bash
chmod +x aestun.sh
sudo ./aestun.sh install
```

The installer prompts for **everything** and applies network optimization. Run it on
both the **Iran** side and the **foreign** side:

* Choose **1) Iran server** on the inside box → becomes role `a`, tunnel IP `10.8.0.1`.
* Choose **2) Foreign server** on the outside box → becomes role `b`, tunnel IP `10.8.0.2`.
* Use the **same key** on both (generate it on the first server, paste it on the second).
* Use the **opposite role**, and set `peer` = the *other* server's public IP.

That's it — the tunnel comes up as a systemd service (`aestun`) that auto-starts on boot.

Verify:

```bash
sudo ./aestun.sh      # option 4 = ping test, option 2 = live monitor
```

No prebuilt binary for your CPU? Install Go and the installer builds from source
automatically, or run `./aestun.sh build amd64` (or `arm64`) on any machine with Go and drop
the result next to the scripts.

---

## 4. Management menu (`sudo ./aestun.sh`)

```
1) Setup / reconfigure tunnel (wizard)
2) Live monitoring dashboard      <- TX/RX rate, packets, uptime, peer, auth/replay drops
3) Service management             <- start/stop/restart/enable/disable/status
4) Connectivity test              <- ping the peer's tunnel IP
5) Live logs                      <- journalctl -u aestun -f
6) Show config                    <- key masked
7) Edit config                    <- then optionally restart
8) Generate new key
9) Network optimization           <- show / apply / remove sysctl tuning
d) DPI / probe log                <- who is probing, what the path is doing (section 9)
z) zapret module                  <- optional DPI desync layer
u) Uninstall
```

The **live monitor** reads `/run/aestun/stats.json` (written by the daemon every 2s)
and shows real-time throughput, packet counts, last-received age, and the
authentication/replay drop counters.

---

## 5. Configuration reference

Every value is prompted by `aestun.sh install`, or edit `/etc/aestun/config.json` directly.

| Field | Default | Meaning |
|---|---|---|
| `role` | — | `a` or `b`; **must differ** on the two servers |
| `key` | — | base64 of 32 bytes; **identical** on both servers (`aestun keygen`) |
| `cipher` | `aes-gcm` | `aes-gcm` or `chacha20-poly1305`; **identical** on both servers (section 6) |
| `listen` | `0.0.0.0:51820` | local UDP listen address |
| `peer` | — | the other server `host:port` (learned from traffic if empty) |
| `transport` | `udp` | carrier: `udp` or `tcp`. **Prefer udp** — see the note below |
| `obfs` | `none` | `quic` presents the carrier as a QUIC connection (section 10) |
| `sni` | `www.cloudflare.com` | server name in the synthetic handshake (`obfs: quic` only) |
| `shape` | `true` | quantise datagram sizes onto buckets (`obfs: quic` only) |
| `tun_name` | `tun0` | TUN interface name |
| `local_ip` | `10.8.0.x/24` | this server's tunnel IP (CIDR) |
| `peer_ip` | `10.8.0.y` | the other server's tunnel IP (used by the ping test) |
| `mtu` | `1300` | interface MTU. Raise it if your path allows — see section 7 |
| `txqueuelen` | `1000` | interface tx queue length |
| `pad_max` | `64` | max random padding bytes per packet (0 disables; anti-DPI) |
| `rekey_interval` | `3600` | key-rotation seconds (0 = static key) |
| `keepalive` | `25` | keepalive seconds (0 disables) |
| `rcvbuf` | `16777216` | UDP socket receive buffer (bytes); absorbs bursts so the kernel doesn't drop |
| `sndbuf` | `16777216` | UDP socket send buffer (bytes) |
| `manage_ip` | `true` | let the daemon run the `ip` commands |
| `stats_path` | `/run/aestun/stats.json` | monitor stats file (empty disables) |
| `offload` | `true` | kernel UDP segmentation/coalescing (section 7) |
| `rate_mbps` | `0` | shape the carrier to this rate; 0 = off. Measure before using (section 7) |
| `gc_percent` | `100` | Go GC target; the packet path allocates nothing, so raising it only inflates RSS |
| `mem_limit` | `67108864` | soft heap ceiling in bytes |
| `max_procs` | `0` | `GOMAXPROCS` override; 0 leaves it to the runtime |
| `pprof_addr` | — | e.g. `127.0.0.1:6060`; only works in a binary built with `-tags pprof` |
| `dpi_log` | *(on)* | DPI/probe observability — see section 9 |

### Packet loss / lag note
The daemon sets the UDP socket buffers (`rcvbuf`/`sndbuf`, 8 MiB each) so traffic
bursts are absorbed instead of dropped. Watch for drops with
`grep Udp: /proc/net/snmp` — a rising **RcvbufErrors** means the buffer is too small
*or* `net.core.rmem_max` is below `rcvbuf` (the kernel caps the buffer at `rmem_max`).
Run the network optimization (below) so `rmem_max` is large enough — otherwise your
8 MiB request is silently clamped to the ~200 KB default and packets drop under load.

### Transport note
The carrier multiplexes **every** inner connection. Over TCP, one lost carrier segment
head-of-line-blocks all of them at once, and the inner TCP retransmits on top of the outer
one — measured on a real link: 4.7% carrier retransmission, a permanently backed-up send
queue, and every user stalling in lockstep. Over UDP a lost packet costs only the connection
whose bytes it carried. Use `tcp` only where UDP is blocked outright, and expect the stalls.

### MTU note
Overhead per packet is ~38 bytes (nonce+tag+seq/pad) plus padding plus the outer
IP/UDP headers (28). Default `mtu=1300` keeps the carrier datagram under 1500 on
standard paths, avoiding fragmentation. Lower it if your path MTU is smaller. The
daemon also sets `tcp_mtu_probing=1` (see below) to survive MTU black holes for inner
TCP.

---

## 6. Cipher choice — check this before anything else

`cipher` must be the same on both servers. It is not negotiated (there is no handshake to
negotiate in, by design), and the two ends will simply not understand each other if they
disagree.

| Suite | Use it when |
|---|---|
| `aes-gcm` | **both** CPUs expose AES-NI *and* PCLMULQDQ |
| `chacha20-poly1305` | **either** CPU does not |

The wire format is byte-identical either way — same 12-byte nonce, same 16-byte tag, same
datagram sizes — so the choice is invisible to an observer. It is purely a CPU decision.

Why it matters more than it looks: Go only takes its fast AES-GCM path when the hardware
offers both instructions. Without them it falls back to a constant-time software AES plus a
generic GHASH, and virtualised CPUs very often hide those flags. Measured on this project's
own two servers, sealing one 1300-byte packet:

| | AES-256-GCM | ChaCha20-Poly1305 |
|---|---|---|
| Xeon E5-2680 v4 (has AES-NI) | **0.97 µs** | 1.29 µs |
| QEMU Virtual CPU 2.5+ (no `aes`, no `pclmulqdq`, no SSE4) | 26.8 µs | **6.6 µs** |

A link is only as fast as its slower end, so one endpoint without AES-NI is enough to make
`chacha20-poly1305` the right answer for **both**.

Ask a machine what it has:

```bash
aestun cipherinfo
# aes_hardware=false
# cpu=QEMU Virtual CPU version 2.5+
# chacha20-poly1305          <- the recommendation, on its own line
```

The installer runs this for you and defaults the prompt to the answer; `sudo ./aestun.sh
upgrade` changes the setting on an existing install without re-running the whole wizard.

### Measured effect on the live link

Same test on both: 2,900 packets/s of 1200-byte payload across the real tunnel, CPU sampled
from `/proc/<pid>/stat`.

| | server A (Iran, has AES-NI) | server B (foreign, no AES-NI) |
|---|---|---|
| before | 14.3% CPU · 50.2 µs/pkt · 8.8 MB RSS | 27.9% CPU · 96.3 µs/pkt · 8.7 MB RSS |
| after | **12.8% CPU · 43.5 µs/pkt · 5.3 MB RSS** | **15.7% CPU · 52.7 µs/pkt · 8.1 MB RSS** |

Isolated back-to-back on one host (both ends measured, so it excludes network cost and
isolates the tunnel itself):

| build | CPU per packet, both ends |
|---|---|
| previous release, AES-GCM | 162.6 µs |
| this release, AES-GCM | 153.4 µs |
| this release, ChaCha20-Poly1305 | **103.6 µs** |

The remaining per-packet cost is dominated by the kernel: a TUN read, a TUN write, and the
UDP send/receive path. That is the floor for a userspace tunnel of this design.

### What else changed on the packet path

* **Zero allocations per packet, in both directions.** `seal` and `open` take a caller-owned
  scratch struct that lives for the life of the goroutine. Previously each packet allocated
  six objects and ~2.9 kB on the way out and four on the way in, which the collector then had
  to chase. `perf_test.go` asserts the count is zero, so it stays that way.
* **No `crypto/rand` on the packet path.** It was being called once or twice per packet at
  ~1.9 µs a call — more than AES-GCM itself costs on a machine that *has* AES-NI. Randomness
  now comes from a buffered pool (`csprng.go`).
* **No per-packet address allocation.** The socket calls now use `netip.AddrPort`, a value
  type; the `*net.UDPAddr` forms allocate a fresh address with a heap-allocated IP inside it
  for every datagram received.
* **Lock-free AEAD lookup in both directions.** The receive path took a mutex per packet.
* **A padding bug.** With `obfs: quic` and `shape: false`, the padding length was derived from
  the first two nonce bytes — which under obfuscation are the connection ID, constant for the
  whole connection. Every packet therefore got *identical* padding and the size randomisation
  it was supposed to provide did nothing at all.

---

## 7. Throughput: offload, MTU, and knowing where the ceiling is

Before tuning anything, find out what is actually limiting you. On the reference deployment
the answer changed twice.

### Measure the path first

```bash
# raw link, outside the tunnel
iperf3 -s                      # on one server
iperf3 -c OTHER_IP -t 12 -P 4  # on the other

# then the same through the tunnel
iperf3 -s -B 10.8.0.1
iperf3 -c 10.8.0.1 -t 12 -P 4
```

If the tunnel is within ~10% of the raw link, the tunnel is not your problem and no amount
of tuning it will help. On the reference link: raw 216 Mbit/s, tunnel 195 Mbit/s — 90%, of
which about 3 points is the encapsulation itself and cannot be removed.

### The packet rate ceiling, and what removed it

Even when the link is the cap, CPU decides your headroom. Sending was costing ~45 µs of
kernel time per packet — a read syscall from the TUN device, a send syscall to the socket,
and a full trip down the UDP output path, all once per 1300 bytes — against 6.6 µs of actual
encryption. Three changes attack that, all on by default:

| Change | Effect |
|---|---|
| `mtu` 1300 → 1420 | 9% fewer packets for the same bytes; the path here carries a full 1500, and 1420 + 39 bytes of tunnel header + 28 of IP/UDP = 1487 still fits. **Sender CPU 92.6% → 86.8%, retransmissions −33%.** |
| UDP segmentation offload (`offload`) | consecutive equal-sized datagrams go out in **one** sendmsg and the kernel splits them below IP, so one syscall and one route lookup cover up to 64 packets. Receiving uses UDP_GRO the same way in reverse. |
| batched TUN drain | one blocking read, then non-blocking reads of whatever is already queued, so the batch above has something to work with. A quiet link still sends immediately — nothing waits for a batch to fill. |

Back-to-back on one host, with the network taken out of the picture:

| | throughput |
|---|---|
| offload off | 305 Mbit/s |
| offload on | **457 Mbit/s** |

And on the live link, at the same delivered throughput:

| | sender CPU | receiver CPU |
|---|---|---|
| before | 92.6% | — |
| after MTU + offload | **70.5%** | 60.7% |

Nothing changes on the wire. Segmentation happens below IP; the peer receives exactly the
same datagrams, in the same order, at the same sizes. If a kernel refuses the socket
options the code logs `udp_gso=false` and sends one datagram per syscall as before.

### Socket buffers

`rcvbuf`/`sndbuf` default to 16 MiB, matching the `net.core.rmem_max` the network tuning
sets. At 8 MiB the receiver was still overflowing on a saturated link — 660 dropped
datagrams in a twelve-second run, each one costing an inner TCP retransmission. At 16 MiB
the same run drops **zero**. The DPI log reports this as `kernel.udp_errors` with
`RcvbufErrors`, so you do not have to go looking for it.

### Watch out for a policer, and do not assume shaping fixes it

Sweeping offered rate against delivered rate is worth doing once on any link. On this one it
produced a cliff, not a curve:

| offered | delivered | loss |
|---|---|---|
| 185 Mbit/s | 183 Mbit/s | 0% |
| 210 Mbit/s | 210 Mbit/s | 0% |
| 220 Mbit/s | 145 Mbit/s | 34% |
| 260 Mbit/s | 155 Mbit/s | 40% |

```bash
for R in 100 150 200 220 260; do iperf3 -c PEER -u -b ${R}M -t 8 -l 1400 | grep receiver; done
```

That is a policer: a few percent over the threshold and delivered throughput *falls by a
quarter*. `rate_mbps` shapes the carrier below such a threshold, and shaping is not policing
— it delays rather than drops, so the inner TCP senders see the backpressure and slow down
on their own.

**It did not help here, and the honest result is worth recording.** Shaped to 200 Mbit/s the
link delivered 181 Mbit/s at 138 ms under load; unshaped it delivered 196 Mbit/s at 92 ms.
Retransmissions did fall by 63%, but BBR with `fq` was already finding a better operating
point than a token bucket sitting above the TUN queue, and the bucket's own queue added more
latency than the loss it prevented. `rate_mbps` therefore defaults to `0`, off. Turn it on
only if you have measured your own path and measured that it helps — a wrong value is just a
speed limit.

### What about KCP / kcptun-style transports?

A reasonable question on a lossy link, and the measurements above answer it for this one.
KCP's value is aggressive ARQ plus FEC to paper over **random** loss. The loss here is not
random: it is exactly 0% up to 210 Mbit/s and only appears when the policer is crossed. There
is nothing for FEC to repair, and KCP's extra retransmissions and parity packets would add
offered load to a path that punishes precisely that.

There is also a structural objection, and it is the same one that makes `transport: tcp` a
last resort (section 5): the carrier multiplexes *every* inner connection. KCP is a reliable,
ordered stream, so a single loss on it head-of-line-blocks every user at once and its
retransmissions stack on top of the inner TCP's own — which is the failure this project
already measured at 4.7% carrier retransmission and permanent queue backup. kcptun avoids
this by sitting under a single proxied connection at a time, not under a whole IP tunnel.

If your path does turn out to have genuine random loss — check with the UDP sweep above; the
signature is non-zero loss at rates *well below* the knee — then the useful thing to add is
FEC alone, not ARQ: parity recovers isolated drops without any head-of-line blocking. That is
a reasonable addition to this design. Blanket KCP is not.

---

## 8. Network optimization (Ubuntu tuning)

Applied at install time (you can decline, and manage it later from menu option 9).
Writes `/etc/sysctl.d/99-aestun.conf`:

* **BBR + fq** congestion control / qdisc (big throughput win on lossy/long links).
* Larger **socket buffers** (`rmem_max`/`wmem_max`, default 16 MiB) and TCP
  `rmem`/`wmem` windows for connections traversing the tunnel.
* `tcp_mtu_probing=1`, `tcp_fastopen=3`, `tcp_slow_start_after_idle=0`.
* UDP `udp_rmem_min`/`udp_wmem_min` raised (the carrier is UDP).
* `ip_forward` enabled (so you can route through the tunnel if you later want to).
* `netdev_max_backlog`, `somaxconn`, `nf_conntrack_max` raised.
* Loads the `tcp_bbr` module and pins it via `/etc/modules-load.d/aestun-bbr.conf`.
* The daemon sets the TUN `txqueuelen` from config.

Congestion control and buffer size are configurable at the prompt (`bbr`/`cubic`,
bytes). `remove_network_opt` (menu → 9 → 3) reverts it.

> **Apply it on BOTH servers, and it persists across reboots** (`/etc/sysctl.d/99-aestun.conf`).
> If one side reverts to defaults (e.g. after a reboot without the file), its UDP
> receive buffer drops to ~200 KB and it starts dropping tunnel packets under load —
> the classic cause of "the tunnel works but Instagram/video lags and stalls." Verify
> both sides with `sysctl net.ipv4.tcp_congestion_control net.core.rmem_max`.

---

## 9. DPI and probe log (`dpi_log`)

Traffic counters tell you how much crossed the tunnel. They do not tell you **who else is
talking to the carrier port**, or **what the path is doing to your packets** — and those are
the two things that matter once an ISP starts taking an interest in a link. This module adds
both, on by default, and costs essentially nothing when nothing is happening.

### What it watches

**1. Everything arriving that is not the peer.** Each datagram that fails to authenticate as
peer traffic is classified and aggregated per source address, so a port scan collapses into a
single record instead of ten thousand lines. The classes are chosen so that each one means
something different:

| Event | What it means |
|---|---|
| `probe.quic_initial` | a stranger sent a QUIC handshake to the carrier port. The obfuscation layer answers Initials, so this is someone checking whether the port *really* speaks QUIC. The Initial is decrypted (Initial keys are public by design) and the **server name from the ClientHello is recorded** — a censor's prober usually replays a plausible one. |
| `probe.replay` | a datagram that decrypted correctly but replayed a sequence number already seen. From a third party this is a **recording of your own traffic being played back at you**, which is the classic way a censor confirms what a suspicious flow is. High severity, and rightly so. |
| `inject.spoofed_peer` | unauthenticated datagrams carrying the peer's own source address — on-path injection, or the peer's own zapret desync fakes. |
| `anomaly.ttl` | a packet from the peer's address whose IP hop count disagrees with the peer's established one. An injector sits closer than the real peer and has to guess this value; being wrong by one hop gives it away. The baseline is learned from several agreeing packets, so one forged packet cannot set it. |
| `scan.unauth` | ordinary background noise. Random junk that merely happens to set the QUIC form bit is filed here, not as a probe, so the probe classes keep their meaning. |

**2. What the path does to the packets.** The inner sequence numbers already exist for
anti-replay, so loss and reordering are measured for free, with nothing extra sent:

| Event | What it means |
|---|---|
| `path.blackhole` | still transmitting, nothing coming back for the whole silence window. If nothing has *ever* come back the message says so — that is the "wrong key, wrong port, or blocked" case. |
| `path.throttle` | receive throughput collapsed to a fraction of this link's own recent peak while it kept sending. |
| `path.loss_burst` | sustained loss on the authenticated stream. |
| `path.rtt_spike` | round-trip time well above its own baseline, measured by a small probe frame **inside** the tunnel encryption — invisible on the wire, so it adds no signature. |
| `kernel.udp_errors` | the kernel's own UDP counters. Bad-checksum drops matter most: forged and desynced packets die in the kernel and are otherwise invisible to userspace entirely. |
| `flow.health` | a periodic summary line: loss, RTT, reordering, probe and scan totals. |

### Reading it

```bash
sudo ./aestun.sh              # menu -> d) DPI / probe log
aestun dpi-report -hours 24   # or straight from the command line
```

```
Events by class
  scan.unauth                    40
  inject.spoofed_peer             5
  probe.quic_initial              3
  probe.replay                    3

Top sources (outside the tunnel-to-tunnel conversation)
  SOURCE                     PACKETS  WORST    CLASSES
  203.0.113.9:41834               40  info     scan.unauth=40
  198.51.100.4:4444                5  high     inject.spoofed_peer=5
  198.51.100.7:47852               3  warn     quic_initial=3
```

The live monitor (menu → 2) shows the same counters in its DPI panel, and non-`info`
findings are mirrored to the journal, so `journalctl -u aestun -f` carries them too.

### Prove it works on your own box

Menu → `d` → `5` sends this server's own carrier port the traffic a prober would, then prints
what the observer made of it. The detectors were verified this way against real packets:
QUIC Initials, a genuine tunnel packet captured off the wire and replayed, forged datagrams
wearing the peer's exact address and port, and plain scanning — each one classified correctly.

### Cost

Authenticated peer packets — which is to say all of them, almost all of the time — touch
nothing here but a few atomic increments; there is a test asserting that path allocates
nothing. Events reach the writer through a buffered channel with a non-blocking send, so a
flood of probes can never slow or block the packet loops. The log is JSONL, rate-limited per
minute, size-rotated, and says so in the log itself when it suppresses anything.

| Field | Default | Meaning |
|---|---|---|
| `enabled` | `true` | master switch |
| `path` | `/var/log/aestun/dpi.jsonl` | JSONL output |
| `max_size_mb` / `keep` | `16` / `2` | rotation |
| `max_per_min` | `240` | event rate limit |
| `flush_sec` | `60` | per-source aggregation window |
| `health_sec` | `300` | heartbeat interval (0 = off) |
| `probe` / `probe_sec` | `true` / `20` | in-tunnel RTT probes |
| `silence_sec` | `60` | silence before a blackhole is declared |
| `max_sources` | `2048` | per-source table cap |
| `stdout` | `true` | mirror findings to the journal |

## 10. QUIC obfuscation (`obfs: quic`)

Set `"obfs": "quic"` on **both** servers (the two ends must agree; the format is not
compatible with `none`).

The payload is AEAD ciphertext, so against *content* inspection there is nothing left to
improve — uniform random bytes are the optimum. The problem is that this is also the tell.
Real protocols have structure; a flow that is high-entropy from byte 0, bimodal in packet
size, and heartbeats on an exact period is recognisable without anyone decrypting a thing.
This layer attacks that surface rather than the crypto:

| Signature | What the layer does |
|---|---|
| high entropy starting at byte 0 | a QUIC v1 short header — form bit, fixed bit, stable connection ID |
| a plainly incrementing counter | packet numbers are header-protected exactly as RFC 9001 specifies, so the field looks random |
| no handshake ever observed | the flow opens with a real Initial packet carrying a TLS ClientHello (SNI + `h3` ALPN), encrypted with the standard Initial keys — an inspector that decrypts it finds an ordinary connection to an ordinary host |
| 1-RTT packets unrelated to that handshake | each side adopts the connection ID its peer advertised, so the data packets belong to the handshake |
| bimodal packet sizes | sizes are quantised onto buckets, folding the small-packet cluster into the distribution |
| keepalive on an exact period | the interval is jittered ±40% |

Verified with Wireshark's own QUIC dissector against a capture of the real link: every packet
decodes as QUIC, the ClientHello and its SNI are readable, and the
"Unknown QUIC connection. Missing Initial Packet" expert warning goes from 19/20 packets to
zero. Overhead is one byte of header plus the shaping padding.

**What this does not claim.** It removes the cheap, specific signatures a classifier keys on.
It is not a proof of undetectability, and nobody can honestly offer one: a statistical
classifier trained on flow duration, volume, and timing may still separate this from real
QUIC, and volumetric throttling of a long-lived high-rate flow does not depend on
classification at all. Treat it as raising the cost of detection, not eliminating it.

## 11. zapret module (optional DPI bypass)

[bol-van/zapret](https://github.com/bol-van/zapret) is a DPI-circumvention toolkit.
This project can layer its `nfqws` desync on the tunnel's **carrier** UDP packets so a
censoring ISP has a harder time recognizing or throttling them. From `aestun.sh` → `z`:

1. **install** — clones zapret and **builds `nfqws` from source** (upstream no longer ships
   prebuilt binaries in the git tree). Installs the build deps automatically
   (`build-essential`, `libnetfilter-queue-dev`, `libnfnetlink-dev`, `libmnl-dev`,
   `libcap-dev`, `zlib1g-dev`). Result: `/opt/zapret/nfq/nfqws`.
2. **enable** — adds an `iptables` NFQUEUE rule for outbound UDP to the tunnel port and
   runs `nfqws` as a service (`aestun-zapret`).
3. **status / disable / remove**.

The default desync mode (`--dpi-desync=fake --dpi-desync-repeats=6`) is a sane starting
point; tune it for your network with zapret's own `blockcheck.sh`. If traffic breaks,
disable the module — the tunnel itself does not depend on it.

---

## 12. Manual deployment (without the wizard)

```bash
# build (any machine with Go), or use the shipped binary
./aestun.sh build amd64

# on each server
sudo install -m0755 aestun-linux-amd64 /usr/local/bin/aestun
sudo mkdir -p /etc/aestun
aestun keygen                              # run once, put the SAME output in both configs
sudo cp config.server-a.json /etc/aestun/config.json   # edit key/peer/IPs; role b uses config.server-b.json
sudo cp aestun.service /etc/systemd/system/
sudo systemctl enable --now aestun
sudo ufw allow 51820/udp                   # if using ufw
```

---

## 13. Troubleshooting

* **No ping over the tunnel** → check both services are `active`, the UDP port is open
  in the cloud firewall/security group *and* the OS firewall, and that the key is
  identical and roles are opposite.
* **`auth_fail` climbing** (monitor) → wrong key, mismatched roles, or just Internet
  scanners hitting the port (harmless).
* **Works then dies at hour boundaries** → clock skew with `rekey_interval` set; the
  receiver tolerates ±1 epoch, so keep NTP running (default on Ubuntu) or set
  `rekey_interval: 0`.
* **Throughput lower than expected** → confirm BBR is active (`sysctl -n
  net.ipv4.tcp_congestion_control`), and lower `mtu` if the path fragments.
* **Tunnel dead after a restart, both ends "active", nothing received** → check whether the
  carrier's exact source-port/destination-port pair has been blocked. This happened on the
  reference deployment: with both servers on `443`, plain random UDP from source port 443 to
  the peer's 443 stopped arriving, while the *same* random UDP from an ephemeral source port
  went through untouched. The block was on the 5-tuple, not the host — ICMP and TCP to the
  same IP were fine. Moving one end to a different listen port restored the link immediately.
  Test it without guessing:

  ```bash
  systemctl stop aestun
  python3 -c "import socket,os
  s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('0.0.0.0',443))
  [s.sendto(os.urandom(200),('PEER_IP',443)) for _ in range(5)]"
  # then on the peer:  tcpdump -i any -n 'udp and src host YOUR_IP'
  ```
  Nothing arrives, but the same test from an unbound socket does? The pair is blocked; change
  a port. Note the destination port must still be open in the peer's cloud firewall — pick the
  new port on whichever side has the more permissive one.
* **`path.blackhole` in the DPI log** → exactly the case above, or the peer address, port, key
  or `cipher` does not match. The event says which of the two it is by reporting whether
  anything has *ever* been received.
* **`cipher` mismatch** → the two ends will not understand each other at all: `rx_packets`
  stays 0 and `auth_fail` stays 0, because nothing even reaches the AEAD. Both servers must
  carry the same value.
* **Logs** → `journalctl -u aestun -f`; DPI findings also at `/var/log/aestun/dpi.jsonl`.

---

## 14. Building & testing

```bash
go test ./...                 # protocol/crypto/observer unit tests (run natively, any OS)
go test -bench . -benchtime 2s   # per-packet cost and allocation counts on THIS cpu
./aestun.sh build amd64       # -> aestun-linux-amd64
./aestun.sh build arm64       # -> aestun-linux-arm64
./aestun.sh build amd64 pprof # -> aestun-linux-amd64-pprof, adds net/http/pprof
```
