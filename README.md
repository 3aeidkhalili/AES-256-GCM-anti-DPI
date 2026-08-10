# 🛡️ aestun — AES-256-GCM anti-DPI server-to-server tunnel

> `🐧 Linux` · `🔒 AES-256-GCM / ChaCha20-Poly1305` · `🥷 QUIC + TLS wire disguise` · `📦 single static Go binary` · `🛰️ built-in DPI observer` · `⚙️ zero-alloc packet path`

A small, fast tunnel between two Ubuntu servers (built for an **🇮🇷 Iran ↔ 🌍 foreign** link). It
carries IP traffic over a TUN interface with **private/local IPs**, encrypts every packet with
**AES-256-GCM** (or **ChaCha20-Poly1305** on CPUs without AES-NI — see §6, it is worth
checking), and is designed so the wire traffic is **indistinguishable from random data**: no
handshake, no fixed header, no protocol signature for DPI to match. It also **watches for DPI**,
logging who probes the carrier port and what the path does to the packets in flight (§9).

Written in Go and vendored, so it still builds **offline** into a single static binary with no
runtime dependencies. The only third-party code is `golang.org/x/crypto/chacha20poly1305`
(upstream's audited AEAD — see §6 for why hand-rolling one was not worth the risk) and
`golang.org/x/sys/unix`, both committed under `vendor/`.

### ✨ Features at a glance

| | Capability | Default | Where |
|---|---|---|---|
| 🔒 | AEAD encryption, per-direction keys, anti-replay, epoch rotation | on | §1 |
| 🥷 | **QUIC** wire disguise over UDP (synthetic handshake, header protection, size buckets) | on with `obfs:quic` | §10 |
| 🧣 | **TLS** wire disguise over TCP (synthetic ClientHello/ServerHello + application-data records) | on with `tcp`+`obfs:quic` | §10.1 |
| 🛡️ | **QUIC v2** handshake cover — passes carriers that drop every QUIC v1 long header | on with `obfs:quic2` | §10.2 |
| 📞 | **DTLS** wire disguise over UDP (1.2 records + plaintext ClientHello cover) | on with `obfs:dtls` | §10.3 |
| 🎭 | **desync** — native in-process fake-QUIC injector (the zapret idea, no NFQUEUE) | **on** | §15.1 |
| 🫧 | **junk** — flow-start cover traffic | **on** | §15.2 |
| 🔀 | **hop** — keyed synchronised UDP port hopping | off | §15.3 |
| ✂️ | **split** — IP-fragment the disposable fakes | **on** | §15.4 |
| 🔁 | **tcp_rotate** — rotate the TCP connection to dodge volumetric throttling | off | §15.5 |
| 🧩 | **zapret** — optional external `nfqws` desync (now covers TCP + UDP + any protocol) | off | §11 |
| 🧪 | **auto-test** — sweep every method/protocol on the live link and apply the best | menu `t` | §16 |
| 🛰️ | **DPI observer** — probes, replays, injection, TTL anomalies, throttle/blackhole detection | on | §9 |

> 🧭 **Recommended default (verified on a live link):** `transport: udp` + `obfs: quic2` +
> **desync + split + junk**. See the field-test log in **§17** — measured on the reference
> servers while they carried real user traffic. Prefer `quic2` over `quic` on Iranian
> carriers: both carry traffic identically, but v1's handshake cover is dropped outright
> there, which silently removes the disguise §10 exists to provide (**§10.2**).

> 🇮🇷 **فارسی:** یک راهنمای کامل فارسی در **[README.fa.md](README.fa.md)** هست.

---

## 🧭 0. Start here — the short version

**What this is.** Two servers, one encrypted tunnel between them. You get a private network
link (`10.8.0.1` ↔ `10.8.0.2`) that carries any IP traffic, and the bytes on the wire are
built so that a censor's Deep Packet Inspection box cannot tell what they are.

**The usual setup.** One server inside a censored network, one outside. Users connect to the
inside server; their traffic rides the tunnel out.

```
   your users  ──▶  🇮🇷 server A  ══ encrypted tunnel ══▶  🌍 server B  ──▶  the internet
                    (role "a")        looks like QUIC          (role "b")
```

**Install it — the whole thing, on each server:**

```bash
git clone https://github.com/YOURNAME/aestun && cd aestun
sudo ./aestun.sh install     # answer the questions; run this on BOTH servers
```

Run `sudo ./aestun.sh` afterwards for the menu (status, live dashboard, logs, tuning).

Three things **must be identical on both servers**, or nothing will work: the `key`, the
`cipher`, and the `obfs` mode. Everything else is per-server.

### Which options should I pick?

If you do not want to read the rest of this document, use these answers.

| Question | Answer | Why |
|---|---|---|
| `transport` | **`udp`** | ~3× faster than `tcp` here (650 vs 200 Mbit/s) and far better latency. Use `tcp` only if UDP is blocked outright. |
| `obfs` | **`quic2`** | Makes the traffic look like a normal QUIC connection. `quic` looks the same but its opening handshake is **deleted by Iranian networks**, so the disguise quietly stops working (§10.2). |
| `cipher` | **`chacha20-poly1305`** unless *both* CPUs have AES-NI | On a CPU without AES-NI, AES is slow and software-only. The wizard checks and tells you (§6). |
| socket buffers | **2 MiB** (the default) | Bigger is *not* better — it is a queue, and an 8 MiB one adds ~60 ms of lag whenever the link is busy (§7.1). |
| anti-DPI modules | start with all **off** | Turn them on only if the link is actually being interfered with. They cost speed and solve problems you may not have (§15). |

**Not sure it is working?** `sudo ./aestun.sh` → *4) Connectivity test*. If that pings, the
tunnel is up. If it does not, go to §13.

### Words you will see

| Term | In plain language |
|---|---|
| **DPI** | The censor's machine that reads passing traffic and decides what to block. |
| **carrier** | The real UDP/TCP connection between your two servers, that everything else hides inside. |
| **obfs / disguise** | Making the carrier *look* like some ordinary protocol so DPI ignores it. |
| **cover / handshake cover** | Fake opening packets that make the flow look like a real QUIC or DTLS session starting. They carry no data. |
| **role a / role b** | Which end is which. `a` opens the conversation (put it on the inside server), `b` answers. |
| **bufferbloat** | Oversized queues. Speed looks fine, but ping goes bad the moment the link is busy. |

---

## ⚙️ 1. How it works

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

## 📁 2. Files

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
| `desync.go` | native in-process DPI desync — raw-socket fake QUIC injection (the zapret `nfqws` idea, ours; section 15) |
| `junk.go` | flow-start cover traffic (section 15) |
| `hop.go` | keyed synchronised port hopping (section 15) |
| `split.go` | IP-fragmentation of the disposable desync fakes (section 15) |
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

## 🚀 3. Quick start (recommended)

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

## 🎛️ 4. Management menu (`sudo ./aestun.sh`)

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
d) DPI / probe log                <- who is probing, what the path is doing (§9)
x) Anti-DPI hardening             <- toggle desync / junk / port-hop / split (§15)
t) Auto-test methods              <- sweep every method/protocol, apply the best (§16)
z) zapret module                  <- optional external DPI desync layer (§11)
u) Uninstall
```

The **live monitor** reads `/run/aestun/stats.json` (written by the daemon every 2s)
and shows real-time throughput, packet counts, last-received age, and the
authentication/replay drop counters.

---

## 🔧 5. Configuration reference

Every value is prompted by `aestun.sh install`, or edit `/etc/aestun/config.json` directly.

| Field | Default | Meaning |
|---|---|---|
| `role` | — | `a` or `b`; **must differ** on the two servers |
| `key` | — | base64 of 32 bytes; **identical** on both servers (`aestun keygen`) |
| `cipher` | `aes-gcm` | `aes-gcm` or `chacha20-poly1305`; **identical** on both servers (section 6) |
| `listen` | `0.0.0.0:51820` | local UDP listen address |
| `peer` | — | the other server `host:port` (learned from traffic if empty) |
| `transport` | `udp` | carrier: `udp` or `tcp`. **Prefer udp** — see the note below |
| `obfs` | `none` | `quic` shapes the carrier as its natural TLS-family form: **QUIC** over UDP (section 10), **TLS** over TCP (section 10.1). `quic2` is the same wire format with a **QUIC v2** handshake cover — use it where v1 is filtered (section 10.2). `dtls` shapes the carrier as **DTLS 1.2** records instead, UDP only (section 10.3) |
| `sni` | `www.cloudflare.com` | server name in the synthetic handshake (any `obfs` other than `none`) |
| `shape` | `true` | quantise datagram sizes onto buckets (not with `obfs: none`) |
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
| `desync` | *(off)* | native in-process fake injector — see section 15 |
| `junk` | *(off)* | flow-start cover traffic — see section 15 |
| `hop` | *(off)* | keyed port hopping — see section 15 |
| `split` | *(off)* | IP-fragment the desync fakes — see section 15 |

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

When you do run `tcp`, set `obfs: quic` on both ends: over TCP that turns on the **TLS**
disguise (section 10.1), not QUIC, so the stream looks like an ordinary HTTPS connection rather
than a bare length-prefixed byte stream. It is the single most useful thing you can do to a TCP
carrier that has to survive DPI.

### MTU note
Overhead per packet is ~38 bytes (nonce+tag+seq/pad) plus padding plus the outer
IP/UDP headers (28). Default `mtu=1300` keeps the carrier datagram under 1500 on
standard paths, avoiding fragmentation. Lower it if your path MTU is smaller. The
daemon also sets `tcp_mtu_probing=1` (see below) to survive MTU black holes for inner
TCP.

---

## 🔐 6. Cipher choice — check this before anything else

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

## 📈 7. Throughput: offload, MTU, and knowing where the ceiling is

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

### 7.1 Latency under load — the socket buffer is a queue

Idle ping across the tunnel is set by distance and nothing in this project moves it: on the
reference Iran↔Germany link it is ~79 ms whatever you configure. What *is* tunable, and what
users actually experience as "bad ping", is the delay that appears **while the link is busy**.
That delay is queueing, and the biggest queue is the carrier's own socket buffer.

Measured on the reference link (650 Mbit/s, saturated with 4 TCP streams, pinging across the
tunnel at the same time):

| `rcvbuf` / `sndbuf` | throughput | idle ping | ping under load | jitter | added delay |
|---|---|---|---|---|---|
| 16 MiB | 669 Mbit/s | 79 ms | 189 ms | 55 ms | **+109 ms** |
| 8 MiB | 660 Mbit/s | 80 ms | 142 ms | 35 ms | **+62 ms** |
| **2 MiB** *(default)* | 633 Mbit/s | 80 ms | 97 ms | 9 ms | **+16 ms** |
| 1 MiB | 614 Mbit/s | 80 ms | 91 ms | 6 ms | +11 ms |
| 512 KiB | 595 Mbit/s | 80 ms | 88 ms | 7 ms | +8 ms |

So the old 8–16 MiB default bought a few percent of peak throughput and paid four to seven
times the delay for it. **2 MiB is the default** because it keeps ~95% of the throughput and
turns a link that felt laggy under load into one that does not.

Three things that sound like they should help here, and do not:

* **Asymmetric sizing** (small send buffer, large receive buffer) measured at +70 ms — an
  oversized *receive* buffer is just as much of a backlog when the reader falls behind.
* **The tun interface's qdisc.** `fq`, `fq_codel`, `cake` and `pfifo_fast` all landed within
  noise of each other. The queue that matters is not there.
* **`rate_mbps` pacing.** Shaping to just under line rate made both latency and throughput
  slightly worse. Pacing is for getting under a *policer* (§7), not for latency.

**TCP carriers cannot be fixed this way.** With `transport: tcp` the added delay stayed at
+106…+134 ms no matter how the buffers were set, because the queues that matter are the
kernel's TCP send queues at both ends and TCP-over-TCP retransmission on top of them. This is
the same reason §5 says to prefer UDP: it is not only faster, it is dramatically smoother.

---

## 🐧 8. Network optimization (Ubuntu tuning)

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

## 🛰️ 9. DPI and probe log (`dpi_log`)

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

## 🥷 10. QUIC obfuscation (`obfs: quic`)

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

### 10.1 TLS shaping over TCP (`transport: tcp` + `obfs: quic`)

QUIC is a UDP protocol, so the section-10 disguise is the wrong shape for a TCP carrier — a TCP
stream carrying QUIC short-header bytes matches nothing an inspector expects, and the bare
2-byte length prefix the TCP carrier otherwise uses is a small signature of its own. So over
TCP, `obfs: quic` turns on a **TLS** disguise instead (implemented in `tls.go`), which is the
natural cover for a long-lived flow to port 443:

* the connection **opens with a synthetic TLS 1.3 handshake** — a real ClientHello (the same
  builder the QUIC cover uses, carrying an SNI) from the dialing side, a ServerHello +
  ChangeCipherSpec from the accepting side. A record-level DPI watching from the first byte sees
  an ordinary TLS connection to an ordinary host being established;
* every sealed datagram is then framed as a **TLS 1.3 application-data record**
  (`[0x17][0x03 0x03][len][ciphertext]`). Application data is encrypted, so a high-entropy
  payload is exactly what belongs there — the same "uniform random is the optimum" property as
  the rest of the project, now wearing framing a DPI will not look at twice.

Both ends must agree (`transport: tcp` + `obfs: quic` on both). Nothing here derives TLS keys or
completes a real handshake — the tunnel's own AEAD protects the payload; the records exist to be
looked at, exactly like the QUIC Initials. Same honest caveat as section 10: it strips cheap
signatures, it is not a proof of undetectability, and a classifier that actively completes TLS
would find the handshake goes nowhere.

> **Field note — volumetric throttling.** On the reference Iran↔foreign link this disguise made
> the flow *parse* as TLS perfectly (verified with a wire capture: ClientHello, ServerHello,
> ChangeCipherSpec, then application-data records) and yet the tunnel was throttled to a
> blackhole within ~30 s: a single long-lived, high-rate TLS connection is volumetrically
> anomalous no matter how well-formed it is, and the ISP throttled it on rate alone. The
> project's own DPI observer flagged it (`path.throttle` → `path.blackhole`), and the same link
> ran the UDP/QUIC carrier with zero loss. The lesson is the one section 5 already gives: use
> `tcp` only where UDP is blocked outright, and do not expect a bulk flow over it to survive a
> volumetric policer just because it looks like HTTPS.

### 10.2 QUIC v2 cover (`obfs: quic2`) — when v1 is filtered

`obfs: quic2` is byte-for-byte the same wire format as `quic` for tunnel data. The only
difference is the version the synthetic handshake in section 10 claims: **QUIC v2**
(RFC 9369, `0x6b3343cf`) instead of v1. v2 is a real, deployed version — it changes the
Initial salt, renames the key-derivation labels to `quicv2 …`, and permutes the long-header
packet type codes, all of which this build implements, so the packet is a genuine v2 Initial
rather than a v1 one with the version field overwritten.

It exists because of a measurement. On two independent Iranian carriers — AS25184 (Afranet)
and AS34918 (Pishgaman) — every long-header packet carrying **QUIC v1** was dropped, in both
directions, while the same flow's short-header packets passed untouched:

| cover sent (200 packets each) | delivered |
|---|---|
| QUIC v1 Initial (`0x00000001`) | **0 / 200** |
| QUIC v2 Initial (`0x6b3343cf`) | 200 / 200 |
| DTLS 1.2 ClientHello | 200 / 200 |
| random 1200-byte datagrams | 200 / 200 |

The draft series (`0xff0000xx`) is filtered too; version 0 and GREASE values are not. The
rule is a version blocklist, and it is national rather than per-ISP.

Two consequences worth being explicit about:

* **A tunnel on `obfs: quic` still runs on such a link.** The Initial is cover — it carries no
  tunnel data — so losing it costs no connectivity and nothing in the logs looks wrong. What is
  lost is the entire point of section 10: the flow becomes 1-RTT packets with no handshake in
  front of them, which is the exact anomaly the cover exists to remove. `quic2` is what makes
  the disguise real again on these links.
* **A dropped Initial can take the flow with it.** In controlled tests a single v1 Initial
  blackholed the whole 5-tuple: short-header packets that followed on the same source and
  destination port were dropped too, until the flow went idle long enough to age out. That is
  a tunnel that comes up and then dies for no visible reason — check the cover before blaming
  the carrier.

Verify the cover actually arrives, rather than assuming it does, with the built-in prober
(counters on the receiving end, e.g. `nft … counter` or `tcpdump`):

```bash
aestun probe -mode quic  -target PEER:PORT -count 200   # v1
aestun probe -mode quic2 -target PEER:PORT -count 200   # v2
aestun probe -mode dtls  -target PEER:PORT -count 200   # DTLS ClientHello
```

### 10.3 DTLS shaping (`obfs: dtls`) — a disguise that is not QUIC

A version blocklist is cheap to extend. `obfs: dtls` is the answer to that: not a different
QUIC, but a different protocol. Each datagram becomes a **DTLS 1.2 application-data record**,
and the flow opens with a plaintext **ClientHello** that a censor's parser can read straight
off the wire (unlike QUIC's, which it must decrypt first).

```
[1 type=0x17][2 version=0xfefd][2 epoch][6 sequence][2 length][ciphertext][16 tag]
```

The record header is 13 bytes — exactly the size the QUIC short-header format already uses —
so the disguise costs nothing extra on the wire. As in real DTLS with an AEAD cipher
(RFC 6347 §4.1.2.1, RFC 5288) the nonce is a salt derived from the pre-shared key followed by
the record's own epoch and sequence number, so the header *is* nonce material rather than
something prepended to it. The header stays in the clear, because that is what a real DTLS
record looks like: there is no header protection to imitate, and masking it would be the one
thing that stops the record parsing.

Why DTLS specifically: it is what WebRTC uses for every browser call and what OpenVPN uses in
its UDP mode, so it is close to unblockable wholesale — and the measurement above confirms it
passes these links at the full offered rate. Both ends must be set to `dtls` (the formats are
not negotiated), and it is **UDP only**; over TCP the coherent disguise is TLS, which is what
`obfs: quic` already gives you (section 10.1).

Same honest caveat as section 10. This raises the cost of classification; it is not proof of
undetectability, and nothing here completes a real DTLS handshake — a prober that tries would
find the handshake goes nowhere.

## 🧩 11. zapret module (optional DPI bypass)

[bol-van/zapret](https://github.com/bol-van/zapret) is a DPI-circumvention toolkit.
This project can layer its `nfqws` desync on the tunnel's **carrier** UDP packets so a
censoring ISP has a harder time recognizing or throttling them. From `aestun.sh` → `z`:

1. **install** — clones zapret and **builds `nfqws` from source** (upstream no longer ships
   prebuilt binaries in the git tree). Installs the build deps automatically
   (`build-essential`, `libnetfilter-queue-dev`, `libnfnetlink-dev`, `libmnl-dev`,
   `libcap-dev`, `zlib1g-dev`). Result: `/opt/zapret/nfq/nfqws`.
2. **enable** — adds `iptables` NFQUEUE rules and runs `nfqws` as a service (`aestun-zapret`).
3. **status / disable / remove**.

### 🌐 Protocol coverage (TCP + UDP + any protocol)

The NFQUEUE rule now queues **both `tcp` and `udp`** on the carrier port, and `nfqws` runs two
profiles so it acts on whatever the carrier is — and keeps working if you switch transport:

* **TCP on the carrier port → `multisplit`** (fragments the TLS-record stream; the peer
  reassembles it transparently, on-path DPI sees a split connection start);
* **everything else (the UDP carrier, and any other protocol) → `fake` injection** with
  `--dpi-desync-any-protocol=1`, so it desyncs the carrier's opaque payload regardless of L7.

Tune it for your network with zapret's own `blockcheck.sh`. If traffic breaks, disable the
module — the tunnel itself does not depend on it.

> ### 🤔 zapret (external) vs. the native `desync` module (§15) — and why the native one is on by default
>
> §15 reimplements the useful half of `nfqws` **inside** aestun — no NFQUEUE, no iptables rule,
> no second process that can wedge — and it reuses the peer hop count the tunnel already learned.
> For a tunnel whose carrier you own, that in-process version is the better default, so
> **`desync` + `split` + `junk` ship enabled by default**: that *is* the "DPI bypass always on"
> layer, running in the daemon itself.
>
> The external zapret stays available because it is battle-tested and tunable with
> `blockcheck.sh`. It is **not** force-enabled by default on purpose: it needs `nfqws` **built**
> (network + compiler + kernel headers), it can wedge on its raw-socket send buffer, and it
> would **double-inject** if run alongside the native `desync`. **Run one or the other, not
> both.** If you prefer the external layer, install it from menu `z` and turn the native
> `desync` off in menu `x`.

---

## 🛠️ 12. Manual deployment (without the wizard)

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

## 🩺 13. Troubleshooting

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
* **High latency / slow, especially on port 443** → try moving the carrier to a **high,
  less-watched port** (e.g. `2087`). On the reference link, moving the pair off `:443` cut the
  tunnel RTT **from ~82 ms to ~18 ms** and escaped a throttle in one step: the DPI monitors and
  reroutes `:443` through an inspection path (~64 ms of added latency) but does not watch high
  ports (measured — the encrypted in-tunnel probe confirmed it; see §17 finding 4). Do not park
  the carrier on 443 just because it "looks like HTTPS." Port hopping (§15.3) automates this.
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

## 🏗️ 14. Building & testing

```bash
go test ./...                 # protocol/crypto/observer unit tests (run natively, any OS)
go test -bench . -benchtime 2s   # per-packet cost and allocation counts on THIS cpu
./aestun.sh build amd64       # -> aestun-linux-amd64
./aestun.sh build arm64       # -> aestun-linux-arm64
./aestun.sh build amd64 pprof # -> aestun-linux-amd64-pprof, adds net/http/pprof
```

### The `vendor/` directory (offline builds)

The two dependencies (`golang.org/x/crypto`, `golang.org/x/sys`) are committed under `vendor/`,
so **the build works with no network**. What happens if it is missing:

* **Prebuilt binary** (`aestun-linux-amd64`/`arm64`) — needs nothing. It is a static binary with
  no dependencies and no Go; `vendor/` is irrelevant to it. The installer prefers it.
* **Building from source, `vendor/` present** — builds offline from the vendored copies.
* **Building from source, `vendor/` absent, with internet** — Go **downloads** the two modules
  from the proxy automatically (verified against `go.sum`) and builds a correct binary. So yes:
  a source install fetches them for you when the network is there. The installer prints a note
  when it notices `vendor/` is gone.
* **Building from source, `vendor/` absent, offline** — fails (`module lookup disabled`). Either
  ship the prebuilt binary or restore the tree once, on any machine with internet:
  `( cd aestun-final && go mod vendor )`.

---

## 🛡️ 15. Native anti-DPI hardening (in-process, no zapret)

Four optional layers, all built into the daemon, all **off by default**, each toggled from
`sudo ./aestun.sh` → `x` or by editing the config. They exist because aestun owns *both* ends
of its carrier, which lets it do things an external tool bolted onto someone else's flow
cannot — and do the things it *can* do without a second process, an iptables rule, or a
userspace round-trip per packet. Enable only what your path needs; a wrong option is, at best,
wasted packets. Turn on `dpi_log` (section 9) alongside them so you can see whether they help.

Why these are not just "zapret in Go": zapret's `nfqws` is built for the hard case — the far
end is a website it does not control, so every fake it injects has to be crafted so the real
server ignores it, which is what forces it through NFQUEUE. aestun made the opposite bet: it
controls the peer, the peer already discards stray handshake packets safely, and the tunnel
already **measured** the peer's hop count (section 9's TTL learning). So the same attacks cost
far less machinery here.

### 15.1 `desync` — native fake injector (the `nfqws` idea, in-process)

At flow start the daemon opens a raw socket and sprays a few genuine-looking QUIC Initials —
the same real, decryptable ClientHello the obfs layer builds, with a plausible SNI — sharing
the carrier's exact 5-tuple, at a TTL tuned to **die a hop or two before the peer**. A stateful
DPI watching the flow open sees what looks like an ordinary QUIC connection to a real CDN; the
fakes never reach the peer, so they poison the classifier's model of the flow without costing
the tunnel anything. Even a fake that *does* arrive is harmless — the receive loop already
drops stray long-header packets.

The TTL is where owning both ends pays off. `autottl` reads the peer hop count the tunnel
already learned (`peer_ttl` in the monitor), so the fake dies exactly one hop short instead of
being guessed. `badsum` (off) additionally corrupts the fake's UDP checksum so the peer kernel
drops it — rarely needed here, and some NATs drop bad-checksum packets outright, so leave it
off unless you have measured that it helps.

| Field | Default | Meaning |
|---|---|---|
| `enabled` | `false` | master switch |
| `repeats` | `4` | fakes per burst |
| `autottl` | `true` | derive the fake TTL from the learned peer hop count |
| `delta` | `-1` | hops before the peer the fake should die |
| `min_ttl`/`max_ttl` | `3`/`20` | autottl clamp |
| `ttl` | `0` | fixed TTL when `autottl` is off (0 → fallback 8) |
| `badsum` | `false` | corrupt the fake's UDP checksum |
| `every_sec` | `0` | periodic re-burst; 0 = only at start |

Needs `CAP_NET_RAW` (the systemd unit grants it). **IPv4 only** — a v6 peer disables it with a
log line. This is the in-process replacement for the section 11 zapret module; run one, not
both.

### 15.2 `junk` — flow-start cover traffic

A burst of cover packets when the flow opens, so the *beginning* of the connection carries no
fixed packet-count or inter-packet-timing signature — the AmneziaWG "junk" idea. The catch
with literal random junk is that the peer would log it as a scan; so the junk here is real
sealed keepalives — high-entropy and indistinguishable from tunnel data on the wire (they *are*
tunnel data), authenticating cleanly at the peer and decrypting to an empty payload the receive
loop already discards. Count and timing are randomised; sizes vary from the padding the sealer
already applies.

| Field | Default | Meaning |
|---|---|---|
| `enabled` | `false` | master switch |
| `count` | `8` | cover packets at flow start |
| `min_ms`/`max_ms` | `5`/`50` | random gap between them |

### 15.3 `hop` — keyed synchronised port hopping

The reference deployment hit exactly this wall (section 13): an ISP blocked the precise
source/destination **port pair** while the same traffic from any other port sailed through.
Port hopping turns that one-time manual fix into a continuous automatic one. Both ends derive
the current port from the pre-shared key and the clock — the same handshake-free mechanism the
epoch keys use — and step through a small agreed set on a timer. There is nothing for a 5-tuple
block to hold onto: by the time a pair is identified, the flow has moved. It also erases the
fixed-port fingerprint a long-lived flow otherwise carries.

Every port in the set is bound for the whole life of the process on both ends, so a datagram
that crosses an epoch boundary early or late still lands on a bound socket — no rebind, no
handover gap, no race. Peers are matched by IP alone while hopping, so the rotation does not
trip the roam detector.

| Field | Default | Meaning |
|---|---|---|
| `enabled` | `false` | master switch |
| `ports` | `[443, 8443, 2053, 2083, 2087, 2096]` | the set; **identical and in the same order on both ends** |
| `interval` | `30` | seconds per hop |

**Two real costs, stated plainly.** It runs one socket per port; the receive side uses UDP GRO
(one recvmsg drains many datagrams) but the send side **forgoes UDP segmentation offload**, so
peak throughput is lower and CPU per byte is higher — measured on a live no-AES-NI endpoint,
foreign-side CPU rose from ~62% to ~82% at the same ~150 Mbit/s. And you must **open the whole
port set in the firewall on both ends**. It is insurance against blocking, not a throughput
feature. (The port list must match on both servers because the schedule indexes into it; the
installer writes both.)

**If a port cannot be bound, the daemon exits with a clear error naming the port** — it does
*not* fall back to a single socket, because one end quietly reverting to one port while the peer
keeps hopping would silently carry no traffic while both services still look "active" (the worst
failure). A field test hit exactly this: another proxy (`xray`) held UDP 8443 on one box. The
fix is to free the port or drop it from `hop.ports` on **both** ends. Pick a set whose members
are free on both servers *and* reachable through the cloud firewall (test a candidate with a
quick UDP send + `tcpdump` before committing to it).

### 15.4 `split` — IP-fragment the fakes

The split that is safe to do on an opaque encrypted carrier. Splitting *real* carrier datagrams
would scramble bytes a DPI already cannot read (the payload is AEAD ciphertext) while adding a
reassembly protocol and head-of-line risk — cost with no benefit, so this module never touches
real traffic. Instead it fragments the disposable `desync` fakes at the IP layer, the way
zapret's `ipfrag2` does: a DPI that does not reassemble fragments sees only a truncated first
fragment of the cover handshake, while one that does sees the same legitimate Initial. Either
way the real flow is untouched. Only meaningful with `desync` on.

| Field | Default | Meaning |
|---|---|---|
| `enabled` | `false` | master switch |
| `frag_pos` | `24` | fragment position, bytes from the transport header (multiple of 8) |

### 🔁 15.5 `tcp_rotate` — rotate the TCP connection to dodge volumetric throttling

Only relevant with `transport: tcp`. The field test (§17) found that a TCP+TLS carrier, however
perfectly it parses as HTTPS on the wire, can be **volumetrically throttled** — a single
long-lived, high-rate TLS connection is anomalous on rate and lifetime alone, and no disguise
changes its rate. This attacks the *lifetime* instead: the dialer opens a fresh TCP connection
(a new 5-tuple, a new source port) and switches the carrier onto it **before** retiring the old
one ("make before break"), on a jittered timer. No single flow then lives long enough, or
carries enough bytes, to cross whatever the throttle watches for. It is port hopping's idea,
applied to a stream.

| Field | Default | Meaning |
|---|---|---|
| `enabled` | `false` | master switch (transport `tcp` only) |
| `interval_sec` | `15` | seconds a connection lives before it is rotated |

**Honest result from the live test.** The mechanism works cleanly — a local back-to-back test
held **152 Mbit/s across rotations with 0 % ping loss** (make-before-break causes only a tiny
per-rotation blip the inner TCP absorbs). On the *reference censored link*, though, rotation did
**not** lift the cap: with rotation on and off the TCP carrier sat at ~20 Mbit/s either way,
because that link's limiter is not keyed on the per-connection 5-tuple (a port change did not
help either). It is kept because it is correct and cheap, and *does* help where throttling is
per-flow — but on this link the answer stayed **UDP**. A single TCP stream over a lossy ~80 ms
path is also inherently slow (congestion control), independent of any DPI.

### 🧭 Which to reach for

* **Flow gets classified/throttled as it opens** → `desync` (+ `junk`). Start here; it is the
  direct replacement for the zapret module and the cheapest to run.
* **A specific port pair got blocked, or you want to stop being a fixed-port target** → `hop`.
  The only one of the four that changes throughput, so weigh it.
* **`split`** is a small extra on top of `desync`, worth trying only if a plain `desync` burst
  did not move the needle.

None of these is a proof of undetectability — same honesty as section 10. They raise the cost
of detection. Measure with `dpi_log` and an `iperf3` before/after (section 7); keep what helps.

---

## 🧪 16. Auto-test — sweep every method/protocol and apply the best

`sudo ./aestun.sh` → **`t`**. Instead of guessing which methods your path needs, this sweeps a
set of variants **on the live tunnel**, measures each, and applies the winner to **both** ends.

It runs from the **role `a`** (Iran/inside) server and drives the sweep, so it needs to
reconfigure the far end too: it asks once for the **foreign server's SSH password**, holds it in
a `chmod 600` temp file for `sshpass`, and **shreds it** when done. Nothing is written to disk in
clear and nothing persists.

For each variant it: merges the overrides onto **both** configs, restarts both services, waits
for the tunnel to come up (rx climbing), then measures **packet loss + latency** (a light
25-ping burst) and, if `iperf3` is present on both ends, a short **throughput** sample. The
variants swept:

| Variant | What it turns on |
|---|---|
| `baseline` | plain UDP + QUIC, no extensions |
| `desync+split+junk` | the recommended native anti-DPI trio |
| `port-hop` | UDP port hopping over `[443,2053,2083,2087,2096]` |
| `tcp+tls` | TCP carrier with the TLS disguise |
| `tcp+tls+rotate` | TCP + TLS + connection rotation (§15.5) |

At the end it prints a comparison table, names the best (lowest loss, then highest throughput),
and — on your confirm — **applies it to both servers** and shows exactly what the tunnel is now
running. Decline, and it reverts both ends to the pre-test config.

```
VARIANT                 LOSS%    PING_ms   Mbit/s
-------------------------------------------------------
baseline                 0.0      82.3      151
desync+split+junk        0.0      82.1      150
port-hop                 0.0      86.1      154
tcp+tls                 24.8      23.1       —
tcp+tls+rotate          20.1      —          —
```

> ⚠️ It **briefly interrupts the tunnel** on every variant (~40 s each) and pushes test
> traffic — run it in a maintenance window, not at peak, and never twice in parallel. The build
> ships with this feature; the sweep only runs when you pick it and confirm.

---

## 📋 17. Field-test log (measured under real load)

### 📊 17.0 Full matrix — every transport × every disguise × every module

Measured on the reference link (🇮🇷 Pishgaman AS34918 ↔ 🌍 Leaseweb Germany, ~79 ms, both ends
`chacha20-poly1305`), each variant reconfigured on both servers and restarted, then measured
with `iperf3` (4 streams, each direction) and 60 pings across the tunnel. Buffers at 2 MiB.

**Transports and disguises** — all eight combinations came up and carried traffic:

| Variant | ⬇ down | ⬆ up | RTT | jitter | loss |
|---|---|---|---|---|---|
| `udp` + `dtls` | **661** Mbit/s | 704 | 79.7 ms | 1.8 ms | 0 % |
| `udp` + `quic2` | **649** Mbit/s | 691 | 79.6 ms | 1.5 ms | 0 % |
| `udp` + `quic` | 620 Mbit/s | 675 | 79.8 ms | 1.9 ms | 0 % |
| `udp` + `none` | 358 Mbit/s | 488 | 79.8 ms | 1.8 ms | 0 % |
| `tcp` + `quic` (TLS) | 205 Mbit/s | 259 | 83.3 ms | 6.0 ms | 0 % |
| `tcp` + `none` | 197 Mbit/s | 227 | 76.0 ms | 2.3 ms | 0 % |
| `tcp` + `quic2` (TLS) | 197 Mbit/s | 223 | 74.9 ms | 1.8 ms | 0 % |
| `tcp` + `dtls` | rejected at startup — DTLS is a UDP record format; the error says to use `quic` over TCP |

Two things worth noticing. **UDP is ~3× faster than TCP** here, which is why §5 tells you to
prefer it. And **`obfs: none` is the slowest UDP option**, not the fastest — the disguise is
not costing you speed, so there is no throughput argument for running without one.

**Anti-DPI modules**, each on top of `udp` + `quic2`:

| Module | ⬇ down | ⬆ up | RTT | notes |
|---|---|---|---|---|
| *(none)* | 649 | 691 | 79.6 ms | baseline |
| `desync` | 621 | 704 | 79.7 ms | ~4 % cost |
| `junk` | 638 | 657 | 79.9 ms | negligible cost |
| `desync` + `split` | 632 | 688 | 79.5 ms | negligible over desync alone |
| `desync` + `split` + `junk` | 638 | 684 | 80.0 ms | the recommended hardening set |
| `hop` | 402 | 482 | 80.7 ms | **−38 %** — multi-socket forgoes kernel offload |
| `tcp_rotate` (on `tcp`+`quic`) | 237 | 223 | 78.7 ms | works; jitter rises with each rotation |

The hardening set costs about 2 % of throughput, so leaving it on is cheap. **`hop` is the one
expensive module** — turn it on only against an actual 5-tuple block.

**Handshake cover delivery**, 200 packets of each sent at the peer and counted on arrival:

| Cover | Delivered |
|---|---|
| QUIC v1 Initial (`obfs: quic`) | **0 / 200** ❌ |
| QUIC v2 Initial (`obfs: quic2`) | 200 / 200 ✅ |
| DTLS ClientHello (`obfs: dtls`) | 200 / 200 ✅ |
| random datagrams (control) | 200 / 200 ✅ |

This is the measurement behind §10.2, and it is the single most important number in this
document: **on `obfs: quic` the tunnel works and its disguise does not.**

---

The results below were captured on the **reference deployment** — 🇮🇷 Iran (role `a`, AES-NI) ↔
🌍 foreign (role `b`, QEMU **no** AES-NI → both on `chacha20-poly1305`), a real ~80 ms censored
link — **while the tunnel was carrying live user traffic**. Every variant restarted both ends,
captured the wire from flow-open (`tcpdump`), ran `iperf3` (TCP + UDP), pinged over the tunnel,
and sampled `pidstat`/`mpstat` on both servers.

### ✅ Every method verified on the wire (auth_fail = 0 throughout)

| Method | Evidence on the wire |
|---|---|
| 🎭 `desync` | long-header QUIC fakes on the carrier port at **TTL 8/9** (autottl from the learned peer TTL 54 → die ~1 hop before the peer) |
| ✂️ `split` | **24 IP fragments** = 12 fakes × 2, low-TTL — only the disposable fakes fragmented, real traffic intact |
| 🫧 `junk` | flow-start cover keepalives (blend into data by design; logs confirm the burst) |
| 🔀 `hop` | carrier rotating across dst ports `2087 / 2096 / 2083 / 443` |
| 🧣 `tcp+tls` | stream is full **TLS records** — handshake, application-data, ChangeCipherSpec — reads as HTTPS |

### 📊 Throughput / CPU per variant (both ends, under load)

| Variant | TCP Mbit/s | UDP loss @250 | iran CPU | foreign CPU | tunnel RTT |
|---|---|---|---|---|---|
| baseline (udp) | 152.8 | 33 % | 36.6 % | 61.6 % | 83 ms |
| desync | 150.5 | 36 % | 37.7 % | 64.6 % | 82 ms |
| desync + split | 150.9 | 38 % | 36.2 % | 64.1 % | 83 ms |
| junk | 153.6 | 37 % | 35.9 % | 63.6 % | 82 ms |
| port-hop | 154.5 | 33 % | 51.8 % | 83.8 % | 86 ms |
| all-udp (everything) | 153.0 | 34 % | 50.5 % | 81.5 % | 87 ms |
| tcp + tls | 151.5* | 25 % | 37.2 % | 58.8 % | * throttled |

*CPU is % of one core; foreign has no AES-NI, hence its higher chacha cost.*

### 🔎 What the logs revealed, and what was fixed

1. **🐛 (fixed in code) port-hop silent fallback.** With `hop` on, one box could not bind a port
   another proxy held; the carrier silently fell back to a single socket while the peer kept
   hopping → dead-but-"active" tunnel. Now it **fails loudly** naming the port, never falls back.
2. **⚙️ (characterised) port-hop CPU.** Multi-socket forgoes send-side offload; foreign went
   ~62 % → ~82 %. GRO was added on the hop sockets to batch the heavy-receive end. `hop` stays
   **off by default**; enable only against a 5-tuple block.
3. **🌐 (network, not code) TCP+TLS is volumetrically throttled.** The disguise was perfect on
   the wire, yet the flow was throttled to a blackhole within ~30 s (`path.throttle` →
   `path.blackhole`, TCP send-queue stuck). The identical code round-trips perfectly on
   localhost; UDP on the same link had **zero** loss. **UDP is the right transport here.** The
   project's own DPI observer detected and classified it correctly — a nice validation of §9.

4. **📉 Port 443 is on a DPI inspection detour — moving off it cut latency 4.5×.** When a burst
   of load got the `:443` carrier throttled, changing the port pair (to `:2087`) not only
   escaped the block but dropped the tunnel RTT **from ~82 ms to ~18 ms**. The in-tunnel
   *encrypted* probe (§7) — which only the real peer can answer — confirmed the same ~21 ms, so
   it is a genuine path difference, not a measurement artifact. The reading is unambiguous:
   **the DPI actively monitors/reroutes port 443 through an inspection path (~64 ms of added
   latency), and does not watch `:2087`.** The lesson is concrete — **do not run the carrier on
   443 just because it "looks like HTTPS"**: a less-watched high port can be both faster and
   less blocked. And it is the clearest argument for **port hopping (§15.3)**: keep moving so no
   single port stays under the DPI's lens long enough to be inspected, throttled, or blocked.

### 🏁 Final production config (applied to both ends)

```
transport = udp · obfs = quic · cipher = chacha20-poly1305
listen/peer on a HIGH, unwatched port (e.g. 2087) — NOT 443 (443 rides a DPI detour, +64ms)
desync{repeats:6, autottl} + split{frag_pos:24} + junk{count:8}   ← enabled
hop = off   (CPU headroom; enable it if your chosen port later gets blocked)
Result on the live link: 0% loss · RTT ~18 ms (was ~82 ms on 443) · foreign +3–4 % CPU.
```

> The raw per-run logs (`pidstat`/`mpstat` for both ends, `tcpdump` captures, and the full report)
> are saved on the Iran server under `/root/aestun-fieldtest-<timestamp>/`.
