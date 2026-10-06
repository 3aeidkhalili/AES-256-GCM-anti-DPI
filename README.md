# aestun — an anti-DPI tunnel between two servers

`Linux` · `AES-256-GCM / ChaCha20-Poly1305` · `QUIC / TLS / DTLS wire disguise` · `single static Go binary` · `built-in DPI observer` · `allocation-free packet path`

aestun joins two servers with an encrypted IP tunnel and shapes the traffic between them so
that a Deep Packet Inspection box cannot classify it. It was built for, and is measured on, an
Iran ↔ Europe link.

It is one static binary with no runtime dependencies, one shell script that installs and
manages it, and a second script that runs four carriers at once and bonds them together.

> **فارسی:** the full Persian guide is in **[README.fa.md](README.fa.md)**.

---

## Table of contents

1. [What it is](#1-what-it-is)
2. [How it works](#2-how-it-works)
3. [Installation](#3-installation)
4. [Configuration reference](#4-configuration-reference)
5. [Wire disguises (`obfs`)](#5-wire-disguises-obfs)
6. [Carriers (`transport`)](#6-carriers-transport)
7. [Multi-protocol carrier — failover and multipath](#7-multi-protocol-carrier--failover-and-multipath)
8. [Anti-DPI modules](#8-anti-dpi-modules)
9. [Monitoring and observability](#9-monitoring-and-observability)
10. [Performance and tuning](#10-performance-and-tuning)
11. [Management menu](#11-management-menu)
12. [Troubleshooting](#12-troubleshooting)
13. [Building and testing](#13-building-and-testing)
14. [Security model and honest limits](#14-security-model-and-honest-limits)
15. [Measurement appendix](#15-measurement-appendix)
16. [File map](#16-file-map)
17. [Multi-location — one foreign server, many Iran servers](#17-multi-location--one-foreign-server-many-iran-servers)

---

## 1. What it is

Two servers, one encrypted tunnel. Each end gets a TUN interface with a private address, and
anything routed at the peer's address crosses the tunnel. From the operating system's point of
view the two machines share a small LAN.

```
   users  ──▶  server A (Iran)  ══ encrypted carrier ══▶  server B (abroad)  ──▶  internet
                role "a"           looks like QUIC             role "b"
              10.8.0.1/24                                    10.8.0.2/24
```

The design goal is not only confidentiality — that part is easy — but that the *shape* of the
traffic gives nothing away. Three things get tunnels classified in practice, and each has an
answer here:

| What a classifier notices | What aestun does |
|---|---|
| High entropy from byte 0, which no real protocol produces | Wraps every datagram in a header a QUIC, DTLS or TLS parser accepts (§5) |
| A bimodal size distribution — full-MTU bulk plus a cluster of tiny ACKs | Pads small datagrams onto size buckets, inside the encryption (§5) |
| A perfectly periodic keepalive, which is a clean clock signature | Jitters the keepalive by ±40 % |

Three values **must be identical on both servers**: `key`, `cipher`, and `obfs` — four when the
UDP carrier runs `reverse` (§6.4). There is no handshake to negotiate them in — that is
deliberate, because a handshake is a signature. Everything else is per-server.

### Recommended defaults

| Question | Answer | Why |
|---|---|---|
| `transport` | `udp` | ~3× faster than TCP on the reference link and far better latency (§6) |
| `obfs` | `quic2` | Same wire format as `quic`, but its handshake cover actually survives Iranian carriers (§5.2) |
| `cipher` | `aes-gcm` if **both** CPUs have AES-NI, else `chacha20-poly1305` | Without AES-NI, AES-GCM runs in software at ~1/6 the speed (§10.1) |
| socket buffers | leave at the default | A buffer is a queue; oversizing it trades latency for throughput you may not need (§10.3) |
| anti-DPI modules | leave the defaults | All off except `udp_rotate`, which is on because it prevents an observed production failure (§8.5). Turn the rest on against a problem you have actually seen, not pre-emptively (§8) |

---

## 2. How it works

### The packet path

```
tun0 ──read──▶ seal (AEAD + padding + disguise header) ──▶ carrier socket ──▶ network
network ──▶ carrier socket ──▶ open (unmask, decrypt, replay-check) ──write──▶ tun0
```

Both directions are written so the steady state **allocates nothing**. Each goroutine owns a
`sealer` or `opener` holding its scratch buffers and a buffered CSPRNG; the AEAD for the
current key epoch is reached through a lock-free atomic; randomness is drawn a page at a time
instead of one `getrandom` syscall per packet. On a link doing thousands of packets a second
those three things cost more than the cipher itself.

### Wire format

Without a disguise (`obfs: none`) the datagram is a bare random nonce and ciphertext:

```
[ 12-byte random nonce ][ ciphertext ][ 16-byte AEAD tag ]

plaintext sealed inside:
[ 8-byte sequence ][ 2-byte pad length ][ inner IP packet ][ random padding ]
```

With a disguise the 13-byte header *is* the nonce rather than being prepended to one, so the
whole disguise costs a single byte over the bare format:

| Mode | Header (13 bytes) | Nonce built from |
|---|---|---|
| `quic` / `quic2` | `[flags][8-byte connection ID][4-byte packet number]` | connection ID ‖ packet number |
| `dtls` | `[0x17][0xfefd][2-byte epoch][6-byte sequence][2-byte length]` | 4-byte derived salt ‖ epoch ‖ sequence |

The sequence number (for anti-replay) and the padding live *inside* the encryption, so neither
appears on the wire and size correlation is broken. There is no handshake and no key exchange:
keys come from a pre-shared secret.

### Keys

HKDF-SHA256 splits the pre-shared key into a separate key per direction, so the two directions
can never reuse a nonce against each other. With `rekey_interval` set, both ends additionally
derive an epoch key from the wall clock — no exchange, no handshake, and a receiver tries the
current, previous and next epoch so clock skew of up to one interval is tolerated.

### Anti-replay

A 4096-entry sliding window over the inner sequence number. The sequence starts from the
current time in microseconds rather than zero, so a restart cannot collide with the window the
peer still holds.

---

## 3. Installation

On **each** server, copy the directory over and run:

```bash
chmod +x aestun.sh
sudo ./aestun.sh install
```

The installer asks for everything, writes `/etc/aestun/config.json`, installs a systemd unit,
and applies network tuning. Choose the Iran side as role `a` (it opens the conversation) and
the foreign side as role `b` — under reverse UDP (§6.4) the foreign side opens it instead, and
the roles stay as they are. Generate the key on the first server and paste the same one on
the second.

It **compiles from the sources in the directory** whenever a Go toolchain is available or can
be fetched, and only falls back to the shipped prebuilt binary otherwise — saying so out loud
and verifying it against `SHA256SUMS` first. Nothing ties a checked-in binary to the source
beside it, so preferring the source is what keeps "update both servers" meaning the same thing
on both.

Verify with `sudo ./aestun.sh` → *4) Connectivity test*.

To run four carriers at once instead of one, see §7.

---

## 4. Configuration reference

`/etc/aestun/config.json`, mode `0600`. Every field is optional except `role` and `key`.

### Core

| Field | Default | Meaning |
|---|---|---|
| `role` | — | `a` or `b`; **must differ** on the two servers |
| `key` | — | base64 of 32 bytes; **identical** on both (`aestun keygen`) |
| `cipher` | `aes-gcm` | `aes-gcm` or `chacha20-poly1305`; **identical** on both (§10.1) |
| `transport` | `udp` | `udp`, `tcp`, `icmp` or `ws` (§6) |
| `reverse` | `false` | UDP and ws: role `b` (foreign) opens the flow and role `a` (Iran) only answers; **identical** on both (§6.4) |
| `obfs` | `none` | `none`, `quic`, `quic2` or `dtls`; **identical** on both (§5) |
| `listen` | `0.0.0.0:51820` | local carrier address |
| `peer` | — | the other server's `host:port`; learned from traffic if empty |
| `sni` | `www.cloudflare.com` | server name inside the synthetic handshake |
| `shape` | `true` | quantise datagram sizes onto buckets (only with a disguise) |

### Interface

| Field | Default | Meaning |
|---|---|---|
| `tun_name` | `tun0` | interface name |
| `local_ip` | — | this server's tunnel address as CIDR, e.g. `10.8.0.1/24` |
| `peer_ip` | — | the peer's tunnel address (used by the ping test) |
| `mtu` | `1300` | clamped to 576…65279; **must match** across multipath carriers |
| `txqueuelen` | `1000` | negative leaves the kernel default alone |
| `manage_ip` | `true` | let the daemon run the `ip` commands itself |

### Crypto and framing

| Field | Default | Meaning |
|---|---|---|
| `pad_max` | `64` | max random padding bytes per packet; explicit `0` disables |
| `rekey_interval` | `0` | key-rotation seconds; `0` = static key |
| `keepalive` | `25` | keepalive seconds, jittered ±40 %; explicit `0` disables |

### Performance

| Field | Default | Meaning |
|---|---|---|
| `rcvbuf` | `2097152` | carrier receive buffer. A queue — see §10.3 before raising it |
| `sndbuf` | `2097152` | carrier send buffer. Oversizing this is pure bufferbloat |
| `offload` | `true` | kernel UDP segmentation (GSO) and coalescing (GRO) |
| `rate_mbps` | `0` | shape the carrier to this rate; `0` = unlimited (§10.4) |
| `gc_percent` | `100` | Go GC target; the packet path allocates nothing, so raising it only inflates RSS |
| `mem_limit` | `67108864` | soft heap ceiling in bytes |
| `max_procs` | `0` | `GOMAXPROCS` override; `0` leaves it to the runtime |
| `pprof_addr` | — | e.g. `127.0.0.1:6060`; only in a binary built with `-tags pprof` |
| `stats_path` | `/run/aestun/stats.json` | JSON stats for the dashboard; empty disables |

### `dpi_log` — the DPI observer (§9)

| Field | Default | Meaning |
|---|---|---|
| `enabled` | `true` | master switch |
| `path` | `/var/log/aestun/dpi.jsonl` | JSONL output |
| `max_size_mb` / `keep` | `16` / `2` | rotation size and generations |
| `max_per_min` | `240` | event rate limit, so a probe flood cannot fill the disk |
| `flush_sec` | `60` | how often per-source aggregates are emitted |
| `health_sec` | `300` | flow-health heartbeat; negative disables |
| `probe` / `probe_sec` | `true` / `20` | in-tunnel round-trip probes |
| `silence_sec` | `60` | silence before a blackhole is declared |
| `max_sources` | `2048` | per-source table cap |
| `sample_bytes` | `16` | header bytes recorded from a stranger |
| `stdout` | `true` | also write non-routine events to the journal |

Every numeric field here is clamped to a sane value on load. A negative one used to be fatal:
`flush_sec` and `probe_sec` become `time.NewTicker` arguments, which panics on a non-positive
duration, and `sample_bytes` becomes a slice bound on the receive path — reachable from an
unauthenticated packet.

### Anti-DPI module blocks (§8)

`desync`, `junk`, `hop`, `split`, `tcp_rotate` — all `{"enabled": false}` by default.
`udp_rotate` is the exception: `{"enabled": true, "interval_sec": 900}`, because it prevents a
failure that was observed in production rather than one that might occur (§8.5).

### `icmp` — the ICMP carrier (§6.3)

Read this block in two halves. `readers`, `batch` and `kernel_filter` are local performance
choices that change nothing on the wire, so the two ends may differ. `id`, `id_pool`,
`id_rotate_sec` and `mimic_ping` change what the packets look like and are **not negotiated** —
they must be identical on both servers or every packet fails to authenticate.

| Field | Default | Meaning |
|---|---|---|
| `readers` | `0` | receive goroutines; `0` = one per core, capped at 8 |
| `batch` | `32` | messages per `sendmmsg`/`recvmmsg`; `1` disables batching |
| `kernel_filter` | `true` | attach the BPF filter to the raw socket |
| `suppress_replies` | `true` | install the echo-reply drop rule |
| `id` | `0` | fixed echo identifier; `0` derives it from the key |
| `id_pool` | `1` | identifiers to rotate through, max 8 |
| `id_rotate_sec` | `60` | seconds per identifier epoch |
| `mimic_ping` | `false` | prepend the 16-byte timeval `ping(8)` sends |

### `ws` — the WebSocket carrier (§6.5)

One block serves both servers: each end reads the fields that apply to it.

| Field | Default | Meaning |
|---|---|---|
| `url` | — | dialing end: `wss://domain[:port][/path]` (or `ws://` on Cloudflare's plain-HTTP ports) |
| `connect` | — | dialing end: dial these `ip[:port]` (comma-separated, tried in turn from the last that worked) instead of resolving the URL host; SNI/Host unchanged |
| `host` | URL host | `Host` header |
| `sni` | URL host | TLS server name (separate from the top-level `sni`, which is cover for `obfs`) |
| `insecure` | `false` | skip certificate checks — only for dialling a self-signed origin directly |
| `path` | derived from the key | request path; a path in `url` overrides it; empty or `/` derives it |
| `rotate_sec` | `0` | replace the connection make-before-break this often, jittered; min 10 |
| `idle_sec` | 3 × `keepalive`, ≥ 45 | redial when nothing authenticated arrives for this long; negative = off |
| `user_agent` | desktop Chrome | the upgrade request's `User-Agent` |
| `cert` / `cert_key` | self-signed | listening end: PEM certificate and key (Cloudflare "Full (strict)") |

---

## 5. Wire disguises (`obfs`)

The payload is already AEAD ciphertext, so there is nothing to gain against *content*
inspection — uniform random is the optimum and no new framing improves on it. What is still
visible is the datagram's shape, and that is what these modes address.

| Mode | Carrier | What it looks like |
|---|---|---|
| `none` | any | high-entropy datagrams with no structure |
| `quic` | UDP | QUIC v1 short-header packets, opened by a real QUIC v1 Initial |
| `quic2` | UDP | identical wire format for data; the handshake cover claims **QUIC v2** |
| `dtls` | UDP | DTLS 1.2 application-data records, opened by a plaintext ClientHello |
| `quic` | TCP | **TLS** — records plus a synthetic ClientHello/ServerHello (§6.2) |

### 5.1 What the QUIC disguise actually does

* A QUIC v1 short header: form bit clear, fixed bit set, a stable 8-byte connection ID and a
  4-byte packet number.
* **Header protection exactly as RFC 9001 defines it** — a sample of the ciphertext encrypted
  under a derived key, masking the packet number and the low bits of the first byte. Without
  it, an exposed monotonic counter would be a louder fingerprint than the random payload.
* A **spin bit** that flips about once per round trip, because a bit that never moves — or one
  that flips every packet — is itself distinguishable from a real connection.
* A **synthetic handshake** at flow start: a genuine, correctly protected Initial packet
  carrying a structurally valid TLS ClientHello with an SNI and an h3 ALPN. It is encrypted
  with the standard Initial keys, which are derived from the public connection ID, so any
  observer can decrypt it — that is the point. A DPI that looks inside finds an ordinary
  ClientHello for an ordinary host. The far end answers, and adopts the connection ID the peer
  advertised, so the 1-RTT packets belong to the handshake rather than looking unrelated to it.
* **Size shaping** onto buckets of 128/256/512/768/1024/1280 bytes. Small datagrams are padded
  up so the tiny-packet cluster stops forming its own mode in the size histogram; large ones
  are left alone, which is where nearly all the bytes are.

### 5.2 Why `quic2` rather than `quic`

Measurement on two independent Iranian carriers (AS25184 Afranet, AS34918 Pishgaman) found
QUIC **v1 long-header** packets dropped outright in both directions — the same national rule on
both networks. Worse, one dropped v1 Initial blackholed the whole 5-tuple, so the short-header
traffic that followed died with it.

200 cover packets of each kind, sent and counted on arrival:

| Cover | Delivered |
|---|---|
| QUIC v1 Initial (`obfs: quic`) | **0 / 200** |
| QUIC v2 Initial (`obfs: quic2`) | 200 / 200 |
| DTLS ClientHello (`obfs: dtls`) | 200 / 200 |
| random datagrams (control) | 200 / 200 |

`quic` and `quic2` carry data identically, so this costs nothing. On `obfs: quic` over such a
link **the tunnel works and its disguise does not** — which is the worst of both worlds,
because you believe you are hidden.

### 5.3 `dtls` — a disguise that is not QUIC at all

A censor that already maintains a QUIC version blocklist can extend it. `quic2` sidesteps
today's list; a disguise that is not QUIC is what survives the list growing. DTLS is the
natural second choice and the same measurement backs it: DTLS-shaped datagrams sustained the
full offered rate on both carriers. It is also what a censor can least afford to block
wholesale — every WebRTC call, and OpenVPN in its UDP mode, is DTLS.

Unlike QUIC there is no header protection to imitate: a real DTLS record header is plaintext,
so masking it would be the one thing that makes the record fail to parse.

---

## 6. Carriers (`transport`)

### 6.1 `udp` — the default

One socket, kernel segmentation offload on both sides. Consecutive equally sized datagrams are
concatenated and handed to the kernel in a single `sendmsg` carrying a `UDP_SEGMENT` control
message, so one syscall and one pass down the output path cover up to 64 datagrams. Inbound,
`UDP_GRO` lets one `recvmsg` return several. None of this changes a byte on the wire —
segmentation happens below IP.

The TUN pump does one blocking read and then drains whatever else is already queued with
non-blocking reads. Under load that fills a batch; when the link is quiet the drain returns
immediately and a single packet goes out on its own, so batching never adds latency.

### 6.2 `tcp` — only where UDP is blocked

The carrier multiplexes **every** inner connection, so one lost carrier segment
head-of-line-blocks all of them at once, and the inner TCP retransmits on top of the outer one.
Measured on a real link: 4.7 % carrier retransmission, a permanently backed-up send queue, and
every user stalling in lockstep.

If you must use it, set `obfs: quic` on both ends. Over TCP that selects the **TLS** disguise,
not QUIC: each datagram becomes a TLS application-data record and the connection opens with a
synthetic ClientHello/ServerHello flight. TLS application data is encrypted, so a high-entropy
payload is exactly what an inspector expects there.

Role `a` dials and role `b` listens. `tcp_rotate` (§8.5) periodically moves the connection to a
fresh 5-tuple, make-before-break, to dodge volumetric throttling.

Fixed on 2026-10-05: the stream carrier's writers and its reader used to share one lock, and a
write blocked on a full send window held the lock the receive loop needed to find its connection.
With both directions saturated at once, each end stopped reading because it could not write, and the
tunnel froze for good — reproduced 3 of 3 times in a loopback test. Writers now serialise on a lock
of their own.

### 6.3 `icmp` — when UDP is not blocked but is broken

This exists because of a measurement. On the reference link the path does something a policer
does not:

| protocol | offered | delivered | loss | outages |
|---|---|---|---|---|
| TCP (any port) | — | 0.07–1.3 Mbit/s | — | 500+ retransmits / 15 s |
| UDP (any port) | 0.5 Mbit/s | 0.30 Mbit/s | 40.8 % | ~94 ms every ~345 ms |
| UDP (any port) | 40 Mbit/s | 23.2 Mbit/s | 42.5 % | ~94 ms every ~345 ms |
| **ICMP echo** | 30 Mbit/s | **30.4 Mbit/s** | **0.4 %** | none |

The UDP loss is flat across two orders of magnitude of offered rate, so it is not congestion and
not a policer — there is no threshold to stay under. It arrives as blackouts: the path swallows
everything for ~94 ms, then passes everything for ~250 ms. Sampled across four flows on four
different port pairs, those dead windows coincide with Jaccard 0.96–0.97, so the blackout
belongs to the path, not the flow. Port hopping and 5-tuple rotation all move traffic from one
blocked window into the same blocked window. ICMP crosses the same path at the same moment with
no blackout at all.

Three details make it work rather than merely look like it should:

* **Echo requests both ways, never replies.** An unsolicited echo reply is dropped somewhere on
  this path (measured: 100 % of 37500) because a stateful middlebox has no request to match it
  to. A request is not a response to anything.
* **The peer's kernel must be stopped from answering.** Otherwise every data packet draws an
  echo reply carrying a copy of the payload back the way it came. `suppress_replies` installs
  one firewall rule matched on the ICMP identifier, so only this tunnel's pings go unanswered
  and ordinary `ping` to the peer keeps working.
* **A raw socket is not a UDP socket.** It has no GSO/GRO and sees every ICMP message the host
  receives. A classic BPF filter attached to the socket makes the kernel queue only this
  tunnel's echo requests; `sendmmsg`/`recvmmsg` amortise the syscall; and several receive
  goroutines cut the time between reads. A single unbatched reader at 400 Mbit/s lost 22829
  packets to receive-buffer overflow while the network delivered 99.5 % of them.

`obfs` must be `none` on this carrier: no real ping carries a QUIC header, so it would be the
one anomalous thing about an otherwise ordinary packet. Port hopping does not apply either.

### 6.4 `reverse` — the foreign server opens the flow (UDP)

By default the Iran server (role `a`) dials: it sends the first packet of every carrier flow,
plays the client side of the synthetic handshake, and is the end `udp_rotate` moves — so every
flow on the wire is one opened from inside Iran toward a foreign address. Reverse tunnels
(Backhaul, rathole, frp) exist because a censor does not have to treat the two directions alike:
a flow opened from inside toward a foreign address is the kind that gets flagged or cut when the
filter tightens, while a foreign host reaching a server inside looks like a visitor reaching a
domestic service. `"reverse": true` gives the UDP carrier that shape and changes nothing else:

| | normal | `reverse: true` |
|---|---|---|
| opens the flow (first packet, client hello) | role `a` — Iran | role `b` — foreign |
| answers the handshake cover | role `b` | role `a` |
| needs `peer` | role `a` (role `b` may learn it) | role `b` only; role `a` never dials it |
| moves its source port (`udp_rotate`) | role `a` | role `b` |
| must accept inbound UDP on its port | role `b` | role `a` — in the cloud firewall too |

The roles keep everything else — key directions, tunnel addresses, everything the scripts derive
from them — so the Iran server is still `a` and still `10.8.0.1`. Like `key`, `cipher` and `obfs`
the switch is not negotiated: set it the same on **both** servers (wizard, or menu `x` → `7`).

Iran server:

```json
"role": "a", "transport": "udp", "reverse": true, "listen": "0.0.0.0:51820"
```

Foreign server:

```json
"role": "b", "transport": "udp", "reverse": true, "peer": "IRAN_PUBLIC_IP:51820"
```

**The listening end is strictly passive.** It sends nothing — no keepalive, no probe, no
handshake reply, no traffic — to an address that has not first sent it an authenticated packet,
so every datagram it emits is the reply direction of a flow opened from abroad. Its `peer` is not
dialled; the peer is learned from the first authenticated packet, by the same roaming that already
follows a moving source port. The dialer sends a few sealed keepalives right behind its hello, so
the listener learns where it is within a round trip rather than at the first keepalive.

**The handshake cover still completes.** The listener has to answer the dialer's Initial (or DTLS
ClientHello) the way a server would — an Initial nobody answers is exactly the "Unknown QUIC
connection" a stateful classifier keys on — but the hello arrives before the dialer has
authenticated, from an address as anonymous as a prober's. So the listener holds it until an
authenticated packet arrives from that exact address, and only then answers it and adopts the
connection ID it carried. A prober that sends the port a perfectly good Initial gets nothing back,
and is filed in the DPI log as `probe.quic_initial` once the 40 s hold runs out.

Limits, stated plainly:

* **UDP only.** The binary refuses `reverse` with `tcp` or `icmp` — ICMP has no direction to
  reverse, both ends send echo requests — and with `hop`, which moves both ends on a shared
  schedule and so leaves no fixed point to dial. `aestun-mp.sh` keeps it on its two UDP carriers.
* **The listener waits.** After it restarts it cannot send until the dialer's next packet: at most
  one keepalive interval, ≤ 35 s at the default 25 s. Keep `keepalive` on at the dialing end — a
  flow that idles out of a middlebox's state table turns the listener's next packet into a flow
  opened from inside.
* **It changes who opens the flow, not what the path does to the packets.** Measured on the
  reference pair on 2026-10-04, while every carrier was down: the path cut each new UDP flow after
  its first few datagrams. Inside → outside delivered ~1 % whichever end had opened the flow;
  outside → inside delivered ~1 % when the outside opened it and 100 % as replies to a flow the
  inside opened. ICMP and bulk TCP from inside were dropped too. Reverse cannot help a path that
  drops the inside's packets whatever their direction; it helps where the path treats the two
  directions differently. Auto-test (menu `t`) measures a `reverse-udp` variant on your own path.

zapret (menu `z`) queues packets sent *to* the configured peer port, so under reverse it acts on
the foreign end — the end that now opens the flow.

### 6.5 `ws` — WebSocket through a CDN (Cloudflare)

Every carrier above talks to the peer's own address, and on the reference path that address is
the problem: measured on 2026-10-05, every flow the Iran server opened toward the foreign server —
UDP, ICMP or TCP, on any port — was cut after its first ~6 packets or 8688 bytes. No disguise
changes the destination address. A CDN does:

```
Iran (dialer) --TLS, SNI=your domain--> CDN edge --HTTP(S), same port--> foreign (listener, the origin)
```

The Iran server only ever talks to the CDN's edge — addresses it shares with a large part of the
ordinary web — and the edge carries the bytes on over a path the censor never sees. On the wire
it is an ordinary TLS connection carrying an HTTP/1.1 upgrade to WebSocket, then binary messages,
one sealed tunnel datagram per message. The tunnel's own AEAD still protects every byte end to
end; the edge terminates the TLS layer and learns nothing it can use.

**Cloudflare, once:**

1. DNS: an `A` record for a (sub)domain → the foreign server's IP, **Proxied** (orange cloud).
2. SSL/TLS mode **Full** — the listener makes itself a certificate at start-up, which Full accepts.
   Flexible works too (the listener speaks TLS and plain HTTP on the same port, told apart by the
   first byte); Full (strict) needs a real certificate in `ws.cert` / `ws.cert_key`, e.g. a
   Cloudflare Origin CA one.
3. Network → WebSockets: On (the default).
4. Pick a port from Cloudflare's TLS list — **443, 2053, 2083, 2087, 2096, 8443** — that nothing else
   uses on the foreign server. Cloudflare connects to the origin on the port the visitor used, so the
   listener's `listen` is that same port. Allow it inbound (TCP) on the foreign server.

**Both servers** carry the same `ws` block; each end reads what applies to it:

```json
"role": "a", "transport": "ws", "obfs": "none",
"ws": { "url": "wss://tunnel.example.com:8443" }
```
```json
"role": "b", "transport": "ws", "obfs": "none", "listen": "0.0.0.0:8443",
"ws": { "url": "wss://tunnel.example.com:8443" }
```

The request path is derived from the key, so the two ends agree without being told (the listener
prints it at start-up); a path in the URL or in `ws.path` overrides it. `ws.connect` dials specific
Cloudflare addresses instead of resolving the domain — for a server whose DNS cannot resolve it, or
when some Cloudflare ranges are filtered — while SNI and `Host` stay the domain. It takes a list
(`"104.26.8.173, 172.67.68.133"`): an address that cannot be reached is skipped and the one that
worked is tried first next time. Measured from one Iranian network on 2026-10-05, one Cloudflare
range timed out while another passed, and the two exited through different countries to different
Cloudflare PoPs — so which address you dial changes both whether and how well it works.

**Check before switching anything over.** On the dialing server:

```bash
aestun ws-check -config /etc/aestun/config.json            # or -url / -connect / -sni to try variants
```

It dials exactly as the carrier would and reports each step — TCP, TLS (version, ALPN, certificate),
the upgrade — and, when the upgrade fails, the CDN's status and which leg it means: `521` nothing
listens on the origin port (or its firewall refuses Cloudflare), `522` Cloudflare's packets to the
origin are dropped, `525`/`526` origin TLS versus the SSL mode, `404` the path or key differ, `301`
plain HTTP redirected (use `wss://`). It closes politely without sending data, so it never disturbs
a running tunnel and is not filed as a probe.

**Admission.** The path is a secret, but it is not what lets a connection carry the tunnel. The
listener answers the upgrade, then waits for the first message; only if that message opens under
the tunnel key — fresh, not a replay — does the connection replace the current one. Anything else is
answered with nginx's own 404 and filed by the DPI observer: `probe.http` for requests that are not
the tunnel's upgrade, and `probe.ws_unauth` (severity high) for an upgrade on the right path whose
first message did not authenticate — whoever sent it has the path but not the key. Behind
Cloudflare the visitor's address is taken from `CF-Connecting-IP` for the log.

**Staying up.** The dialer redials with backoff when the connection drops. A CDN can keep the
dialer's leg open after the leg to the origin has died, so the socket looks healthy and nothing
arrives; the dialer therefore watches the peer's keepalives and replaces a connection that has
carried nothing authenticated for `ws.idle_sec` (default 3 × keepalive, at least 45 s). Sockets use
`TCP_USER_TIMEOUT` = 30 s, so a path that swallows a connection mid-flow surfaces in 30 s rather
than after ~15 minutes of retransmission. `ws.rotate_sec` replaces the connection on a jittered
timer, make-before-break, like `tcp_rotate`. Cloudflare drops a WebSocket idle for 100 s; the
default 25 s keepalive stays well inside that.

**Reverse.** `"reverse": true` works here too: the foreign server dials a domain proxied to the
Iran server, which becomes the origin and only answers connections that authenticate. Measured on
2026-10-05, Cloudflare could not reach the Iran server's origin (every TLS port timed out), so this
direction depends on the Iran host accepting connections from Cloudflare's ranges.

**Limits, plainly.** It is a stream carrier: one lost segment stalls every inner connection until
it is retransmitted, as with `tcp`, so it is not a replacement for UDP where UDP works. The TLS
ClientHello is Go's `crypto/tls`, not a browser's, so a JA3-style fingerprint tells it apart from
Chrome. The CDN sees the WebSocket's timing and volume (not its content) and its terms of service
apply. `obfs` must be `none` and port hopping off — the TLS connection to the CDN is the disguise.

Local system test, with nginx standing in for the edge (three network namespaces, the dialer with
no route to the origin): ~1 Gbit/s each way through a TLS→TLS edge, 686 Mbit/s with a
plain-HTTP origin leg; recovery after an origin restart, an edge restart, and a silent outage of the
edge's leg (watchdog, 15 s); 736 MiB intact across two make-before-break rotations; reverse up.

Through real Cloudflare on 2026-10-05 — dialer on a residential Iranian connection, origin the
foreign server in Baku, SSL mode Full, port 8443, iperf3 for 12 s:

| path | RTT | up | down, 1 stream | down, 4 streams |
|---|---|---|---|---|
| direct, no tunnel (the baseline) | ~62 ms | 1.08 Mbit/s | 10.9 Mbit/s | — |
| `ws` via Cloudflare 188.114.98.0 (PoP SOF) | 76 ms | 0.83 | 7.17 | 12.6 |
| `ws` via Cloudflare 104.26.8.173 (PoP FRA) | 215 ms | 0.57 | 5.24 | 6.55 |

Ping through the tunnel lost nothing (0 of 30). The uplink of that connection is ~1 Mbit/s, so the
up column is the access line, not the carrier. The same afternoon the Iran server itself could reach
no foreign address at all — not Cloudflare, not the foreign server, not Google — while domestic
sites answered: no carrier can leave a host in that state, and this one is no exception.

---

## 7. Multi-protocol carrier — failover and multipath

A single `aestun` picks one carrier at startup and keeps it. `aestun-mp.sh` runs four
instances — each on its own TUN device, port and `/30` — and bonds them at the routing layer:

```
application  ──▶  10.10.0.x            ← stable overlay address, never changes
                      │
        ┌─────────────┼─────────────┬─────────────┐
    udp/quic2     udp/dtls      tcp/tls        icmp        ← four independent carriers
      tun0         mpdtls        mptls        mpicmp
        └─────────────┴─────────────┴─────────────┘
                      │
                  peer server
```

Applications only ever address the overlay IP. Which protocol carries a given packet is the
supervisor's decision and can change at any moment without the application noticing. A separate
`/32` on `lo` is the only address that survives a carrier switch — each carrier's own `/30`
dies with it.

### Modes

| Mode | Behaviour |
|---|---|
| `failover` | One carrier at a time, in table order. The first responsive protocol takes everything; when it stops answering the next takes over. |
| `multipath` | Every healthy carrier at once, as a weighted ECMP route. Weight follows RTT and loss, clamped to 1…16. |

Linux hashes ECMP **per flow**, not per packet: one TCP connection stays on one protocol for
its whole life while concurrent connections spread across all of them. That is the honest
description — multipath raises aggregate capacity and survivability; it does not accelerate a
single connection. `setup` sets `net.ipv4.fib_multipath_hash_policy=1`, without which the kernel
hashes on addresses alone and — since every overlay flow shares one address pair — *every* flow
lands on the same carrier.

### Health checking

The supervisor probes all four carriers concurrently every 2 s, using two independent signals,
because either alone lies:

* a ping across the carrier's own `/30` — the end-to-end truth, but it cannot say *why* a dead
  carrier is dead;
* the instance's own `auth_fail` counter — rising `auth_fail` with traffic flowing means the two
  ends disagree on the wire format, which no amount of failover will fix and which otherwise
  looks exactly like network loss.

Hysteresis is asymmetric on purpose: two consecutive failures drop a carrier, three consecutive
successes re-admit it, so a flapping link does not drag traffic back every few seconds. When
every carrier is down the last route is deliberately left in place — tearing it down would turn
a transient blip into a hard failure for every established connection.

### Commands

```bash
aestun-mp.sh setup            # generate a config per protocol — run on BOTH servers
aestun-mp.sh start            # stand down the single-path service, bring all carriers up
aestun-mp.sh mode multipath   # or: failover
aestun-mp.sh status           # carriers, health, per-device counters, current route
aestun-mp.sh probe            # probe every protocol once
aestun-mp.sh send tls 32      # push 32 MiB over ONE named protocol and time it
aestun-mp.sh bench 16         # the same over every protocol in turn
aestun-mp.sh revert           # back to the stock single-path tunnel
```

`setup` is deterministic: it derives every port, device and address from the role in
`/etc/aestun/config.json`, so running it on both servers produces matching configs with no
cross-server push. Menu option `m` in `aestun.sh` is a front end for the same script.

### Two failure modes worth knowing

* **`mimic_ping` must match on both ends.** It prepends a `ping(8)`-style timeval to the
  plaintext, so if one end mimics and the other does not, every packet crosses the network
  intact and *then* fails AEAD. The carrier logs "tunnel up" and passes zero traffic. This was
  live on the reference pair and is why its ICMP carrier had never worked; `setup` now pins the
  whole `icmp` block on both sides.
* **MTU must be identical across carriers.** Under ECMP the kernel picks a nexthop with no idea
  the carriers differ, so a smaller MTU on one path blackholes exactly the flows hashed onto it
  — a bug that only appears under load. `setup` forces one MTU for all four.

---

## 8. Anti-DPI modules

All off by default. Each raises the cost of classification; none is a proof of anything. Turn
them on against an observed problem.

### 8.1 `desync` — native fake injector

The `nfqws` idea, in-process. zapret is built for the hard case — the far end is a website you
do not control, so every fake must be crafted so the real server ignores it — and that
constraint forces it through NFQUEUE, a userspace round trip per carrier packet, and an
iptables rule kept in sync with the listen port.

aestun owns *both* ends. It already knows the carrier 5-tuple because it opened it, it already
learned the peer's hop count from the TTL of the peer's own packets, and the peer's receive path
already discards stray long-header datagrams safely. So the injector needs none of that
machinery: one raw socket, and at flow start a handful of genuine-looking QUIC Initials sharing
the carrier's exact 5-tuple, at a TTL tuned to die a hop or two before the peer.

| Field | Default | Meaning |
|---|---|---|
| `repeats` | `4` | fakes per burst |
| `autottl` / `delta` | `true` / `-1` | derive TTL from the learned hop count, dying one hop early |
| `min_ttl` / `max_ttl` | `3` / `20` | clamp |
| `ttl` | `0` | fixed TTL when `autottl` is off |
| `badsum` | `false` | corrupt the fake's checksum so the peer's kernel drops it |
| `every_sec` | `0` | periodic re-burst; `0` = only at flow start |

IPv4 only, needs `CAP_NET_RAW`. On the ICMP carrier there is no UDP 5-tuple to ride, so the
equivalent injector sends **decoy pings** instead — the exact 56-byte `iputils` payload, wearing
the carrier's own identifier, so a stateful classifier sees an ordinary ping session that later
grows rather than one born at hundreds of megabits.

### 8.2 `junk` — flow-start cover traffic

A tunnel that opens with the same number of packets, at the same sizes, in the same rhythm,
every time has a start-of-flow fingerprint even when every byte is encrypted. This sends a burst
of `count` packets with a random gap between each.

The packets are **real sealed keepalives**, not random bytes. Literal junk would fail
authentication at the peer and be filed by the observer as a scan — turning our own cover
traffic into noise in our own DPI log. These authenticate cleanly, decrypt to an empty payload
the receive loop already discards, and with a disguise on they even parse as QUIC.

### 8.3 `hop` — keyed synchronised port hopping

The reference deployment hit a block on the precise source/destination port *pair*, while the
same random UDP from any other port went through untouched. Both ends derive the same port from
the pre-shared key and the wall clock — the mechanism the tunnel already uses for epoch keys —
and step through an agreed set on a timer.

Every port in the set is bound for the whole life of the process on both ends, so a packet that
arrives a little early or late still lands on a bound socket. There is no rebind, so no handover
gap and no race. Peers are matched by IP alone while hopping, so the rotation does not trip the
roam detector.

**Cost, stated plainly:** one socket per port and one datagram per syscall — this mode forgoes
send-side segmentation offload, and measured **−38 %** throughput. It is insurance against
blocking, not a throughput feature.

### 8.4 `split` — IP-fragment the fakes

zapret's most effective trick against websites is cutting a plaintext ClientHello across
segments so the DPI cannot reassemble the SNI. That works because the DPI can see the plaintext
it wants. Here it cannot: the carrier payload is uniform random from the first byte. Splitting
*real* traffic would mean inventing a reassembly protocol and adding head-of-line risk to
scramble bytes a DPI already cannot read.

So this module deliberately does not touch real traffic. It fragments only the disposable
desync fakes, which are throwaway by construction. A DPI that does not reassemble sees a
truncated first fragment of the cover handshake; one that does sees the same legitimate Initial
as before. Either way the real flow is untouched.

### 8.5 `udp_rotate` — keep the 5-tuple moving (on by default)

**This one is on by default**, because the failure it prevents is one that actually happened
on the reference pair rather than one that might.

The quic carrier ran on a fixed pair of ports and carried ~33 GB over it. That exact 5-tuple
then stopped passing **in both directions, permanently** — while the *same destination port
from any other source port* kept working, and the other three carriers were untouched.
Measured in a single window with `tcpdump` running on both servers:

| flow | delivered |
|---|---|
| `A:1376 → B:1376` (the carrier's own pair) | **0 packets** |
| `A:40606 → B:1376` | 18 packets |
| `B:48584 → A:1376` | 15 packets |

The block keys on the tuple and is triggered by what that tuple accumulates. The port is fine;
the *pair* is burned. The carrier went silent at the same instant on both ends and stayed dead
for over an hour, with `auth_fail` at zero the whole time — nothing was wrong with the tunnel.

`udp_rotate` binds a fresh source port on a jittered timer and switches onto it,
make-before-break, so no tuple lives long enough to be worth blocking. It works because of a
property the protocol already had: the peer learns our address from any authenticated packet
(roaming). So:

* **nothing is negotiated** — a peer on an older build follows automatically;
* **the destination port never moves** — no firewall on either end has to be touched;
* **only the dialing end rotates** — role `a`, or role `b` under `reverse` (§6.4). The listening
  end is the fixed point both ends are addressed at, and two ends moving at once could lose each
  other. Same rule as `tcp_rotate`, where only the dialer rotates.

Unlike `hop` it keeps one socket at a time, so segmentation offload is preserved and there is
no throughput cost — `hop` measured −38 % for the same idea because it binds a whole port set
and sends one datagram per syscall. The retired socket is held open, unread, for 40 s: closing
it at once would make the kernel answer in-flight datagrams with ICMP port-unreachable, which
is a loud signal on a link where the point is to emit none.

| Field | Default | Meaning |
|---|---|---|
| `enabled` | `true` | set `false` if a stateful middlebox on your path pins the source port |
| `interval_sec` | `900` | seconds between rotations, jittered ±40 %; floored at 60 |

The cost is whatever was in flight to the old port for about one round trip; the inner TCP
retransmits it. The new socket sends a keepalive immediately so the peer roams within that RTT.
It is skipped under `hop`, which already moves the tuple, and does not apply to `tcp` or `icmp`.

If a tuple gets blocked anyway despite rotation, `hop` (§8.3) is the stronger answer — it moves
both ends' ports on a keyed schedule, at the cost of offload.

### 8.6 `tcp_rotate` — dodge volumetric throttling

The field test found a TCP+TLS carrier, however perfectly it parsed as HTTPS, throttled to a
blackhole within ~30 s: a single long-lived, high-rate TLS connection is anomalous on rate and
lifetime alone, and no disguise changes its rate. This attacks the *lifetime* instead — the
dialer opens a fresh connection on a jittered timer and switches onto it before retiring the old
one, so no single flow lives long enough to cross the threshold. A few in-flight bytes are lost
per rotation and the inner TCP retransmits them; a blip every 15 s beats a blackhole.

---

## 9. Monitoring and observability

### 9.1 The live dashboard (menu `2`)

Reads the stats each carrier publishes and refreshes every 2 s. It detects single-path and
multipath automatically and, under multipath, aggregates all four carriers and shows a
per-carrier breakdown:

```
+-- aestun live monitor -------------------------------+
  mode     : multipath    4/4 carriers up
  uptime   : 4h 48m       last RX: 0s ago   iface tun0: up
  peer     : 185.41202:1378
+-- traffic (all carriers) ----------------------------+
  TX :      4.36 GB  (0 B/s)  packets: 6154870
  RX :      7.18 GB  (0 B/s)  packets: 8128375
+-- per carrier ---------------------------------------+
  NAME           RX         TX AUTHFAIL   LOSS%   RTT_ms
  dtls      1.52 GB  179.47 MB        0    2.11    67.25
  icmp      1.93 GB   11.16 MB        0    2.67    58.87
  quic      2.53 GB    4.16 GB        0    1.68    47.24
  tls       1.20 GB    9.78 MB        0       0    44.97
+-- security ------------------------------------------+
  auth failures (auth_fail) : 0
  replay drops              : 0
  key rotation              : every 3600s
+-- DPI observer --------------------------------------+
  active probes / replays   : 0 / 0
  injections / TTL anomalies: 0 / 0
  background scanning       : 0
  worst loss / RTT          : 2.67%  /  67.25 ms
+-----------------------------------------------------+
```

`auth_fail` is the field to watch. It should be **0**. Anything else means the two ends disagree
about the wire — key, cipher, `obfs`, or `mimic_ping`.

### 9.2 Live tunnel log (menu `l`) and recording it (menu `r`)

Both follow the journal of whichever aestun units are actually running, merged, so they behave
the same on a single-path and a multi-protocol install. The DPI observer already writes its
non-routine findings to stdout, so those arrive on the same stream. Lines are coloured by
severity: red for high/blackhole/injection, yellow for warn/throttle/loss.

`r` captures that stream to `/var/log/aestun/live-<timestamp>.log`, takes an optional duration,
writes a self-describing header (host, units, wire format, peer) so the file makes sense when
read somewhere else, and prints a high-severity and warning count when it stops. Ctrl+C returns
to the menu.

### 9.3 The DPI observer (`dpi_log`)

Two distinct questions, answered separately.

**"Who is talking to this port that is not the peer?"** Every datagram that is not authenticated
peer traffic is classified and aggregated per source address, so a port scan collapses into one
record. The interesting cases are the ones that are not scans:

| Event | What it means |
|---|---|
| `probe.quic_initial` | a stranger sent a QUIC handshake — someone is checking whether this port really speaks QUIC |
| `probe.replay` | a third party replayed our own captured packets back at us — the classic way a censor confirms what a suspicious flow is |
| `inject.spoofed_peer` | unauthenticated datagrams wearing the peer's source address — on-path injection |
| `anomaly.ttl` | a packet from the peer's address with the wrong hop count — an injector nearly always sits fewer hops away, and the TTL it has to guess is what it most often gets wrong |
| `scan.unauth` | ordinary background noise |

**"Is the path mistreating our packets?"** The inner sequence numbers measure loss and
reordering for free. On top of that: `path.blackhole` (still sending, nothing coming back),
`path.throttle` (throughput collapsed against the flow's own recent baseline), `path.loss_burst`,
`path.rtt_spike`, and `kernel.udp_errors` — because forged and desynced packets die in the
kernel and are otherwise invisible.

Cost is close to nothing when nothing is happening: authenticated packets touch only a handful
of atomics. Events reach the writer through a buffered channel with a non-blocking send, so a
flood of probes can never slow the packet loops — it just increments a dropped counter.

`aestun.sh dpi-report` (or menu `d`) summarises the log.

### 9.4 In-tunnel probes

Loss and reordering come free from the sequence numbers, but latency does not — nothing in the
protocol asks the peer to answer. So one small frame every `probe_sec` travels *inside* the
tunnel encryption, in the slot where an inner IP packet normally goes. Anything there is already
indistinguishable from the rest of the traffic, which is why the measurement is not built into
the carrier layer. Only the real peer can answer, so the RTT it reports is genuine.

---

## 10. Performance and tuning

### 10.1 Cipher — check this before anything else

AES-256-GCM is right **when the CPU has AES-NI**. Without it, Go falls back to a constant-time
software AES plus a generic GHASH, and the cost is not a detail:

| Suite | With AES-NI | Without (QEMU virtual CPU) |
|---|---|---|
| AES-256-GCM | fast | **41 MB/s** |
| ChaCha20-Poly1305 | slightly slower | **234 MB/s** |

That is 5.7×, or 26 µs saved on every 1300-byte packet. ChaCha20 needs nothing but 32-bit adds,
xors and rotates, so it does not care that the CPU is a stripped-down virtual model.

Both AEADs take a 12-byte nonce and add a 16-byte tag, so the choice is **invisible on the
wire** — same layout, same sizes. A link is only as fast as its slower end, so if *either* box
lacks AES-NI, set both to `chacha20-poly1305`.

```bash
aestun cipherinfo      # prints aes_hardware, the CPU model, and the recommendation
```

### 10.2 Throughput, measured

Reference link (Pishgaman AS34918 ↔ Leaseweb Germany, ~79 ms, both ends `chacha20-poly1305`),
`iperf3` with 4 streams each direction, buffers at 2 MiB:

| Variant | ↓ down | ↑ up | RTT | jitter | loss |
|---|---|---|---|---|---|
| `udp` + `dtls` | **661** Mbit/s | 704 | 79.7 ms | 1.8 ms | 0 % |
| `udp` + `quic2` | **649** Mbit/s | 691 | 79.6 ms | 1.5 ms | 0 % |
| `udp` + `quic` | 620 Mbit/s | 675 | 79.8 ms | 1.9 ms | 0 % |
| `udp` + `none` | 358 Mbit/s | 488 | 79.8 ms | 1.8 ms | 0 % |
| `tcp` + `quic` (TLS) | 205 Mbit/s | 259 | 83.3 ms | 6.0 ms | 0 % |
| `tcp` + `none` | 197 Mbit/s | 227 | 76.0 ms | 2.3 ms | 0 % |

Two things worth noticing. **UDP is ~3× faster than TCP**, and **`obfs: none` is the slowest UDP
option, not the fastest** — the disguise is not costing you speed, so there is no throughput
argument for running without one.

Module cost on top of `udp` + `quic2`: `desync` ~4 %, `junk` negligible, `desync`+`split`+`junk`
about 2 % combined. `hop` costs **38 %** because it forgoes offload.

### 10.3 Socket buffers are a queue

Sizing a buffer for peak throughput sizes it for latency too. Measured on the 650 Mbit/s link,
saturated, pinging across the tunnel:

| Buffer | Throughput | Added queueing delay | Jitter |
|---|---|---|---|
| 16 MiB both ways | 669 Mbit/s | **+109 ms** | 55 ms |
| 2 MiB both ways | 611 Mbit/s | **+22 ms** | 11 ms |

The old 16 MiB default bought 9 % more peak throughput and paid five times the delay for it.
Hence the 2 MiB default.

**Multipath changes this calculation**, because four carriers share one host and their bursts
arrive together. Measured on the production pair, 32 flows offering 2 GiB across all four
carriers, counted on the 2-core receiver:

| `rcvbuf` | goodput | UDP `RcvbufErrors` | raw-socket drops | ping across the tunnel |
|---|---|---|---|---|
| 2 MiB | 553 Mbit/s | 28442 (6.14 %) | 33190 | 10.0 % loss, 83 ms |
| **4 MiB** | **585 Mbit/s** | 2512 (0.56 %) | 2492 | 1.4 % loss, 109 ms |
| 8 MiB | 556 Mbit/s | 421 (0.08 %) | 0 | 4.3 % loss, 130 ms |

The NIC counters were **zero** throughout: every one of those packets crossed the network and
was then thrown away on the host for want of a reader. 4 MiB removes the bulk of that for a
bounded latency cost and, because the drops were themselves causing retransmissions, it is also
the fastest of the three. `aestun-mp.sh setup` therefore raises the multipath carriers to 4 MiB
while leaving `sndbuf` alone — every drop measured was on receive, and oversizing the send side
is bufferbloat with nothing to show for it.

Watch for this yourself with `grep Udp: /proc/net/snmp`; a rising `RcvbufErrors` means the
buffer is too small *or* `net.core.rmem_max` is below it, since the kernel clamps the request.

### 10.4 Rate shaping (`rate_mbps`)

Sweeping offered rate against delivered rate on the reference link produced a cliff rather than
a curve:

| offered | delivered | loss |
|---|---|---|
| 185 Mbit/s | 183 | 0 % |
| 210 Mbit/s | 210 | 0 % |
| 220 Mbit/s | 145 | **34 %** |
| 260 Mbit/s | 155 | **40 %** |

That is a policer. A few percent above its threshold, a third of the traffic is discarded and
*delivered* throughput falls by a quarter — pushing harder makes the link slower. TCP cannot see
this, because congestion control probes upward until it loses packets and therefore sits
permanently on the wrong side of the cliff: BBR offered 232 Mbit/s to deliver 194, retransmitting
18 %, while a paced 190 Mbit/s delivered 188 with no loss at all.

Shaping and policing are not the same thing. A policer drops what exceeds the rate; this delays
it, which backs pressure up through the TUN queue to the inner TCP senders, and they slow down
on their own. Off by default — it has to be set from a measurement of your own path, and a wrong
value is just a speed limit.

### 10.5 What the supervisor costs

The multipath supervisor is a shell loop, and a shell loop that forks is expensive. Its field
lookups originally ran through command substitution — a fork per field, per protocol, per pass —
plus a `python3` start-up per carrier per pass to read one integer out of a JSON file:

| | before | after |
|---|---|---|
| Iran (4-core) | 25.52 % of a core | **2.07 %** |
| Foreign (2-core) | 27.07 % of a core | **1.85 %** |
| system forks/sec | 50 | **7** |

For scale: the four `aestun` processes it supervises used **0.35 % of a core between them** while
idle. The supervisor cost seventy times the thing it was supervising. It now expands the
constant protocol table into associative arrays once at load and indexes them, parses JSON with
bash's own regex, and does the ECMP weight arithmetic in fixed point instead of forking to
`awk`. The weight function was verified bit-identical to the original across 187 RTT/loss
combinations.

The same lesson applies to the dashboard, where an early version of the stats reader repeated
the mistake: a fork-free helper is still a fork when it is called as `$(helper)`. Loading each
file once into an associative array took a refresh from 311 ms to 31 ms.

---

## 11. Management menu

```
sudo ./aestun.sh
```

```
1) Setup / reconfigure tunnel (wizard)
2) Live monitoring dashboard      <- aggregated + per-carrier, auto-detects multipath (§9.1)
3) Service management             <- start/stop/restart/enable/disable/status
4) Connectivity test              <- ping the peer's tunnel IP
5) Live logs                      <- follows whichever units are running
l) Live tunnel log                <- follow the tunnel processes, coloured by severity (§9.2)
r) Record live log to file        <- capture that stream for later / to send on (§9.2)
6) Show config                    <- key masked
7) Edit config                    <- then optionally restart
8) Generate new key
9) Network optimization           <- show / apply / remove sysctl tuning
d) DPI / probe log                <- who is probing, what the path is doing (§9.3)
x) Anti-DPI hardening             <- desync / junk / port-hop / split (§8), reverse UDP (§6.4)
i) ICMP carrier settings          <- readers / batching / id rotation / ping mimicry (§6.3)
t) Auto-test methods              <- sweep every method/protocol, apply the best
m) Multi-protocol tunnel          <- run 4 carriers at once: failover + multipath (§7)
p) Locations (multi-peer)         <- one foreign server to many Iran servers, or the reverse (§17)
z) zapret module                  <- optional external DPI desync layer
u) Uninstall
```

`l` and `r` are also reachable directly from the dashboard without leaving it.

---

## 12. Troubleshooting

| Symptom | Where to look |
|---|---|
| Ping test fails | Both services active? Carrier port open in the **cloud** firewall as well as the host one? `role` different on the two servers? |
| `auth_fail` climbing | The two ends disagree on the wire: `key`, `cipher`, `obfs`, or `icmp.mimic_ping`. Not a network problem — failover will not fix it. |
| Tunnel "up" but no traffic on the ICMP carrier | `mimic_ping` mismatch (§7). Also check ICMP echo is allowed inbound in the cloud firewall. |
| Works, then dies after ~30 s on TCP | Volumetric throttling. Switch to UDP, or enable `tcp_rotate` (§8.5). |
| `reverse`: the Iran server reports "no peer has dialled in" | The foreign server must run with `reverse: true` and `peer` = the Iran server's public `IP:port`; that UDP port must be open inbound on the Iran server, in the **cloud** firewall too; `key`/`cipher`/`obfs`/`reverse` must match (§6.4). |
| Good throughput, bad ping under load | Buffers are too large — see §10.3. |
| Rising `RcvbufErrors` | Buffer too small, or `net.core.rmem_max` below it. Run the network optimization (menu `9`). |
| Nothing in the dashboard | Nothing is writing `/run/aestun/stats*.json`. Start the tunnel, or the multipath carriers (menu `m` → `5`). |
| Port 443 is slow | Measured on the reference link: `:443` rides a DPI inspection detour worth ~64 ms. Moving to `:2087` cut tunnel RTT from ~82 ms to ~18 ms. Do not run the carrier on 443 just because it "looks like HTTPS". |

---

## 13. Building and testing

```bash
go build -o aestun .                         # plain build
./aestun.sh build amd64                      # cross-build + refresh SHA256SUMS
./aestun.sh build arm64
```

> Note: `go build ./...` writes its output to `./aestun`, overwriting the shipped binary. Use
> `go build -o <path> .`.

This tree ships without test files. Nothing in the program depends on them — test files are
never compiled into a binary — so their absence leaves the build byte-identical.

Builds are reproducible (`CGO_ENABLED=0`, `-trimpath`), so you can check rather than trust:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o /tmp/v .
sha256sum /tmp/v aestun-linux-amd64     # the two hashes must match
```

`./aestun.sh build <arch>` regenerates `SHA256SUMS` and, when building for the host's own
architecture, refreshes `./aestun` too — so the checksum file cannot certify a binary that no
longer exists, and the "run it directly" binary cannot silently be the previous program.

---

## 14. Security model and honest limits

**What it gives you.** Confidentiality and integrity from an AEAD (tampered packets are
dropped), separate keys per direction so the two can never reuse a nonce against each other,
anti-replay over a 4096-packet window, optional epoch key rotation with no handshake, and a wire
image with no fixed bytes for a classifier to match.

**What it does not.** This is a **pre-shared-key** tunnel. Anyone with the PSK reads all
traffic. Epoch rotation limits nonce reuse and gives coarse key hygiene, but it is **not**
forward secrecy: a leaked PSK compromises past and future traffic. Keep the config `0600` and
rotate the PSK periodically on long-lived, high-volume links.

**On the disguises.** They remove cheap signatures. They are not a proof of undetectability. A
classifier that actively completes a TLS or QUIC handshake would find that ours does not go
anywhere; a classifier with enough traffic analysis can work on timing and volume regardless of
framing. Every module here raises the cost of classification — that is the claim, and it is the
only one worth making.

**Capabilities.** The service needs `CAP_NET_ADMIN` (TUN device, `ip` commands, `SO_RCVBUFFORCE`)
and `CAP_NET_BIND_SERVICE`. `CAP_NET_RAW` is required by the ICMP carrier and by `desync`, and
is harmless when neither is in use.

---

## 15. Measurement appendix

Every figure in this document was measured on the reference deployment — Iran (role `a`) ↔
Europe (role `b`) — under real load, not synthesised. The most consequential results, collected:

* **QUIC v1 cover is deleted in transit** on two Iranian carriers: 0/200 delivered, while v2 and
  DTLS both delivered 200/200. Use `quic2` or `dtls`. (§5.2)
* **UDP is ~3× faster than TCP** here, and TCP+TLS is volumetrically throttled to a blackhole
  within ~30 s however well it is disguised. (§6.2, §10.2)
* **The UDP path has correlated blackouts** — ~94 ms dead every ~345 ms, identical across four
  independent flows — that no amount of port hopping can dodge, while ICMP crosses cleanly.
  (§6.3)
* **Port 443 rides a DPI inspection detour** worth ~64 ms; moving to an unwatched high port cut
  tunnel RTT from ~82 ms to ~18 ms. (§12)
* **Oversized socket buffers cost five times the latency** for 9 % throughput on a single
  carrier; under multipath, undersized ones cost 6 % of all packets to host-side overflow.
  (§10.3)
* **Multipath aggregate:** 2 GiB over 32 concurrent flows at 585 Mbit/s with zero auth failures
  and zero replay drops; blocking both UDP carriers at once cost 0.00 % loss on the overlay.
* **Per-carrier cost** under load, sender side: ~0.65 of a core for 290–410 Mbit/s on the UDP and
  TCP carriers; ICMP is the most expensive at ~0.96 of a core for 275 Mbit/s, having no GSO/GRO
  to fall back on.

---

## 16. File map

| File | Purpose |
|---|---|
| `tunnel.go` | protocol and crypto core, OS-independent and unit-tested |
| `cipher.go` | suite selection and CPU capability detection |
| `csprng.go` | buffered randomness, so the packet path never calls `crypto/rand` |
| `hkdf.go` | HKDF-SHA256 (RFC 5869) |
| `obfs.go` | QUIC-shaped wire obfuscation — headers, header protection, size shaping |
| `quicinit.go` | synthetic QUIC handshake (RFC 9001 Initials, TLS ClientHello, SNI reader) |
| `dtlsobfs.go` | DTLS 1.2 record disguise and its handshake cover |
| `tls.go` | TLS record shaping for the TCP carrier |
| `main.go` | TUN device, UDP/TCP carriers, main loops (Linux) |
| `offload.go` | UDP GSO/GRO, batched TUN reads, TUN attach ordering |
| `mmsg.go` | `sendmmsg`/`recvmmsg` plumbing for the ICMP carrier |
| `icmp.go` | the ICMP carrier: ping-payload transport, BPF filter, identifier rotation, decoy-ping desync |
| `pacer.go` | optional carrier rate shaping |
| `probe.go` | in-tunnel round-trip probes |
| `dpilog.go` | DPI and probe observability, reporting |
| `desync.go` | native in-process fake injector |
| `junk.go` | flow-start cover traffic |
| `hop.go` | keyed synchronised port hopping |
| `split.go` | IP-fragmentation of the disposable fakes |
| `tcprotate.go` | TCP carrier connection rotation |
| `reverse.go` | reverse UDP: which end dials, the passive listener, the hello gate |
| `ws.go` | WebSocket carrier: RFC 6455 framing, the upgrade, admission, TLS sniffing, `ws-check` |
| `wscarrier.go` | WebSocket carrier runtime: dial loop with watchdog and rotation, accept loop |
| `pprof_on.go` / `pprof_off.go` | profiling endpoints, behind the `pprof` build tag |
| `aestun.sh` | installer, management TUI, live monitor, zapret, tuning, build, NFQUEUE helper |
| `aestun-mp.sh` | multi-protocol supervisor: health probing, failover, ECMP (§7) |
| `dokodemo.sh` | optional port-forwarding helper |
| `aestun.service` | reference systemd unit |
| `config.server-a.json` / `config.server-b.json` / `config.icmp.json` | example configs |
| `aestun` | the build for this host — run it straight out of the directory |
| `aestun-linux-amd64` / `aestun-linux-arm64` | the same program, cross-built |
| `SHA256SUMS` | their checksums, the Go version and flags used, and a source fingerprint |

---

## 17. Multi-location — one foreign server, many Iran servers

One `aestun` process is one tunnel between two servers. A foreign server that serves several
Iran servers (or an Iran server with several foreign exits) simply runs several processes,
and that is the right shape: every location has its own key, TUN device, subnet, stats file
and DPI log, so a location that is throttled or blocked cannot touch the others. What this
section adds is the management layer, so a second location is no longer a hand-written
systemd unit next to the stock one.

```
                         ┌──────────────┐
   Iran server A  ◀──────┤              │        location "default"  tun0  10.8.0.0/24   :9090
                         │   foreign    │
   Iran server B  ◀──────┤   server     │        location "ir2"      tun1  10.8.10.0/24  :9091
                         │              │
   Iran server C  ◀──────┤              │        location "ir3"      tun2  10.8.1.0/24   :9092
                         └──────────────┘
```

The stock tunnel (`config.json` / `aestun.service`) is the location named **default** and is
not changed by any of this. Every additional location has a **name** and lives in:

| what | where |
|---|---|
| config | `/etc/aestun/peers/NAME.json` — same schema as `config.json` |
| service | `aestun@NAME.service` — one systemd template, N instances |
| stats | `/run/aestun/peers/NAME/stats.json` |
| DPI log | `/var/log/aestun/peers/NAME/dpi.jsonl` |
| zapret | `aestun-zapret@NAME.service`, armed by the marker `peers/NAME.zapret`; queues that location's carrier into the shared `nfqws` started by the stock tunnel's zapret module |
| shaping | `peers/NAME.shape` — a rate in Mbit/s, applied as `cake` on that location's TUN on every start |

A location has the **same name on both ends**. On an Iran server that has one foreign exit,
the far side of a location is usually its stock tunnel (`config.json`); the tools accept
that and fall back to it when `peers/NAME.json` does not exist there.

### 17.1 Commands

```
sudo ./aestun.sh peer list                  every location: state, loss, RTT, shaping
sudo ./aestun.sh peer add [NAME]            wizard — port, subnet, TUN and key are chosen for
                                            you; wire settings are copied from config.json;
                                            then optionally installs the far end over SSH
sudo ./aestun.sh peer push NAME [HOST]      (re)install this location on the far end over SSH:
                                            copies the binary + manager, writes the mirrored
                                            config (roles and tunnel addresses swapped), starts it
sudo ./aestun.sh peer import NAME FILE      what push runs on the far end; also for by-hand setups
sudo ./aestun.sh peer del NAME              remove a location from this host (far end untouched)
sudo ./aestun.sh peer sweep [NAME]          UDP sweep through the tunnel to find the path's loss
                                            cliff (§17.2); suggests a shape value
sudo ./aestun.sh peer shape NAME <Mbit|off> cake shaping on that location's TUN
sudo ./aestun.sh peer zapret NAME on|off    per-location NFQUEUE rules
sudo ./aestun.sh peer start|stop|restart|status|log NAME
sudo ./aestun.sh peer menu NAME             the whole management menu (dashboard, DPI log,
                                            anti-DPI, auto-test, service) pointed at that location
```

`p` in the menu opens the same thing interactively. Adding a location from the foreign
server end to end is one command:

```
sudo ./aestun.sh peer add ir3
  This server's role for 'ir3' (a = Iran/inside, b = foreign/outside) [b]:
  Far end public IP / host: 185.126.x.x
  UDP port (same on both ends) [9092]:
  Tunnel subnet (/24) [10.8.1.0/24]:
  TUN device [tun2]:
  Shared key (Enter = generate):
  [OK] location 'ir3' started: aestun@ir3.service
  Configure the far end over SSH now (copies binary + config, starts it) [Y/n]: y
  ...
  [OK] tunnel 'ir3' is up: 10.8.1.1 answers through it.
```

The reverse topology — several Iran servers into one foreign server, or one Iran server with
several foreign exits — is the same thing seen from the other side: each pair is a location on
both hosts. Run `peer add` from whichever end has SSH access to the other.

### 17.2 Per-location shaping — why it exists

Paths into Iran differ per datacentre. Measured on this project's own servers on the same
night: one Iran path carried 400 Mbit/s with no loss, the other had a **policer at ~150
Mbit/s** — 160 Mbit/s offered delivered 127 with 20 % loss, 220 delivered 170 with 23 %.
TCP cannot see a policer; it probes until it loses packets and then sits permanently on the
wrong side of the cliff, so every user on that location saw loss and retransmits whenever
one of them started a download. `peer sweep` finds the cliff (UDP at rising rates through the
tunnel, iperf3 on both ends), and `peer shape` puts a `cake` qdisc on that location's TUN just
under it: `flows` shares the rate fairly per inner connection, and its AQM keeps the queue
short. On the policed path this went from 79 Mbit/s with 19 785 retransmits and 325 ms ping
under load to 96 Mbit/s, 1 retransmit and 82 ms. The `rate_mbps` pacer in the daemon (§10)
does the same thing one layer lower, without the per-flow fairness; with both set, keep the
cake rate a few Mbit/s below `rate_mbps` so the pacer never has to drop at the TUN ring.

### 17.3 What `upgrade` and `uninstall` do with locations

`upgrade` refreshes the two templates and restarts every location after the stock tunnel.
`uninstall` stops and removes every location (units, rules, TUN devices) together with the
stock tunnel. The far ends are never touched by either.
