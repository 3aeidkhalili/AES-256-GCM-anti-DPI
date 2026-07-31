# aestun — AES-256-GCM anti-DPI server-to-server tunnel

A small, dependency-free tunnel between two Ubuntu servers. It carries IP traffic
over a TUN interface with **private/local IPs**, encrypts every packet with
**AES-256-GCM**, and is designed so the wire traffic is **indistinguishable from
random data** — no handshake, no fixed header, no protocol signature for DPI to match.

Written in pure Go (standard library only) → a single static binary, no runtime deps.

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
| Confidentiality + integrity | AES-256-GCM (AEAD); tampered packets are dropped |
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
| `obfs.go` | QUIC-shaped wire obfuscation — headers, header protection, size shaping |
| `quicinit.go` | synthetic QUIC handshake (RFC 9001 Initial packets + TLS ClientHello) |
| `main.go` | Linux TUN device, UDP/TCP carriers, main loop (build-tagged `linux`) |
| `tunnel_test.go` / `obfs_test.go` | unit tests (`go test`) |
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
| `listen` | `0.0.0.0:51820` | local UDP listen address |
| `peer` | — | the other server `host:port` (learned from traffic if empty) |
| `transport` | `udp` | carrier: `udp` or `tcp`. **Prefer udp** — see the note below |
| `obfs` | `none` | `quic` presents the carrier as a QUIC connection (section 7) |
| `sni` | `www.cloudflare.com` | server name in the synthetic handshake (`obfs: quic` only) |
| `shape` | `true` | quantise datagram sizes onto buckets (`obfs: quic` only) |
| `tun_name` | `tun0` | TUN interface name |
| `local_ip` | `10.8.0.x/24` | this server's tunnel IP (CIDR) |
| `peer_ip` | `10.8.0.y` | the other server's tunnel IP (used by the ping test) |
| `mtu` | `1300` | interface MTU |
| `txqueuelen` | `1000` | interface tx queue length |
| `pad_max` | `64` | max random padding bytes per packet (0 disables; anti-DPI) |
| `rekey_interval` | `3600` | key-rotation seconds (0 = static key) |
| `keepalive` | `25` | keepalive seconds (0 disables) |
| `rcvbuf` | `8388608` | UDP socket receive buffer (bytes); absorbs bursts so the kernel doesn't drop |
| `sndbuf` | `8388608` | UDP socket send buffer (bytes) |
| `manage_ip` | `true` | let the daemon run the `ip` commands |
| `stats_path` | `/run/aestun/stats.json` | monitor stats file (empty disables) |

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

## 6. Network optimization (Ubuntu tuning)

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

## 7. QUIC obfuscation (`obfs: quic`)

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

## 8. zapret module (optional DPI bypass)

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

## 9. Manual deployment (without the wizard)

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

## 10. Troubleshooting

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
* **Logs** → `journalctl -u aestun -f`.

---

## 11. Building & testing

```bash
go test ./...                 # protocol/crypto unit tests (run natively, any OS)
./aestun.sh build amd64       # -> aestun-linux-amd64
./aestun.sh build arm64       # -> aestun-linux-arm64
```
