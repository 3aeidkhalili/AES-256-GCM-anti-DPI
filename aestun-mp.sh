#!/usr/bin/env bash
# =============================================================================
#  aestun-mp — multi-protocol (multipath) supervisor for the aestun tunnel
# =============================================================================
#
#  WHY THIS EXISTS
#
#  main.go picks ONE carrier at startup (switch cfg.Transport) and runs it for the
#  life of the process, so a single aestun cannot spread traffic over several
#  protocols. What it CAN do is run several times over, each instance on its own
#  TUN device, port and /30. This supervisor does exactly that and then bonds the
#  instances together at the routing layer:
#
#      application  ->  10.10.0.x  (stable overlay address, never changes)
#                          |
#                   +------+------+------+------+
#                   |      |      |      |      |
#                udp/quic2 udp/dtls tcp/tls  icmp     <- four independent carriers
#                   |      |      |      |      |
#                   +------+------+------+------+
#                          |
#                       peer server
#
#  Applications only ever talk to the overlay address. Which protocol actually
#  carries a packet is this supervisor's decision, and it can change at any moment
#  without the application noticing.
#
#  TWO MODES
#    failover   one carrier at a time, in priority order. The first responsive
#               protocol wins; when it stops answering the next one takes over.
#    multipath  every healthy carrier at once, as a weighted ECMP route. Linux
#               hashes per FLOW (not per packet), so one TCP connection stays on
#               one protocol while concurrent connections spread across all of
#               them. Measured on the live pair: 622 MiB over 16 flows split
#               41/13/32/15 % across quic2/tls/icmp/dtls.
#
#  WHY AN OVERLAY /32 RATHER THAN JUST MOVING THE DEFAULT ROUTE
#  Each carrier has its own /30, so its address dies with it. A separate /32 on
#  lo is the only address that survives a carrier switch, which is what lets an
#  established application keep one destination while the path underneath changes.
#
#  BOTH ENDS MUST AGREE. The path table below is deterministic: given the role
#  (a/b) from /etc/aestun/config.json it derives every port, device and address.
#  Run `aestun-mp.sh setup` on BOTH servers and the two sides match by construction.
#
#  Usage:  aestun-mp.sh <command>          (see `aestun-mp.sh help`)
# =============================================================================
set -uo pipefail

CONF="${AESTUN_CONF:-/etc/aestun/config.json}"
PATHDIR="/etc/aestun/paths"
STATEDIR="/run/aestun-mp"
BIN="${AESTUN_BIN:-/usr/local/bin/aestun}"
SELF="$(readlink -f "$0")"
SINK_PORT=51821

# Overlay addresses — the stable, protocol-independent identity of each server.
OVERLAY_A="10.10.0.1"
OVERLAY_B="10.10.0.2"

# Health hysteresis: how many consecutive results flip a carrier's state. Asymmetric
# on purpose — drop a bad carrier fast, re-admit a recovered one slowly, so a link
# that is flapping does not drag flows back onto it every few seconds.
FAIL_THRESHOLD=2
RISE_THRESHOLD=3
# Timings are chosen for how long a carrier stays black before traffic moves off it:
# worst case is FAIL_THRESHOLD x (probe pass + interval). Probes run CONCURRENTLY
# (see main_sender), so a pass costs one timeout rather than the sum of them — with
# them serialised, one blackholed carrier stretched every pass to ~10s and a real
# blocked-protocol failover measured 20.6s of downtime on the live pair.
PROBE_INTERVAL="${AESTUN_MP_INTERVAL:-2}"
PROBE_COUNT=3
PROBE_WAIT=1

C=$'\033[36m'; G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'
W=$'\033[37m'; D=$'\033[2m'; BOLD=$'\033[1m'; N=$'\033[0m'
msg()  { printf '%s[+]%s %s\n' "$G" "$N" "$*"; }
warn() { printf '%s[!]%s %s\n' "$Y" "$N" "$*"; }
err()  { printf '%s[x]%s %s\n' "$R" "$N" "$*" >&2; }
hdr()  { printf '\n%s== %s ==%s\n' "$BOLD" "$*" "$N"; }
log()  { printf '%s %s\n' "$(date '+%F %T')" "$*"; }

# -----------------------------------------------------------------------------
#  THE PROTOCOL TABLE  —  name|transport|obfs|port|tun|a_ip|b_ip|prefixlen
# -----------------------------------------------------------------------------
#  Four carriers, in failover priority order. Any three satisfy the "at least 3
#  protocols" requirement; all four are independent at the wire level, which is
#  the point — a DPI box that learns to drop one has not learned the others.
#
#  "quic" deliberately keeps the port, device and subnet the single-path install
#  already uses (1376 / tun0 / 10.8.0.0/24), so anything already pointed at
#  10.8.0.2 keeps working after the switch to multipath.
#
#  MTU is forced identical across every carrier (see gen_path_config). Under ECMP
#  the kernel picks a nexthop per flow with no idea that one carrier might fit
#  fewer bytes than another, so a smaller MTU on one path would blackhole exactly
#  the flows hashed onto it — a bug that only shows up under load.
PROTO_TABLE=(
  "quic|udp|quic2|1376|tun0|10.8.0.1|10.8.0.2|24"
  "dtls|udp|dtls|1378|mpdtls|10.9.1.5|10.9.1.6|30"
  "tls|tcp|quic|1377|mptls|10.9.1.9|10.9.1.10|30"
  "icmp|icmp|none|0|mpicmp|10.9.1.13|10.9.1.14|30"
)

PROTOCOLS=(); for _e in "${PROTO_TABLE[@]}"; do PROTOCOLS+=("${_e%%|*}"); done

# -----------------------------------------------------------------------------
#  Field lookup.
#
#  This used to be `_row` + `_f`, two functions called through $( ) — which means a
#  fork per field, per protocol, per pass. With four protocols and a dozen field
#  reads each, one supervisor pass forked about a hundred times; at the 2 s probe
#  interval that measured at 25-27% of a core, permanently, on both live servers,
#  while the four aestun processes it supervises used 0.35% between them. The
#  supervisor cost seventy times the thing it was supervising.
#
#  The table is constant, so it is expanded once into associative arrays at load
#  time and read as ${P_TUN[$n]} thereafter: no subshell, no fork, same values.
#  The p_* functions are kept for the interactive commands, where a fork does not
#  matter; the daemon's hot path indexes the arrays directly.
# -----------------------------------------------------------------------------
declare -A P_TRANS P_OBFS P_PORT P_TUN P_PLEN P_A_IP P_B_IP
for _e in "${PROTO_TABLE[@]}"; do
  IFS='|' read -r _n _t _o _p _d _a _b _l <<<"$_e"
  P_TRANS[$_n]="$_t"; P_OBFS[$_n]="$_o"; P_PORT[$_n]="$_p"; P_TUN[$_n]="$_d"
  P_A_IP[$_n]="$_a";  P_B_IP[$_n]="$_b";  P_PLEN[$_n]="$_l"
done
unset _e _n _t _o _p _d _a _b _l

# -----------------------------------------------------------------------------
#  local identity, read from the single-path config that setup already produced
# -----------------------------------------------------------------------------
#  Read with bash's own regex rather than python3. This is called once at load,
#  but `role` was reached from p_local_ip/p_peer_ip on every field lookup, so on
#  any code path that did not warm the cache first it was a 35 ms interpreter
#  start-up per call. A JSON string field is a regex either way.
_json_str() { # _json_str FILE KEY -> the string value, or nothing
  local line
  [[ -r "$1" ]] || return 1
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" =~ \"$2\"[[:space:]]*:[[:space:]]*\"([^\"]*)\" ]]; then
      printf '%s' "${BASH_REMATCH[1]}"; return 0
    fi
  done < "$1"
  return 1
}
_json_num() { # _json_num FILE KEY -> the integer value, or 0
  local line
  if [[ -r "$1" ]]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
      if [[ "$line" =~ \"$2\"[[:space:]]*:[[:space:]]*([0-9]+) ]]; then
        printf '%s' "${BASH_REMATCH[1]}"; return 0
      fi
    done < "$1"
  fi
  printf '0'; return 1
}

_ROLE=""; _PEERPUB=""
role() {
  if [[ -z "$_ROLE" ]]; then
    _ROLE="$(_json_str "$CONF" role)"; : "${_ROLE:=a}"
  fi
  printf '%s' "$_ROLE"
}
peer_pub() {  # the peer's PUBLIC address, with any carrier port stripped
  if [[ -z "$_PEERPUB" ]]; then
    local p; p="$(_json_str "$CONF" peer)"
    # host:port, [v6]:port or a bare address (the icmp carrier has no port at all)
    if [[ "$p" == \[*\]* ]]; then p="${p#\[}"; p="${p%%\]*}"
    elif [[ "$p" == *:*:* ]]; then :                 # bare IPv6, no port
    elif [[ "$p" == *:* ]]; then p="${p%:*}"
    fi
    _PEERPUB="$p"
  fi
  printf '%s' "$_PEERPUB"
}

# ROLE_IS_A is resolved once and drives every local/peer address lookup below.
ROLE_IS_A=1; [[ "$(role)" == a ]] || ROLE_IS_A=0
if (( ROLE_IS_A )); then declare -n P_LOCAL=P_A_IP; declare -n P_PEER=P_B_IP
else                     declare -n P_LOCAL=P_B_IP; declare -n P_PEER=P_A_IP; fi

_row() { local n="$1" e; for e in "${PROTO_TABLE[@]}"; do [[ "${e%%|*}" == "$n" ]] && { printf '%s' "$e"; return 0; }; done; return 1; }
p_transport() { printf '%s' "${P_TRANS[$1]-}"; }; p_obfs() { printf '%s' "${P_OBFS[$1]-}"; }
p_port()      { printf '%s' "${P_PORT[$1]-}"; };  p_tun()  { printf '%s' "${P_TUN[$1]-}"; }
p_plen()      { printf '%s' "${P_PLEN[$1]-}"; }
p_local_ip()  { printf '%s' "${P_LOCAL[$1]-}"; }
p_peer_ip()   { printf '%s' "${P_PEER[$1]-}"; }
p_conf()      { printf '%s/%s.json' "$PATHDIR" "$1"; }
p_unit()      { printf 'aestun-path@%s.service' "$1"; }
if (( ROLE_IS_A )); then OVERLAY_LOCAL="$OVERLAY_A"; OVERLAY_PEER="$OVERLAY_B"
else                     OVERLAY_LOCAL="$OVERLAY_B"; OVERLAY_PEER="$OVERLAY_A"; fi
overlay_local() { printf '%s' "$OVERLAY_LOCAL"; }
overlay_peer()  { printf '%s' "$OVERLAY_PEER"; }

need_root() { [[ "$(id -u)" == 0 ]] || { err "run as root."; exit 1; }; }
need_base() { [[ -f "$CONF" ]] || { err "$CONF not found — run the normal aestun setup first."; exit 1; }; }

# =============================================================================
#  setup — generate one aestun config per protocol, plus the units
# =============================================================================
gen_path_config() {
  local name="$1"
  python3 - "$CONF" "$(p_conf "$name")" "$name" "$(p_transport "$name")" "$(p_obfs "$name")" \
           "$(p_port "$name")" "$(p_tun "$name")" "$(p_local_ip "$name")/$(p_plen "$name")" \
           "$(p_peer_ip "$name")" "$(peer_pub)" <<'PY'
import json,sys
base,out,name,transport,obfs,port,tun,local_ip,peer_ip,peer_pub = sys.argv[1:11]
c=json.load(open(base))
c["transport"]=transport; c["obfs"]=obfs
c["tun_name"]=tun; c["local_ip"]=local_ip; c["peer_ip"]=peer_ip
c["stats_path"]="/run/aestun/stats-%s.json"%name
c["manage_ip"]=True
# The ICMP carrier has no ports: give it a bare peer and let listen stay unused.
if transport=="icmp":
    c["listen"]="0.0.0.0:0"; c["peer"]=peer_pub
else:
    c["listen"]="0.0.0.0:%s"%port; c["peer"]="%s:%s"%(peer_pub,port)

# Every carrier gets the SAME MTU. Under ECMP the kernel has no idea the carriers
# differ, so an MTU that varies per path silently blackholes whichever flows hash
# onto the smaller one.
c["mtu"]=int(c.get("mtu") or 1300)

# Receive buffer, raised from the single-path default.
#
# aestun's 2 MiB default is measured for ONE carrier, where a socket buffer is a queue
# and a bigger one buys peak throughput with latency. Multipath breaks that assumption:
# four carriers share one host, their bursts arrive together, and 2 MiB is about 24 ms of
# buffer at the rate this link runs. Measured on the live pair, 32 flows offering 2 GiB
# across all four carriers, counted on the 2-core receiver:
#
#   rcvbuf   goodput   UDP RcvbufErrors   raw-socket drops   ping across the tunnel
#    2 MiB   553 Mb/s   28442  (6.14%)        33190          10.0% loss,  83 ms avg
#    4 MiB   585 Mb/s    2512  (0.56%)         2492           1.4% loss, 109 ms avg
#    8 MiB   556 Mb/s     421  (0.08%)             0          4.3% loss, 130 ms avg
#
# The NIC counters were zero throughout: every one of those packets crossed the network
# and was then thrown away on the host for want of a reader. 4 MiB removes the great bulk
# of that for a bounded latency cost and, because the drops were themselves costing
# retransmissions, it is also the fastest of the three. Raise it to 8 MiB if this link
# only carries bulk; the kernel clamps to net.core.rmem_max either way.
#
# sndbuf is deliberately left alone: every drop measured was on receive, and oversizing
# the send side is bufferbloat with nothing to show for it.
if int(c.get("rcvbuf") or 0) < 4194304:
    c["rcvbuf"]=4194304

# Each instance writes its own DPI log, or they interleave into one file and the
# per-carrier verdict becomes unreadable.
if isinstance(c.get("dpi_log"),dict) and c["dpi_log"].get("enabled"):
    c["dpi_log"]=dict(c["dpi_log"],path="/var/log/aestun/dpi-%s.jsonl"%name)

# Anti-DPI method blocks are per-carrier and off by default here: the supervisor's
# job is to compare carriers, and a method enabled on one end only would look like
# a dead carrier rather than a misconfiguration.
for b in ("desync","junk","hop","split","tcp_rotate"):
    c.setdefault(b,{})["enabled"]=False

# The ICMP sub-block MUST be byte-identical on both servers. mimic_ping prepends a
# ping(8)-style timeval to the plaintext (icmp.go), so if one end mimics and the
# other does not, every packet crosses the network intact and then fails AEAD auth
# — the carrier looks "up" from the process log and passes zero traffic. This was
# live on this very pair (Iran mimic_ping=true, foreign false) and is why the icmp
# carrier had never worked. Pin it here rather than inheriting it.
c["icmp"]=dict(c.get("icmp",{}), mimic_ping=True, kernel_filter=True,
               suppress_replies=True, id_pool=1, id_rotate_sec=60, batch=32, readers=0)
json.dump(c,open(out,"w"),indent=1)
PY
  chmod 600 "$(p_conf "$name")"
}

install_units() {
  cat >/etc/systemd/system/aestun-path@.service <<'EOF'
[Unit]
Description=aestun multipath carrier %i
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/aestun -config /etc/aestun/paths/%i.json
Restart=always
RestartSec=2
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
RuntimeDirectory=aestun
# Every carrier unit declares the same RuntimeDirectory. Without this, stopping any
# one of them deletes /run/aestun and blinds the stats of all the others.
RuntimeDirectoryPreserve=yes
LogsDirectory=aestun
ProtectSystem=full
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF

  cat >/etc/systemd/system/aestun-mp-sink.service <<EOF
[Unit]
Description=aestun multipath data sink (receives send_data payloads)
After=network-online.target

[Service]
Type=simple
ExecStart=$SELF sink
Restart=always
RestartSec=2
ProtectSystem=full
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF

  cat >/etc/systemd/system/aestun-mp.service <<EOF
[Unit]
Description=aestun multipath supervisor (health probing, failover, ECMP)
After=network-online.target

[Service]
Type=simple
ExecStart=$SELF daemon
Restart=always
RestartSec=5
ProtectSystem=full
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
}

cmd_setup() {
  need_root; need_base
  mkdir -p "$PATHDIR" "$STATEDIR" /run/aestun; chmod 700 "$PATHDIR"
  [[ -x "$BIN" ]] || { err "$BIN not found."; exit 1; }
  hdr "Generating carrier configs (role $(role), peer $(peer_pub))"
  local n
  for n in "${PROTOCOLS[@]}"; do
    gen_path_config "$n"
    printf '  %-6s %-5s/%-6s port %-5s dev %-7s %s -> %s\n' \
      "$n" "$(p_transport "$n")" "$(p_obfs "$n")" "$(p_port "$n")" "$(p_tun "$n")" \
      "$(p_local_ip "$n")" "$(p_peer_ip "$n")"
  done
  install_units
  # L4 hashing: without it the kernel hashes on src/dst address only, and since every
  # overlay flow shares one address pair EVERY flow lands on the same carrier — ECMP
  # that silently degrades to a single path.
  sysctl -qw net.ipv4.fib_multipath_hash_policy=1 2>/dev/null
  printf 'net.ipv4.fib_multipath_hash_policy=1\n' >/etc/sysctl.d/99-aestun-mp.conf
  msg "Configs in $PATHDIR, units installed."
  msg "Run the SAME command on the other server, then: $0 start"
}

# =============================================================================
#  carrier lifecycle
# =============================================================================
overlay_up() {
  local ov; ov="$(overlay_local)"
  ip addr show dev lo 2>/dev/null | grep -q "inet $ov/32" || ip addr add "$ov/32" dev lo 2>/dev/null
}
overlay_down() { ip addr del "$(overlay_local)/32" dev lo 2>/dev/null; }

cmd_start() {
  need_root; need_base
  [[ -f "$(p_conf "${PROTOCOLS[0]}")" ]] || { err "no carrier configs — run: $0 setup"; exit 1; }
  # The single-path service owns tun0/1376, which the quic carrier also uses. Running
  # both means two processes fighting over the same device and port, so stand the old
  # one down first. `disable` (not just stop) keeps it from racing us at next boot.
  if systemctl is-enabled aestun >/dev/null 2>&1 || systemctl is-active aestun >/dev/null 2>&1; then
    warn "stopping the single-path aestun.service (multipath takes over tun0/1376)"
    systemctl disable --now aestun >/dev/null 2>&1
  fi
  overlay_up
  local n
  for n in "${PROTOCOLS[@]}"; do systemctl enable --now "$(p_unit "$n")" >/dev/null 2>&1; done
  systemctl enable --now aestun-mp-sink.service >/dev/null 2>&1
  msg "Carriers started: ${PROTOCOLS[*]}"
  sleep 4
  systemctl enable --now aestun-mp.service >/dev/null 2>&1
  msg "Supervisor started (mode: $(get_mode)). Overlay: $(overlay_local) -> $(overlay_peer)"
}

cmd_stop() {
  need_root
  systemctl disable --now aestun-mp.service >/dev/null 2>&1
  local n; for n in "${PROTOCOLS[@]}"; do systemctl disable --now "$(p_unit "$n")" >/dev/null 2>&1; done
  systemctl disable --now aestun-mp-sink.service >/dev/null 2>&1
  ip route del "$(overlay_peer)/32" 2>/dev/null
  overlay_down
  msg "Multipath stopped."
}

cmd_revert() {   # back to the stock single-path tunnel, exactly as before
  need_root
  cmd_stop
  systemctl enable --now aestun >/dev/null 2>&1
  msg "Reverted to the single-path aestun.service."
}

# =============================================================================
#  send_data — push real payload over ONE named protocol and time it
# =============================================================================
#  Path selection is the destination address: each carrier's peer /30 address is
#  reachable only through that carrier's own device, so addressing the payload at
#  it pins the transfer to exactly that protocol. No policy routing needed, and it
#  measures the carrier the application would actually get.
#
#  The clock stops when the RECEIVER acknowledges the last byte, not when the local
#  socket accepts it: a write returns as soon as the bytes are in the local send buffer,
#  so timing the write alone charges a multi-MiB transfer with only the part that did
#  not fit — on this pair that read as ~240 Mbit/s on every carrier, which was the
#  buffer draining, not the link.
#
#  send_data PROTO [FILE|SIZE_MB]   -- FILE sends that file, a bare number sends
#                                      that many MiB of zeros, default 8.
send_data() {
  local name="${1:?send_data PROTO [FILE|SIZE_MB]}" src="${2:-8}"
  _row "$name" >/dev/null || { err "unknown protocol: $name"; return 2; }
  local pip; pip="$(p_peer_ip "$name")"
  local tmp="" bytes
  if [[ -f "$src" ]]; then
    bytes="$(stat -c%s "$src")"
  else
    [[ "$src" =~ ^[0-9]+$ ]] || { err "second argument must be a file or a size in MiB"; return 2; }
    bytes=$(( src * 1048576 )); tmp="$STATEDIR/payload.$$"; mkdir -p "$STATEDIR"
    head -c "$bytes" /dev/zero >"$tmp"; src="$tmp"
  fi
  local out rc
  out="$(python3 - "$pip" "$SINK_PORT" "$src" <<'PY' 2>&1
import socket,sys,time
dst,port,path = sys.argv[1],int(sys.argv[2]),sys.argv[3]
try:
    s=socket.create_connection((dst,port),timeout=20)
except Exception as e:
    print("ERR connect: %s"%e); sys.exit(7)
s.settimeout(180)
n=0
try:
    t0=time.monotonic()
    with open(path,"rb") as f:
        while True:
            b=f.read(262144)
            if not b: break
            s.sendall(b); n+=len(b)
    s.shutdown(socket.SHUT_WR)          # tell the sink nothing more is coming
    ack=b""
    while b"\n" not in ack:             # the sink answers only after the last byte lands
        c=s.recv(64)
        if not c: break
        ack+=c
    t1=time.monotonic()
    s.close()
except Exception as e:
    print("ERR transfer: %s"%e); sys.exit(8)
got=0
try: got=int(ack.split()[0])
except Exception: pass
print("OK %d %d %.6f"%(n,got,t1-t0))
PY
)"; rc=$?
  [[ -n "$tmp" ]] && rm -f "$tmp"
  if (( rc != 0 )) || [[ "$out" != OK* ]]; then
    (( rc == 7 )) && err "$name: no sink at $pip:$SINK_PORT (carrier down, or the peer's sink is not running)" \
                  || err "$name: ${out:-transfer failed}"
    return 1
  fi
  local sent got secs; read -r _ sent got secs <<<"$out"
  # A short count means the carrier dropped the tail. Report that rather than dividing
  # the full offered size by the elapsed time and calling the result throughput.
  [[ "$got" == "$sent" ]] || warn "$name: receiver acknowledged $got of $sent bytes — carrier lost the tail"
  awk -v b="$got" -v s="$secs" -v p="$name" 'BEGIN{
    if (s<=0) s=0.000001
    printf "%-6s delivered %.1f MiB in %.2f s  =  %.1f Mbit/s\n", p, b/1048576, s, b*8/s/1e6}'
  return 0
}

cmd_sink() {   # the receiving half of send_data; runs as aestun-mp-sink.service
  exec python3 -c '
import socket,threading,sys
port=int(sys.argv[1])
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",port)); s.listen(64)
def h(c):
    n=0
    try:
        c.settimeout(180)
        while True:
            b=c.recv(262144)
            if not b: break
            n+=len(b)
        # Acknowledge only once every byte has been read. This is what lets the sender
        # time real delivery instead of timing its own socket buffer.
        c.sendall(b"%d\n"%n)
    except Exception: pass
    finally:
        try: c.close()
        except Exception: pass
while True:
    try:
        c,_=s.accept(); threading.Thread(target=h,args=(c,),daemon=True).start()
    except Exception: pass
' "$SINK_PORT"
}

# =============================================================================
#  probe_protocol — is this carrier actually passing traffic right now?
# =============================================================================
#  Sets PROBE_LOSS / PROBE_RTT / PROBE_NOTE. Returns 0 when the carrier is usable.
#
#  Two independent signals, because either one alone lies:
#    * ping across the carrier's own /30 — the end-to-end truth, but it cannot say
#      WHY a dead carrier is dead;
#    * the instance's own auth_fail counter — rising auth_fail with traffic flowing
#      means the two ends disagree on the wire format (mismatched key, obfs, or the
#      mimic_ping trap), which no amount of failover will fix and which otherwise
#      looks exactly like a network drop.
#  Everything below the ping is deliberately fork-free: ping is the one process this has
#  to start, and the sed/head/awk/python3 pipeline around it used to cost several times
#  more CPU than the measurement itself.
probe_protocol() {
  local name="$1"; PROBE_LOSS=100; PROBE_RTT="-"; PROBE_NOTE=""
  [[ -n "${P_TUN[$name]-}" ]] || return 2
  local pip="${P_PEER[$name]}" dev="${P_TUN[$name]}"
  # /sys is the same answer `ip link show` gives, without spawning iproute2.
  [[ -d "/sys/class/net/$dev" ]] || { PROBE_NOTE="no-device"; return 1; }

  local out; out="$(ping -c "$PROBE_COUNT" -i 0.3 -W "$PROBE_WAIT" -q "$pip" 2>/dev/null)"
  [[ "$out" =~ ([0-9]+(\.[0-9]+)?)%\ packet\ loss ]] && PROBE_LOSS="${BASH_REMATCH[1]}"
  [[ "$out" =~ =\ [0-9.]+/([0-9.]+)/ ]] && PROBE_RTT="${BASH_REMATCH[1]}"
  : "${PROBE_LOSS:=100}" "${PROBE_RTT:=-}"

  local af pv=0 prev="$STATEDIR/authfail.$name"
  af="$(_json_num "/run/aestun/stats-${name}.json" auth_fail)"
  [[ -r "$prev" ]] && read -r pv <"$prev"; [[ "$pv" =~ ^[0-9]+$ ]] || pv=0
  printf '%s' "$af" >"$prev"
  if (( af > pv + 5 )); then
    PROBE_NOTE="auth_fail+$(( af - pv )) (wire-format mismatch between the two ends)"
  fi

  # Usable when anything at all came back. Integer part only: 99.9% loss is still a
  # carrier that answers, 100% is not.
  (( ${PROBE_LOSS%%.*} < 100 ))
}

# =============================================================================
#  routing — turn a set of healthy carriers into a route to the overlay peer
# =============================================================================
#  Weight follows RTT and loss so the better carriers take proportionally more
#  flows. Clamped to 1..16: weight 0 would remove the nexthop entirely, and a huge
#  spread would starve a usable backup of the occasional flow that keeps it warm.
#  Integer arithmetic in bash rather than a fork to awk: this runs once per healthy
#  carrier per pass. w = (200/(rtt+5)) * (1 - loss/100), computed in tenths so the
#  rounding matches what the float version produced, then clamped to 1..16.
#  Sets PATH_WEIGHT rather than printing it, so the caller does not fork a subshell
#  per carrier per pass just to read one small integer back.
path_weight() {
  local rtt="${1%%.*}" loss="${2%%.*}" w10
  [[ "$rtt"  =~ ^[0-9]+$ ]] && (( rtt > 0 )) || rtt=100
  [[ "$loss" =~ ^[0-9]+$ ]] || loss=0
  (( loss > 100 )) && loss=100
  w10=$(( 20 * (100 - loss) / (rtt + 5) ))
  PATH_WEIGHT=$(( (w10 + 5) / 10 ))
  (( PATH_WEIGHT < 1 )) && PATH_WEIGHT=1
  (( PATH_WEIGHT > 16 )) && PATH_WEIGHT=16
}

apply_route() {   # apply_route "name:rtt:loss ..."
  local ovp; ovp="$(overlay_peer)"
  local -a spec=(); local entry name rtt loss
  for entry in $1; do
    IFS=':' read -r name rtt loss <<<"$entry"
    path_weight "$rtt" "$loss"
    spec+=(nexthop via "${P_PEER[$name]}" dev "${P_TUN[$name]}" weight "$PATH_WEIGHT")
  done
  if ((${#spec[@]} == 0)); then
    # Deliberately leave the last working route in place. Tearing it down would turn a
    # transient all-carriers-down blip into an instant hard failure for every existing
    # connection, and the route costs nothing while the carriers come back.
    return 1
  fi
  ip route replace "$ovp/32" "${spec[@]}" 2>/dev/null
}

# The chosen mode lives on disk, not in $STATEDIR: /run is tmpfs, so keeping it there
# means every reboot silently drops an operator's "multipath" back to "failover" — the
# tunnel would come back up looking healthy while quietly using one carrier.
MODEFILE="/etc/aestun/mp-mode"
# Sets MP_MODE as well as printing, so the daemon loop can read it back without a subshell.
MP_MODE="failover"
get_mode() {
  local m=""
  [[ -r "$MODEFILE" ]] && read -r m <"$MODEFILE"
  [[ "$m" == multipath || "$m" == failover ]] && MP_MODE="$m" || MP_MODE="failover"
  printf '%s' "$MP_MODE"
}
set_mode() { mkdir -p "$(dirname "$MODEFILE")"; printf '%s' "$1" >"$MODEFILE"; }

# =============================================================================
#  main_sender — probe every protocol, choose, route, and keep choosing
# =============================================================================
#  One pass:
#    1. probe every protocol in the table
#    2. apply hysteresis so a single lost ping does not move production traffic
#    3. failover  -> the FIRST healthy protocol in priority order carries everything
#       multipath -> every healthy protocol carries traffic, weighted by quality
#    4. install the route, and log only when the decision actually changes
main_sender() {
  local mode="${1:-$(get_mode)}" quiet="${2:-0}"
  mkdir -p "$STATEDIR"
  local name healthy=() report=() chosen=""

  # Probe every carrier CONCURRENTLY. Serialised, a blackholed carrier's ping timeout
  # is added to the latency of every carrier behind it in the list, so the pass — and
  # with it the time before traffic leaves a dead protocol — grows with the number of
  # broken carriers, which is precisely when it must not.
  for name in "${PROTOCOLS[@]}"; do
    ( probe_protocol "$name"; rc=$?
      printf '%s|%s|%s|%s' "$rc" "$PROBE_RTT" "$PROBE_LOSS" "$PROBE_NOTE" >"$STATEDIR/probe.$name" ) &
  done
  wait

  for name in "${PROTOCOLS[@]}"; do
    local rc=1 ok=0
    IFS='|' read -r rc PROBE_RTT PROBE_LOSS PROBE_NOTE <"$STATEDIR/probe.$name" 2>/dev/null
    : "${rc:=1}" "${PROBE_RTT:=-}" "${PROBE_LOSS:=100}"
    [[ "$rc" == 0 ]] && ok=1
    local sf="$STATEDIR/state.$name" cf="$STATEDIR/cnt.$name"
    local st="down" cnt=0
    # `read <file` rather than $(cat file): the builtin reads it without a fork, and this
    # loop runs for every carrier on every pass.
    [[ -r "$sf" ]] && read -r st <"$sf"; [[ -r "$cf" ]] && read -r cnt <"$cf"
    : "${st:=down}" "${cnt:=0}"
    if (( ok )); then
      if [[ "$st" == up ]]; then cnt=0; else
        cnt=$(( cnt + 1 ))
        (( cnt >= RISE_THRESHOLD )) && { st=up; cnt=0; [[ "$quiet" == 0 ]] && log "carrier $name is UP (rtt ${PROBE_RTT}ms loss ${PROBE_LOSS}%)"; }
      fi
    else
      if [[ "$st" == down ]]; then cnt=0; else
        cnt=$(( cnt + 1 ))
        (( cnt >= FAIL_THRESHOLD )) && { st=down; cnt=0; [[ "$quiet" == 0 ]] && log "carrier $name is DOWN (${PROBE_NOTE:-loss ${PROBE_LOSS}%})"; }
      fi
    fi
    printf '%s' "$st" >"$sf"; printf '%s' "$cnt" >"$cf"
    report+=("$name|$st|$PROBE_RTT|$PROBE_LOSS|${PROBE_NOTE}")
    [[ "$st" == up ]] && healthy+=("$name:$PROBE_RTT:$PROBE_LOSS")
  done

  local sel=""
  if [[ "$mode" == multipath ]]; then
    sel="${healthy[*]}"                      # every healthy carrier at once
  else
    # Strict priority order: the first protocol that answers takes the traffic, and
    # keeps it until it stops answering. Ordered, not scored, so the choice is
    # predictable and does not oscillate between two near-equal carriers.
    local h; for h in "${healthy[@]}"; do sel="$h"; break; done
    chosen="${sel%%:*}"
  fi

  local prev=""; [[ -r "$STATEDIR/active" ]] && read -r prev <"$STATEDIR/active"
  # "quic:44:0 icmp:52:0" -> "quic,icmp,", in the shell rather than through tr|cut|tr.
  local now="" e
  for e in $sel; do now+="${e%%:*},"; done
  if apply_route "$sel"; then
    if [[ "$now" != "$prev" ]]; then
      printf '%s' "$now" >"$STATEDIR/active"
      [[ "$quiet" == 0 ]] && log "mode=$mode active carriers: ${now%,}"
    fi
  else
    [[ "$quiet" == 0 && "$prev" != "NONE" ]] && { log "ALL CARRIERS DOWN — keeping the last route in place"; printf 'NONE' >"$STATEDIR/active"; }
  fi
  printf '%s\n' "${report[@]}" >"$STATEDIR/report"
  [[ -n "$chosen" ]] && printf '%s' "$chosen" >"$STATEDIR/chosen"
  return 0
}

cmd_daemon() {
  need_root; need_base
  overlay_up
  log "supervisor up: mode=$(get_mode) protocols=${PROTOCOLS[*]} interval=${PROBE_INTERVAL}s"
  trap 'log "supervisor exiting"; exit 0' TERM INT
  while true; do
    # get_mode sets MP_MODE in this shell; reading it through $( ) would fork once every
    # pass for a value that changes only when an operator runs `mode`.
    get_mode >/dev/null
    main_sender "$MP_MODE" 0
    sleep "$PROBE_INTERVAL"
  done
}

cmd_mode() {
  need_root
  local m="${1:-}"
  [[ "$m" == failover || "$m" == multipath ]] || { err "mode must be 'failover' or 'multipath'"; exit 2; }
  set_mode "$m"; msg "mode set to $m"
  main_sender "$m" 0
}

# =============================================================================
#  reporting
# =============================================================================
cmd_probe() {
  need_base
  hdr "Carrier probe (role $(role) -> $(peer_pub))"
  printf '%-7s %-5s/%-6s %-7s %8s %8s  %s\n' "PROTO" "TRANS" "OBFS" "DEV" "RTT_ms" "LOSS%" "STATE"
  printf '%s\n' "----------------------------------------------------------------------"
  local n
  for n in "${PROTOCOLS[@]}"; do
    local st="$G""up""$N"; probe_protocol "$n" || st="$R""down""$N"
    printf '%-7s %-5s/%-6s %-7s %8s %8s  %b\n' "$n" "$(p_transport "$n")" "$(p_obfs "$n")" \
      "$(p_tun "$n")" "$PROBE_RTT" "$PROBE_LOSS" "$st${PROBE_NOTE:+  $Y$PROBE_NOTE$N}"
  done
}

cmd_status() {
  need_base
  hdr "aestun multipath — role $(role), overlay $(overlay_local) -> $(overlay_peer)"
  printf 'mode      : %s\n' "$(get_mode)"
  printf 'supervisor: %s\n' "$(systemctl is-active aestun-mp 2>/dev/null || echo inactive)"
  printf 'sink      : %s\n' "$(systemctl is-active aestun-mp-sink 2>/dev/null || echo inactive)"
  printf 'active    : %s\n\n' "$(cat "$STATEDIR/active" 2>/dev/null || echo '-')"
  printf '%-7s %-9s %-8s %8s %8s %14s  %s\n' "PROTO" "UNIT" "STATE" "RTT_ms" "LOSS%" "TX_BYTES" "NOTE"
  printf '%s\n' "--------------------------------------------------------------------------------"
  local n
  for n in "${PROTOCOLS[@]}"; do
    local u; u="$(systemctl is-active "$(p_unit "$n")" 2>/dev/null || echo inactive)"
    local line st rtt loss note
    line="$(grep "^$n|" "$STATEDIR/report" 2>/dev/null)"
    IFS='|' read -r _ st rtt loss note <<<"${line:-$n|?|-|-|}"
    local dev tx="-"; dev="$(p_tun "$n")"
    [[ -r "/sys/class/net/$dev/statistics/tx_bytes" ]] && tx="$(cat "/sys/class/net/$dev/statistics/tx_bytes")"
    local c="$R"; [[ "$st" == up ]] && c="$G"
    printf '%-7s %-9s %b%-8s%b %8s %8s %14s  %s\n' "$n" "$u" "$c" "${st:-?}" "$N" "${rtt:--}" "${loss:--}" "$tx" "${note:-}"
  done
  printf '\n%sroute to %s:%s\n' "$D" "$(overlay_peer)" "$N"
  ip route show "$(overlay_peer)/32" 2>/dev/null | sed 's/^/  /'
}

cmd_bench() {   # send real data over every protocol, one at a time
  need_base
  local sz="${1:-8}"
  hdr "send_data over each protocol (${sz} MiB each)"
  local n
  for n in "${PROTOCOLS[@]}"; do send_data "$n" "$sz"; done
}

cmd_help() {
  cat <<EOF
${BOLD}aestun-mp${N} — multi-protocol tunnel supervisor (failover + multipath)

  ${C}setup${N}                generate a carrier config per protocol + systemd units
                       (run on BOTH servers; the two sides derive to matching configs)
  ${C}start${N}                stand down the single-path service, start all carriers,
                       the sink and the supervisor
  ${C}stop${N}                 stop multipath (leaves the single-path service disabled)
  ${C}revert${N}               stop multipath and bring back the stock single-path tunnel
  ${C}mode${N} failover|multipath
                       failover  = first responsive protocol carries everything
                       multipath = all healthy protocols at once (weighted ECMP)
  ${C}probe${N}                probe every protocol once and print RTT/loss
  ${C}status${N}               carriers, health, per-device counters, current route
  ${C}send${N} PROTO [FILE|MiB] send real data over ONE named protocol and time it
  ${C}bench${N} [MiB]           run send over every protocol in turn
  ${C}once${N}                  run one supervisor pass in the foreground
  ${C}daemon${N}                supervisor loop (this is what aestun-mp.service runs)
  ${C}sink${N}                  receiving half of send/bench (aestun-mp-sink.service)

Protocols: ${PROTOCOLS[*]}
EOF
}

case "${1:-help}" in
  setup)  cmd_setup ;;
  start)  cmd_start ;;
  stop)   cmd_stop ;;
  revert) cmd_revert ;;
  mode)   shift; cmd_mode "${1:-}" ;;
  probe)  cmd_probe ;;
  status) cmd_status ;;
  send)   shift; need_base; send_data "${1:-}" "${2:-8}" ;;
  bench)  shift; cmd_bench "${1:-8}" ;;
  once)   need_root; need_base; main_sender "$(get_mode)" 0 ;;
  daemon) cmd_daemon ;;
  sink)   cmd_sink ;;
  help|-h|--help) cmd_help ;;
  *) err "unknown command: $1"; cmd_help; exit 2 ;;
esac
