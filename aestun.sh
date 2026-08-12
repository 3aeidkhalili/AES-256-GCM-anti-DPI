#!/usr/bin/env bash
# =============================================================================
#  aestun.sh — one file: installer + manager + live monitor + zapret + build.
#
#    sudo ./aestun.sh              # management menu (default)
#    sudo ./aestun.sh install      # interactive installer (run on each server)
#    ./aestun.sh build [amd64|arm64]   # cross-compile a static binary (dev machine)
#    ./aestun.sh zap-rule {add|del|rearm}   # NFQUEUE helper, invoked by systemd
#
#  Replaces the former install.sh / menu.sh / lib.sh / build.sh / zapret-rules.sh.
# =============================================================================
set -uo pipefail

LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SELF="${LIB_DIR}/$(basename "${BASH_SOURCE[0]}")"
MGR_DST="/usr/local/sbin/aestun-mgr"   # where install copies this script so systemd can call it
# ----------------------------------------------------------------- paths / consts
BIN_DST="/usr/local/bin/aestun"
CONF_DIR="/etc/aestun"
CONF="${CONF_DIR}/config.json"
SERVICE="/etc/systemd/system/aestun.service"
STATS="/run/aestun/stats.json"
DPI_LOG="/var/log/aestun/dpi.jsonl"
SYSCTL_FILE="/etc/sysctl.d/99-aestun.conf"
BBR_MODCONF="/etc/modules-load.d/aestun-bbr.conf"
ZAPRET_DIR="/opt/zapret"
ZAP_BIN="${ZAPRET_DIR}/nfq/nfqws"   # built from source (upstream ships no prebuilt binaries)
ZAP_SERVICE="/etc/systemd/system/aestun-zapret.service"
ZAP_RULES="/etc/aestun/zapret-rules.sh"

# ------------------------------------------------------------------------- colors
if [[ -t 1 ]]; then
  R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; B=$'\e[34m'; C=$'\e[36m'; W=$'\e[97m'; D=$'\e[2m'; BOLD=$'\e[1m'; N=$'\e[0m'
else
  R=""; G=""; Y=""; B=""; C=""; W=""; D=""; BOLD=""; N=""
fi

msg()  { printf '%s\n' "${G}[OK]${N} $*"; }
warn() { printf '%s\n' "${Y}[!]${N} $*"; }
err()  { printf '%s\n' "${R}[X]${N} $*" >&2; }
hdr()  { printf '\n%s\n' "${BOLD}${C}== $* ==${N}"; }
pause(){ printf '\n%s' "${D}Press Enter to continue...${N}"; read -r _; }

confirm() { local a; printf '%s [y/N]: ' "$1"; read -r a; [[ "$a" =~ ^[yY]$ ]]; }

need_root() { if [[ $EUID -ne 0 ]]; then err "Please run as root (sudo)."; exit 1; fi; }

# svc_active UNIT -> single-word state (active/inactive/failed/...). Avoids the
# double-print you get from `systemctl is-active X || echo Y` when a unit is down.
svc_active() { local s; s="$(systemctl is-active "$1" 2>/dev/null | head -1)"; printf '%s' "${s:-unknown}"; }

# ask "prompt" "default"  -> echoes the entered value (or default). Prompt goes to stderr.
# Returns non-zero on EOF (no TTY / closed stdin) so callers can stop instead of spinning.
ask() {
  local p="$1" d="${2-}" a
  if [[ -n "$d" ]]; then printf '%s%s%s [%s%s%s]: ' "$W" "$p" "$N" "$C" "$d" "$N" >&2
  else printf '%s%s%s: ' "$W" "$p" "$N" >&2; fi
  if ! read -r a; then printf '%s' "$d"; return 1; fi
  printf '%s' "${a:-$d}"
}

# ask_req "prompt" "default"  -> like ask but loops until non-empty.
# Returns non-zero on EOF. NOTE: this runs inside $(...) at call sites, so it can only
# signal via its return code — callers MUST use `x="$(ask_req ...)" || return 1` to abort.
ask_req() {
  local v
  while true; do
    if ! v="$(ask "$1" "${2-}")"; then
      err "No input (EOF/non-interactive stdin)."
      return 1
    fi
    [[ -n "$v" ]] && { printf '%s' "$v"; return 0; }
    err "Value required."
  done
}

# ask_yn "prompt" "Y|N (default)"  -> return 0 for yes.
ask_yn() {
  local p="$1" d="${2:-N}" a hint
  [[ "$d" == Y ]] && hint="Y/n" || hint="y/N"
  printf '%s%s%s [%s]: ' "$W" "$p" "$N" "$hint" >&2; read -r a; a="${a:-$d}"
  [[ "$a" =~ ^[yY]$ ]]
}

is_port() { [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 )); }
is_uint() { [[ "$1" =~ ^[0-9]+$ ]]; }

# ask_int "prompt" "default" -> a non-negative integer; falls back to default on non-numeric input.
ask_int() {
  local p="$1" d="$2" v
  v="$(ask "$p" "$d")" || v="$d"
  if is_uint "$v"; then printf '%s' "$v"; else printf '%s\n' "${Y}  (not a number — using ${d})${N}" >&2; printf '%s' "$d"; fi
}

# ------------------------------------------------------------------- architecture
arch_tag() {
  case "$(uname -m)" in
    x86_64|amd64)  echo amd64 ;;
    aarch64|arm64) echo arm64 ;;
    *)             echo unknown ;;
  esac
}
zapret_platform() {
  case "$(uname -m)" in
    x86_64|amd64)  echo linux-x86_64 ;;
    aarch64|arm64) echo linux-arm64 ;;
    *)             echo "" ;;
  esac
}

# ----------------------------------------------------------------- read JSON safely
# carrier_endpoint — split the configured peer into host and port, and say whether this
# carrier has a port at all.  Prints:  HOST|PORT|TRANSPORT   (PORT empty for icmp)
#
# The separator is "|" rather than a tab on purpose: a tab is IFS whitespace, so `read`
# collapses a run of them and the empty PORT field of an ICMP peer would silently shift
# TRANSPORT into PORT.
#
# This exists because "${peer##*:}" is wrong on two of the three carriers. On the ICMP
# carrier the peer is a bare address with no colon in it, so that expansion returns the whole
# address — and every caller then went on to build "--dport 91.107.160.35", which iptables
# rejects and nfqws silently mis-parses. An IPv6 peer in bracket form has the same problem in
# reverse. Parse it once, here, and let the callers ask whether there is a port.
carrier_endpoint() {
  local peer transport host port
  peer="$(json_get "$CONF" peer)"
  transport="$(json_get "$CONF" transport)"; transport="${transport:-udp}"
  if [[ "$transport" == "icmp" ]]; then
    # ICMP has no ports. Accept the host:port form anyway, because operators copy the peer
    # line across from a UDP config, and just drop the port.
    host="${peer%%:*}"; [[ "$peer" == \[*\]* ]] && host="${peer#\[}" && host="${host%%\]*}"
    printf '%s||%s\n' "$host" "$transport"; return 0
  fi
  if [[ "$peer" == \[*\]:* ]]; then          # [2001:db8::1]:443
    host="${peer#\[}"; host="${host%%\]*}"; port="${peer##*:}"
  elif [[ "$peer" == *:* ]]; then            # 1.2.3.4:443
    host="${peer%:*}"; port="${peer##*:}"
  else                                       # no port given: fall back to the listen port
    host="$peer"; port="$(json_get "$CONF" listen)"; port="${port##*:}"
  fi
  [[ "$port" =~ ^[0-9]+$ ]] || port=""
  printf '%s|%s|%s\n' "$host" "$port" "$transport"
}

json_get() { # json_get FILE KEY
  local f="$1" k="$2"
  [[ -f "$f" ]] || { echo ""; return; }
  if command -v jq >/dev/null 2>&1; then
    jq -r --arg k "$k" '.[$k] // empty' "$f" 2>/dev/null
  elif command -v python3 >/dev/null 2>&1; then
    python3 - "$f" "$k" <<'PY' 2>/dev/null
import json,sys
try:
    d=json.load(open(sys.argv[1]))
    v=d.get(sys.argv[2],"")
    print("" if v is None else v)
except Exception:
    pass
PY
  else
    # anchored key removal so values containing ":" (host:port) survive
    grep -oE "\"$k\"[[:space:]]*:[[:space:]]*(\"[^\"]*\"|[0-9]+|true|false)" "$f" \
      | head -1 | sed -E "s/^\"$k\"[[:space:]]*:[[:space:]]*//; s/^\"//; s/\"\$//"
  fi
}

human() { # human BYTES -> e.g. 12.34 MB
  awk -v b="${1:-0}" 'BEGIN{
    split("B KB MB GB TB PB",u," "); i=1;
    while(b>=1024 && i<6){b/=1024;i++}
    printf (i==1?"%d %s":"%.2f %s"), b, u[i]
  }'
}
fmt_dur() { # SECONDS -> Xd Yh Zm
  local s=${1:-0} d h m
  d=$(( s/86400 )); s=$(( s%86400 )); h=$(( s/3600 )); s=$(( s%3600 )); m=$(( s/60 ))
  local out=""; (( d>0 )) && out+="${d}d "; (( h>0 )) && out+="${h}h "; out+="${m}m"; echo "$out"
}

# --------------------------------------------------------------------- dependencies
ensure_deps() {
  local miss=()
  command -v ip >/dev/null 2>&1 || miss+=(iproute2)
  command -v ping >/dev/null 2>&1 || miss+=(iputils-ping)
  if ((${#miss[@]})); then
    warn "Installing prerequisites: ${miss[*]}"
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y "${miss[@]}" >/dev/null 2>&1 || warn "Auto-install failed; install manually: ${miss[*]}"
  fi
  # jq is optional (nicer JSON parsing); install quietly if possible, ignore failure
  command -v jq >/dev/null 2>&1 || apt-get install -y jq >/dev/null 2>&1 || true
}

# check_build_deps — a source build needs either the vendored deps (offline) or network access
# to fetch them.
check_build_deps() {
  if [[ ! -d "${LIB_DIR}/vendor" ]]; then
    warn "vendor/ is absent — the build will fetch golang.org/x/crypto and golang.org/x/sys from"
    warn "the Go module proxy (needs internet; go.sum verifies them). To build fully offline,"
    warn "restore the vendor tree once with:  ( cd '${LIB_DIR}' && go mod vendor )"
  fi
}

# ensure_go — put a Go toolchain on PATH, installing one if the box has none.
#
# Building from source is the *preferred* path even though prebuilt binaries ship alongside
# these sources, and the order matters. Nothing ties a checked-in binary to the source next to
# it: the one previously in this tree predated the ICMP carrier, so an install that preferred
# it put an older program on disk than the sources the operator was reading, with no warning.
# Compiling first means "update both servers" means the same thing on both; the prebuilts are
# the fallback for a box with no toolchain and no way to fetch one.
GO_VERSION="1.26.5"
ensure_go() {
  command -v go >/dev/null 2>&1 && return 0
  [[ -x /usr/local/go/bin/go ]] && { export PATH="/usr/local/go/bin:$PATH"; return 0; }
  local tag; tag="$(arch_tag)"
  local tarball="go${GO_VERSION}.linux-${tag}.tar.gz"
  warn "Go is not installed; fetching ${tarball} to build aestun from source..."
  local url ok=1
  for url in "https://go.dev/dl/${tarball}" \
             "https://dl.google.com/go/${tarball}" \
             "https://mirrors.aliyun.com/golang/${tarball}"; do
    if curl -fsSL --connect-timeout 15 -o "/tmp/${tarball}" "$url" \
       && tar -tzf "/tmp/${tarball}" >/dev/null 2>&1; then ok=0; break; fi
  done
  if (( ok != 0 )); then
    rm -f "/tmp/${tarball}"
    err "Could not download a Go toolchain. Install one manually (apt install golang-go, or"
    err "https://go.dev/dl/) and re-run, or build elsewhere with:  ./aestun.sh build ${tag}"
    return 1
  fi
  rm -rf /usr/local/go && tar -C /usr/local -xzf "/tmp/${tarball}" && rm -f "/tmp/${tarball}"
  export PATH="/usr/local/go/bin:$PATH"
  command -v go >/dev/null 2>&1 || { err "Go install failed."; return 1; }
  msg "Go $(go version | awk '{print $3}') installed in /usr/local/go."
}

# ---------------------------------------------------------------------- install bin
#
# Source build first, prebuilt binary second. Both are supported; the order is what keeps the
# installed program honest. A prebuilt that is older than the sources beside it is the failure
# mode worth designing against — it produces a box running code nobody is looking at — so the
# fallback path says loudly when it is taken and checks the binary against SHA256SUMS.
ensure_binary() {
  local tag; tag="$(arch_tag)"
  local pre="${LIB_DIR}/aestun-linux-${tag}"

  if [[ -f "${LIB_DIR}/main.go" ]] && ensure_go; then
    check_build_deps
    msg "Building aestun from the sources in ${LIB_DIR} ..."
    if ( cd "$LIB_DIR" && CGO_ENABLED=0 GOOS=linux GOARCH="$tag" go build -trimpath -ldflags "-s -w" -o "${BIN_DST}.new" . ); then
      # Replace by rename, so a running service is never left pointing at a half-written file.
      install -m 0755 "${BIN_DST}.new" "$BIN_DST" && rm -f "${BIN_DST}.new"
      msg "Built and installed from source: $BIN_DST (${tag})"
      return 0
    fi
    rm -f "${BIN_DST}.new"
    err "Build failed — falling back to the prebuilt binary if one is present."
  fi

  if [[ -f "$pre" ]]; then
    warn "Using the PREBUILT binary ${pre##*/} — it was not compiled from the sources in this"
    warn "directory just now, so it matches them only if nobody has edited them since."
    # SHA256SUMS records what the shipped binaries hashed to when they were built. A mismatch
    # means the binary was replaced or the file is damaged; either way, say so.
    if [[ -f "${LIB_DIR}/SHA256SUMS" ]]; then
      if ( cd "$LIB_DIR" && grep -q "  aestun-linux-${tag}\$" SHA256SUMS \
           && sha256sum -c --ignore-missing --status SHA256SUMS 2>/dev/null ); then
        msg "  checksum verified against SHA256SUMS."
      else
        err "  checksum does NOT match SHA256SUMS — this binary is not the one that was shipped."
        confirm "  Install it anyway" || return 1
      fi
    fi
    install -m 0755 "$pre" "$BIN_DST"
    msg "Installed prebuilt binary: $BIN_DST (${tag})"
    printf '   %sTo be certain it matches the sources, rebuild:  ./aestun.sh build %s%s\n' "$D" "$tag" "$N"
    return 0
  fi

  err "No Go toolchain could be obtained and no prebuilt aestun-linux-${tag} is present."
  err "On a machine with Go run:  ./aestun.sh build ${tag}   then copy the output here."
  return 1
}

# ------------------------------------------------------------------ systemd service
write_service() {
  cat > "$SERVICE" <<EOF
[Unit]
Description=aestun - AES-256-GCM obfuscated server-to-server tunnel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${BIN_DST} -config ${CONF}
Restart=always
RestartSec=2
LimitNOFILE=1048576
# CAP_NET_RAW is required by transport "icmp" and by the optional native desync module;
# harmless to grant when neither is in use. CAP_NET_ADMIN also enables SO_RCVBUFFORCE.
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
RuntimeDirectory=aestun
# The multi-protocol carriers (aestun-path@) write their stats into this same directory.
# Without Preserve, systemd deletes /run/aestun whenever THIS unit stops — so a stray
# single-path service that is merely crash-looping (it cannot bind a device the carriers
# already hold) silently wipes every carrier's stats file and blinds the dashboard.
RuntimeDirectoryPreserve=yes
# Gives the DPI observer a place to write that survives ProtectSystem=full, created with
# the right ownership before the daemon starts.
LogsDirectory=aestun
ProtectSystem=full
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF
}

# ------------------------------------------------------------------- write config
# Expects globals: CFG_ROLE CFG_KEY CFG_LISTEN_PORT CFG_PEER CFG_TUN CFG_LOCAL_IP
#                  CFG_PEER_IP CFG_MTU CFG_TXQ CFG_PAD CFG_REKEY CFG_KA CFG_TRANSPORT CFG_BUF
write_config() {
  mkdir -p "$CONF_DIR"
  cat > "$CONF" <<EOF
{
  "role": "${CFG_ROLE}",
  "key": "${CFG_KEY}",
  "cipher": "${CFG_CIPHER:-aes-gcm}",
  "listen": "0.0.0.0:${CFG_LISTEN_PORT}",
  "peer": "${CFG_PEER}",
  "transport": "${CFG_TRANSPORT:-udp}",
  "obfs": "${CFG_OBFS:-none}",
  "sni": "${CFG_SNI:-www.cloudflare.com}",
  "tun_name": "${CFG_TUN}",
  "local_ip": "${CFG_LOCAL_IP}",
  "peer_ip": "${CFG_PEER_IP}",
  "mtu": ${CFG_MTU},
  "txqueuelen": ${CFG_TXQ},
  "rcvbuf": ${CFG_BUF:-2097152},
  "sndbuf": ${CFG_BUF:-2097152},
  "pad_max": ${CFG_PAD},
  "rekey_interval": ${CFG_REKEY},
  "keepalive": ${CFG_KA},
  "manage_ip": true,
  "stats_path": "${STATS}",
  "dpi_log": {
    "enabled": ${CFG_DPI:-true},
    "path": "${DPI_LOG}",
    "probe": ${CFG_DPI_PROBE:-true}
  },

  "desync": { "enabled": ${CFG_DESYNC:-false}, "repeats": ${CFG_DESYNC_REP:-4}, "autottl": true, "delta": -1, "badsum": ${CFG_DESYNC_BADSUM:-false} },
  "junk":   { "enabled": ${CFG_JUNK:-false}, "count": ${CFG_JUNK_COUNT:-8}, "min_ms": 5, "max_ms": 50 },
  "hop":    { "enabled": ${CFG_HOP:-false}, "ports": [${CFG_HOP_PORTS:-443, 8443, 2053, 2083, 2087, 2096}], "interval": ${CFG_HOP_INT:-30} },
  "split":  { "enabled": ${CFG_SPLIT:-false}, "frag_pos": 24 },
  "tcp_rotate": { "enabled": ${CFG_TCPROT:-false}, "interval_sec": ${CFG_TCPROT_INT:-15} },

  "icmp": {
    "readers": ${CFG_ICMP_READERS:-0},
    "batch": ${CFG_ICMP_BATCH:-32},
    "kernel_filter": true,
    "suppress_replies": true,
    "id": 0,
    "id_pool": ${CFG_ICMP_POOL:-1},
    "id_rotate_sec": ${CFG_ICMP_ROT:-60},
    "mimic_ping": ${CFG_ICMP_MIMIC:-false}
  }
}
EOF
  chmod 600 "$CONF"
  msg "Config written: $CONF"
}

open_firewall() { # open_firewall PORT
  local port="$1"
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi active; then
    ufw allow "${port}/udp" >/dev/null 2>&1 && msg "UFW rule added for ${port}/udp."
  fi
}
# open_firewall_icmp — the ICMP carrier has no port to open, only a message type. Many cloud
# images ship a UFW policy that drops inbound ICMP echo, which makes the tunnel look blocked
# by the ISP when it is being blocked by the host itself.
open_firewall_icmp() {
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi active; then
    ufw allow proto icmp >/dev/null 2>&1 && msg "UFW rule added for ICMP." \
      || warn "Could not add a UFW ICMP rule; allow ICMP echo manually or the carrier will not receive."
  fi
  printf '  %sAlso allow ICMP echo (type 8) inbound in the CLOUD firewall on both servers —\n' "$Y"
  printf '  a provider security group that only opens TCP/UDP silently drops this carrier.%s\n' "$N"
}

close_firewall() { # close_firewall PORT
  local port="$1"
  command -v ufw >/dev/null 2>&1 && ufw delete allow "${port}/udp" >/dev/null 2>&1 || true
}

# =============================================================================
#  Network optimization (Ubuntu sysctl tuning for the tunnel)
# =============================================================================
# apply_network_opt CC BUFMAX FORWARD(0|1)
apply_network_opt() {
  local cc="${1:-bbr}" buf="${2:-16777216}" fwd="${3:-1}"

  if [[ "$cc" == "bbr" ]]; then
    modprobe tcp_bbr 2>/dev/null || true
    echo tcp_bbr > "$BBR_MODCONF"
  fi

  cat > "$SYSCTL_FILE" <<EOF
# Managed by aestun installer — network optimization for the tunnel.
# Congestion control & queueing discipline
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = ${cc}

# Socket buffer ceilings (bytes)
net.core.rmem_max = ${buf}
net.core.wmem_max = ${buf}
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.core.optmem_max = 65536
net.core.netdev_max_backlog = 250000
net.core.somaxconn = 4096

# TCP tuning (for connections traversing the tunnel)
net.ipv4.tcp_rmem = 4096 1048576 ${buf}
net.ipv4.tcp_wmem = 4096 65536 ${buf}
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_syncookies = 1

# UDP buffers (the tunnel carrier is UDP)
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384

# IP forwarding
net.ipv4.ip_forward = ${fwd}
net.ipv6.conf.all.forwarding = ${fwd}

# Larger connection-tracking table (best-effort; ignored if module absent)
net.netfilter.nf_conntrack_max = 262144
EOF

  sysctl --system >/dev/null 2>&1 || true
  local active; active="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)"
  if [[ "$active" == "$cc" ]]; then
    msg "Network optimization applied (congestion=${active}, buf=$(human "$buf"))."
  else
    warn "Optimization applied, but congestion control is '${active}' (requested '${cc}'). Kernel may lack ${cc}."
  fi
}

remove_network_opt() {
  rm -f "$SYSCTL_FILE" "$BBR_MODCONF"
  sysctl --system >/dev/null 2>&1 || true
  msg "Network optimization removed (defaults restored on next boot; qdisc/cc reset now)."
}

show_network_opt() {
  hdr "Current network settings"
  local keys=(net.ipv4.tcp_congestion_control net.core.default_qdisc net.core.rmem_max net.core.wmem_max \
              net.ipv4.tcp_mtu_probing net.ipv4.tcp_fastopen net.ipv4.ip_forward)
  local k v
  for k in "${keys[@]}"; do
    v="$(sysctl -n "$k" 2>/dev/null || echo '-')"
    printf '  %-38s = %s%s%s\n' "$k" "$W" "$v" "$N"
  done
  printf '  available congestion controls        = %s\n' "$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo '-')"
  if [[ -f "$SYSCTL_FILE" ]]; then msg "aestun tuning file present: $SYSCTL_FILE"; else warn "aestun tuning not installed."; fi
}

# =============================================================================
#  Interactive setup — prompts every value; used on BOTH the Iran and foreign server
# =============================================================================
# icmp_setup_questions — the ICMP carrier's own knobs, asked only when that carrier is chosen.
#
# Split deliberately into two halves. The performance knobs are local to this host and can
# differ between the two servers; the wire knobs are not negotiated (there is no handshake to
# negotiate in) and a mismatch means every packet fails to authenticate, so they are asked
# with that said out loud and default to the interoperable choice.
icmp_setup_questions() {
  printf '\n%sICMP carrier settings%s\n' "$BOLD" "$N"
  printf '  %sThe defaults are right for a busy link; the first two are local to this host.%s\n' "$D" "$N"
  CFG_ICMP_READERS="$(ask_int "Receive goroutines (0 = one per core, capped at 8)" "0")"
  CFG_ICMP_BATCH="$(ask_int "Messages per sendmmsg/recvmmsg (1 disables batching)" "32")"

  printf '\n  %sThe next two change the packets on the wire, so they must be IDENTICAL on\n' "$Y"
  printf '  both servers — there is no negotiation, and a mismatch is a dead tunnel.%s\n' "$N"
  printf '  %sIdentifier rotation%s: port hopping'"'"'s idea applied to the one field an ICMP\n' "$C" "$N"
  printf '    flow has to key on. A middlebox that learns to drop "the ping with identifier\n'
  printf '    0x8D94" has to learn the whole set, and by then the schedule has moved.\n'
  CFG_ICMP_POOL="$(ask_int "  identifiers to rotate through (1 = no rotation, max 8)" "1")"
  if [[ "$CFG_ICMP_POOL" -gt 1 ]]; then
    CFG_ICMP_ROT="$(ask_int "  seconds per identifier" "60")"
  fi
  printf '  %sPing mimicry%s: prepend the 16-byte timeval ping(8) puts at the start of its\n' "$C" "$N"
  printf '    payload, so a dissector renders the flow as ordinary pings with a plausible\n'
  printf '    round-trip time. Costs 16 bytes per packet.\n'
  ask_yn "  enable ping mimicry" "N" && CFG_ICMP_MIMIC=true

  printf '\n  %sThis host must allow ICMP echo in and out in the cloud firewall, and the\n' "$Y"
  printf '  service needs CAP_NET_RAW (the unit already grants it).%s\n' "$N"
  command -v iptables >/dev/null 2>&1 || command -v nft >/dev/null 2>&1 || \
    warn "  neither iptables nor nft is present: the kernel will answer the peer's data pings"
}

interactive_setup() {
  hdr "aestun tunnel setup"
  ensure_deps
  ensure_binary || { pause; return 1; }

  # --- role: which side is this server? ---
  printf '\n%sWhich side is THIS server?%s\n' "$BOLD" "$N"
  printf '  %s1%s) Iran server    (inside / behind DPI)  -> role a, tunnel IP 10.8.0.1\n' "$C" "$N"
  printf '  %s2%s) Foreign server (outside / exit)       -> role b, tunnel IP 10.8.0.2\n' "$C" "$N"
  local sel; sel="$(ask "Choose" "1")"
  local def_local def_peer
  if [[ "$sel" == "2" ]]; then
    CFG_ROLE="b"; def_local="10.8.0.2/24"; def_peer="10.8.0.1"
  else
    CFG_ROLE="a"; def_local="10.8.0.1/24"; def_peer="10.8.0.2"
  fi

  # --- key ---
  local existing=""; [[ -f "$CONF" ]] && existing="$(json_get "$CONF" key)"
  printf '\n%sShared key%s (base64 of 32 bytes) — must be IDENTICAL on both servers.\n' "$BOLD" "$N"
  if [[ -n "$existing" ]] && ask_yn "Keep the existing key" "Y"; then
    CFG_KEY="$existing"
  elif ask_yn "Generate a new random key" "Y"; then
    CFG_KEY="$("$BIN_DST" keygen)"
    printf '  %sGenerated key (use the SAME on the other server):%s\n  %s%s%s\n' "$Y" "$N" "$BOLD" "$CFG_KEY" "$N"
  else
    CFG_KEY="$(ask_req "Paste the base64 key")" || return 1
  fi

  # --- cipher suite ---
  # This matters far more than it looks. Go only has a fast AES-GCM when the CPU exposes
  # AES-NI *and* PCLMULQDQ; without them it falls back to a constant-time software
  # implementation, and on a virtualised CPU that hides those flags the difference measured
  # on this project's own foreign endpoint was 41 MB/s versus 234 MB/s. Both ends must agree,
  # and a link is only as fast as its slower side, so if EITHER server lacks the instructions,
  # both should be set to chacha20-poly1305.
  local rec_cipher hw cpuname
  rec_cipher="$("$BIN_DST" cipherinfo 2>/dev/null | tail -1)"
  hw="$("$BIN_DST" cipherinfo 2>/dev/null | sed -n 's/^aes_hardware=//p')"
  cpuname="$("$BIN_DST" cipherinfo 2>/dev/null | sed -n 's/^cpu=//p')"
  [[ -n "$rec_cipher" ]] || rec_cipher="aes-gcm"
  printf '\n%sCipher suite%s — must be IDENTICAL on both servers.\n' "$BOLD" "$N"
  printf '  this CPU: %s%s%s\n' "$W" "${cpuname:-unknown}" "$N"
  if [[ "$hw" == "true" ]]; then
    printf '  AES hardware acceleration: %syes%s\n' "$G" "$N"
  else
    printf '  AES hardware acceleration: %sno%s — AES-GCM would run in software here and\n' "$R" "$N"
    printf '     will dominate CPU use at any real packet rate.\n'
  fi
  printf '  %saes-gcm%s            : fastest where AES-NI exists\n' "$C" "$N"
  printf '  %schacha20-poly1305%s  : fast everywhere, no special instructions needed\n' "$C" "$N"
  printf '  %sThe wire format is byte-identical either way, so the choice is invisible to DPI.%s\n' "$D" "$N"
  printf '  %sIf the OTHER server lacks AES-NI, choose chacha20-poly1305 on BOTH.%s\n' "$D" "$N"
  CFG_CIPHER="$(ask "Cipher (aes-gcm/chacha20-poly1305)" "$rec_cipher")"
  [[ "$CFG_CIPHER" == "aes-gcm" || "$CFG_CIPHER" == "chacha20-poly1305" ]] || {
    warn "Unknown cipher '$CFG_CIPHER' — using $rec_cipher."; CFG_CIPHER="$rec_cipher"; }

  # --- carrier transport ---
  # UDP is the default for a reason: the carrier multiplexes every inner connection.
  # Over TCP, one lost carrier segment head-of-line-blocks *all* of them at once
  # (and inner TCP retransmits on top of outer TCP), which shows up as every user
  # stalling in lockstep. Only pick TCP if UDP is blocked on your path.
  printf '\n%sCarrier transport%s — udp is the default; icmp is for paths that punish UDP.\n' "$BOLD" "$N"
  printf '  %sudp%s : a lost packet affects only the connection it carried\n' "$C" "$N"
  printf '  %stcp%s : survives UDP-blocking networks, but one loss stalls every connection\n' "$C" "$N"
  printf '  %sicmp%s: the tunnel rides in ping payloads. On the reference Iran<->EU link UDP\n' "$C" "$N"
  printf '        lost ~42%% of everything offered, in ~94 ms blackouts every ~345 ms, at any\n'
  printf '        rate — and ICMP echo crossed the same path at the same moment at 30 Mbit/s\n'
  printf '        with 0.4%% loss. Needs CAP_NET_RAW and takes no obfs and no port hopping.\n'
  CFG_TRANSPORT="$(ask "Transport (udp/tcp/icmp)" "udp")"
  case "$CFG_TRANSPORT" in
    udp|tcp|icmp) ;;
    *) warn "Unknown transport '$CFG_TRANSPORT' — using udp."; CFG_TRANSPORT="udp" ;;
  esac

  # --- wire obfuscation ---
  # The payload is already indistinguishable from random, which is the problem: nothing
  # else on the wire looks like that. "quic" gives each datagram a QUIC short header and
  # opens the flow with a real Initial packet, so it reads as an ordinary QUIC connection.
  if [[ "$CFG_TRANSPORT" == "icmp" ]]; then
    # An echo request is not a datagram protocol with a handshake to imitate. A QUIC or DTLS
    # header inside a ping is not cover — no real ping carries one — so it would be the single
    # anomalous thing about an otherwise ordinary packet. The binary refuses the combination.
    CFG_OBFS="none"
    printf '\n%sWire obfuscation%s: not applicable to the ICMP carrier — the cover *is* the ping.\n' "$BOLD" "$N"
  else
  printf '\n%sWire obfuscation%s — must match on BOTH servers.\n' "$BOLD" "$N"
  printf '  %snone%s : raw high-entropy datagrams (compatible with older builds)\n' "$C" "$N"
  printf '  %squic%s : shapes the carrier as its natural TLS-family form — QUIC over UDP,\n' "$C" "$N"
  printf '         TLS (records + synthetic handshake) over TCP\n'
  printf '  %squic2%s: same as quic, but the handshake cover claims QUIC v2 (RFC 9369).\n' "$C" "$N"
  printf '         Iranian carriers were measured dropping every QUIC %sv1%s long-header\n' "$Y" "$N"
  printf '         packet, which silently discards the quic cover; v2 passes. %sDefault.%s\n' "$G" "$N"
  printf '  %sdtls%s : shapes the carrier as DTLS 1.2 records with a ClientHello cover —\n' "$C" "$N"
  printf '         for links where QUIC itself is what draws attention (UDP only)\n'
  CFG_OBFS="$(ask "Obfuscation (none/quic/quic2/dtls)" "quic2")"
  case "$CFG_OBFS" in
    none|quic|quic2|dtls) ;;
    *) warn "Unknown obfs '$CFG_OBFS' — using none."; CFG_OBFS="none" ;;
  esac
  if [[ "$CFG_OBFS" == "dtls" && "$CFG_TRANSPORT" == "tcp" ]]; then
    warn "dtls is a UDP record format; over TCP the coherent disguise is TLS — using quic2."
    CFG_OBFS="quic2"
  fi
  if [[ "$CFG_OBFS" != "none" ]]; then
    CFG_SNI="$(ask "Server name to present in the handshake" "www.cloudflare.com")"
  fi
  fi

  # --- network endpoints ---
  printf '\n'
  local phost
  if [[ "$CFG_TRANSPORT" == "icmp" ]]; then
    # ICMP has no ports. listen is still written (the config schema is shared) but nothing
    # binds it, and the peer is an address on its own.
    CFG_LISTEN_PORT=51820
    phost="$(ask_req "Public IPv4 of the OTHER server")" || return 1
    CFG_PEER="${phost}"
    printf '  %sThe ICMP carrier is IPv4-only and needs the peer address on BOTH ends.%s\n' "$D" "$N"
  else
    CFG_LISTEN_PORT="$(ask "${CFG_TRANSPORT^^} listen port on THIS server" "51820")"
    is_port "$CFG_LISTEN_PORT" || { CFG_LISTEN_PORT=51820; warn "Invalid port, using 51820."; }
    local pport
    phost="$(ask_req "Public IP/host of the OTHER server")" || return 1
    pport="$(ask "${CFG_TRANSPORT^^} port of the OTHER server" "$CFG_LISTEN_PORT")"
    is_port "$pport" || pport="$CFG_LISTEN_PORT"
    CFG_PEER="${phost}:${pport}"
  fi

  # --- tunnel interface / local IPs ---
  printf '\n'
  CFG_TUN="$(ask "Tunnel interface name" "tun0")"
  CFG_LOCAL_IP="$(ask "Local tunnel IP of THIS server (CIDR)" "$def_local")"
  CFG_PEER_IP="$(ask "Tunnel IP of the OTHER server" "$def_peer")"

  # --- tunnel tunables ---
  printf '\n'
  CFG_MTU="$(ask_int "MTU" "1300")"
  CFG_TXQ="$(ask_int "Interface tx queue length" "1000")"
  CFG_PAD="$(ask_int "Max random padding per packet (0=off, anti-DPI)" "64")"
  CFG_REKEY="$(ask_int "Key rotation interval seconds (0=static)" "3600")"
  CFG_KA="$(ask_int "Keepalive interval seconds (0=off)" "25")"
  # Kernel clamps this to net.core.rmem_max/wmem_max, so the network optimization
  # below has to raise those or the request is silently cut to the ~200 KB default.
  #
  # 2 MiB, not 8. This buffer *is* a queue, and on a fast link an oversized one is pure
  # bufferbloat: measured on the reference 650 Mbit/s link, 8 MiB held ~62 ms of backlog,
  # so latency under load went 80 ms -> 142 ms and jitter to 35 ms. Dropping to 2 MiB cut
  # that to ~19 ms of backlog (loaded latency ~99 ms, jitter ~10 ms) for about 4% of
  # throughput. Raise it only if you are shifting bulk data and do not care about latency.
  printf '\n%sSocket buffer%s — this is a queue: too small caps throughput, too large is\n' "$BOLD" "$N"
  printf 'bufferbloat. 2 MiB is the measured sweet spot on a ~650 Mbit/s link.\n'
  CFG_BUF="$(ask_int "Socket buffer per direction in bytes" "2097152")"

  # --- DPI / probe observability ---
  printf '\n%sDPI and probe logging%s — records what reaches the carrier port from outside the\n' "$BOLD" "$N"
  printf 'tunnel-to-tunnel conversation (scans, active probes, replays, injected packets) and\n'
  printf 'what the path does to the packets in flight (loss, blocking, throttling, latency).\n'
  if ask_yn "Enable DPI/probe logging" "Y"; then CFG_DPI=true; else CFG_DPI=false; fi
  CFG_DPI_PROBE=true
  if [[ "$CFG_DPI" == true ]] && ! ask_yn "Send in-tunnel round-trip probes (needed for latency findings)" "Y"; then
    CFG_DPI_PROBE=false
  fi

  # --- Anti-DPI hardening (optional; all OFF by default) ---
  # These layer on top of the tunnel. Enable only what your path needs — a wrong option is at
  # best wasted packets. Full explanation in README section 15. They can also be toggled later
  # from the management menu (option x) without re-running this wizard.
  CFG_DESYNC=false; CFG_DESYNC_BADSUM=false; CFG_JUNK=false; CFG_HOP=false; CFG_SPLIT=false
  CFG_HOP_PORTS="443, 8443, 2053, 2083, 2087, 2096"
  CFG_ICMP_POOL=1; CFG_ICMP_ROT=60; CFG_ICMP_MIMIC=false; CFG_ICMP_READERS=0; CFG_ICMP_BATCH=32
  if [[ "$CFG_TRANSPORT" == "icmp" ]]; then
    icmp_setup_questions
  else
  printf '\n%sAnti-DPI hardening%s — optional, all off by default (README §15).\n' "$BOLD" "$N"
  if ask_yn "Native desync (in-process fake QUIC injector, replaces the zapret module)" "N"; then
    CFG_DESYNC=true
    ask_yn "  also corrupt the fakes' checksum (badsum: peer kernel drops them)" "N" && CFG_DESYNC_BADSUM=true
    ask_yn "  also IP-fragment the fakes (split)" "N" && CFG_SPLIT=true
  fi
  ask_yn "Flow-start cover traffic (junk: a burst of cover packets when the flow opens)" "N" && CFG_JUNK=true
  if ask_yn "Keyed port hopping (rotate the UDP port; defeats 5-tuple blocks; needs the ports open on BOTH ends; disables offload)" "N"; then
    CFG_HOP=true
    local hp; hp="$(ask "  port set — comma separated, IDENTICAL and in the same order on both servers" "443,8443,2053,2083,2087,2096")"
    CFG_HOP_PORTS="$(printf '%s' "$hp" | tr -d ' ' | sed 's/,/, /g')"
    printf '  %sRemember to open these ports in the cloud/OS firewall on BOTH servers.%s\n' "$Y" "$N"
  fi
  fi

  write_config
  write_service
  systemctl daemon-reload
  systemctl enable --now aestun >/dev/null 2>&1 && msg "Service enabled and started."
  if [[ "$CFG_TRANSPORT" == "icmp" ]]; then
    open_firewall_icmp
  else
    open_firewall "$CFG_LISTEN_PORT"
    if [[ "$CFG_HOP" == true ]]; then
      local p
      for p in ${CFG_HOP_PORTS//,/ }; do open_firewall "$p"; done
    fi
  fi

  # --- zapret (DPI desync on the carrier) ---
  #
  # On by default, and asked after the service is already up so a zapret failure can never
  # stop the tunnel from being installed. It is ordering-only in systemd (Before=aestun,
  # never Requires), and the NFQUEUE rule carries --queue-bypass, so even a wedged nfqws
  # passes traffic through untouched rather than blackholing the carrier.
  printf '\n'
  if [[ "$CFG_TRANSPORT" == "icmp" ]]; then
    printf '%szapret%s: skipped — nfqws desyncs TCP and UDP flows and has no ICMP mode, so\n' "$BOLD" "$N"
    printf '  arming it here would install rules that never match while systemd reports it\n'
    printf '  active. The equivalent for this carrier is built into the binary and is what\n'
    printf '  the "desync" block now means on ICMP: a burst of ordinary 64-byte decoy pings\n'
    printf '  carrying the tunnel'"'"'s own identifier, at a TTL that expires before the peer, so\n'
    printf '  a classifier watching from the first packet sees an ordinary ping session.\n'
    if ask_yn "Enable the native ICMP desync (decoy pings) on the carrier" "Y"; then
      CFG_DESYNC=true
      python3 - "$CONF" <<'PY'
import json,sys
p=sys.argv[1]; c=json.load(open(p))
d=c.setdefault("desync",{}); d["enabled"]=True
d.setdefault("repeats",4); d.setdefault("autottl",True); d.setdefault("delta",-1)
d.setdefault("min_ttl",3); d.setdefault("max_ttl",20); d.setdefault("badsum",False)
json.dump(c,open(p,"w"),indent=2)
PY
      chmod 600 "$CONF"
      systemctl restart aestun >/dev/null 2>&1 && msg "native ICMP desync enabled."
    fi
  else
    printf '%sDPI desync (zapret/nfqws) on the carrier port%s — recommended, on by default.\n' "$BOLD" "$N"
    printf '  Builds nfqws from source and desyncs the first few packets of the carrier flow,\n'
    printf '  which is the window a stateful DPI classifies it in. Needs git + a compiler.\n'
    if ask_yn "Install and enable zapret on ${CFG_TRANSPORT}/${CFG_LISTEN_PORT}" "Y"; then
      if zap_install quiet; then
        zap_enable quiet || warn "zapret built but could not be armed; enable it later from menu 'z'."
      else
        warn "zapret could not be built on this server. The tunnel is unaffected; retry from menu 'z'."
      fi
    fi
  fi

  # --- network optimization ---
  printf '\n'
  if ask_yn "Apply Ubuntu network optimization now (BBR, buffers, MTU probing, forwarding)" "Y"; then
    local cc buf fwd
    cc="$(ask "Congestion control (bbr/cubic)" "bbr")"
    [[ "$cc" == "bbr" || "$cc" == "cubic" ]] || { warn "Unknown congestion control '$cc' — using bbr."; cc="bbr"; }
    buf="$(ask_int "Max socket buffer size in bytes" "16777216")"
    if ask_yn "Enable IP forwarding" "Y"; then fwd=1; else fwd=0; fi
    apply_network_opt "$cc" "$buf" "$fwd"
  fi

  printf '\n'
  msg "Done on the ${CFG_ROLE^^} side."
  printf '%sNow run the SAME installer on the other server with:%s\n' "$D" "$N"
  printf '   - the %ssame key%s\n   - the opposite role (%s)\n   - peer = THIS server public IP\n' \
    "$BOLD" "$N" "$([[ $CFG_ROLE == a ]] && echo 'Foreign / b' || echo 'Iran / a')"
  return 0
}
# ------------------------------------------------------------------ service control
svc() { systemctl "$1" aestun && msg "service: $1 done." || err "operation '$1' failed."; }

service_menu() {
  while true; do
    local st; st="$(svc_active aestun)"
    hdr "Service management (current: ${st})"
    cat <<EOF
  ${C}1${N}) start
  ${C}2${N}) stop
  ${C}3${N}) restart
  ${C}4${N}) enable at boot
  ${C}5${N}) disable at boot
  ${C}6${N}) full status
  ${C}0${N}) back
EOF
    local __c; __c="$(ask 'Choose' '')" || { clear; exit 0; }
    case "$__c" in
      1) svc start ;;
      2) svc stop ;;
      3) svc restart ;;
      4) svc enable ;;
      5) svc disable ;;
      6) systemctl --no-pager status aestun | head -n 20 ;;
      0) return ;;
      *) warn "invalid option" ;;
    esac
    pause
  done
}

# =============================================================================
#  Monitoring plumbing — carrier discovery and fork-free stats reading
# =============================================================================
#  Everything below had one assumption baked into it: that the tunnel is a single
#  process writing /run/aestun/stats.json and logging to aestun.service. Under the
#  multi-protocol setup (§19) neither is true — four carriers each write their own
#  stats-<name>.json and log to aestun-path@<name>.service, and aestun.service is
#  deliberately stopped. So the dashboard read a file that does not exist and showed
#  zeroes, and "live logs" followed a unit that had been dead since the switch. The
#  monitoring section was blind on exactly the deployment it most needed to watch.
#
#  These helpers discover what is actually running instead of assuming.

# js_load — read a whole stats file into the associative array J, in one pass.
#
# The obvious shape for this is a js_get FILE KEY helper, and it is the wrong one: even
# with a fork-free body, every `$(js_get ...)` at the call site is a command substitution,
# which is a fork. Twenty keys across four carriers is eighty forks per refresh, twice a
# second — measured at 311 ms per refresh, which is the same mistake that made the
# multipath supervisor cost 70x the tunnel. Loading once into J and indexing it costs
# nothing, because a function call and an array subscript are both builtins.
declare -A J
js_load() { # js_load FILE  -> fills J with every scalar field
  J=()
  local line
  [[ -r "$1" ]] || return 1
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" =~ \"([A-Za-z_][A-Za-z0-9_]*)\"[[:space:]]*:[[:space:]]*(\"([^\"]*)\"|-?[0-9]+(\.[0-9]+)?|true|false) ]]; then
      if [[ "${BASH_REMATCH[2]}" == \"* ]]; then
        J["${BASH_REMATCH[1]}"]="${BASH_REMATCH[3]}"
      else
        J["${BASH_REMATCH[1]}"]="${BASH_REMATCH[2]}"
      fi
    fi
  done < "$1"
  return 0
}

# jnorm — force the counter fields to integers straight after a load, so the arithmetic
# below can index J directly. Reading them through a helper would mean $(helper), and a
# command substitution is a fork however cheap the helper's body is — which is the whole
# thing this is avoiding. A missing or damaged field becomes 0 rather than a shell error.
JINTS=(tx_bytes rx_bytes tx_packets rx_packets auth_fail replay_drop
       uptime_seconds last_rx_unix now_unix rekey_interval
       dpi_probes dpi_scans dpi_injections dpi_replays dpi_ttl_anomalies)
jnorm() {
  local k
  for k in "${JINTS[@]}"; do
    [[ "${J[$k]-}" =~ ^[0-9]+$ ]] || J[$k]=0
  done
}

# f100 — fixed-point for the two fields that are floats (loss_pct, rtt_ms), so "worst of"
# can be compared without forking to awk. Sets _F; "-", empty and junk become -1.
_F=0
f100() {
  local x="${1-}" i f
  if [[ -z "$x" || "$x" == "-" ]]; then _F=-1; return; fi
  i="${x%%.*}"; [[ "$i" =~ ^[0-9]+$ ]] || { _F=-1; return; }
  if [[ "$x" == *.* ]]; then f="${x#*.}00"; f="${f:0:2}"; else f="00"; fi
  [[ "$f" =~ ^[0-9]+$ ]] || f="00"
  _F=$(( 10#$i * 100 + 10#$f ))
}

# stats_files — every carrier stats file this host is writing, newest layout first.
# Prints "name:path" per line; name is "single" for the one-process deployment.
stats_files() {
  local f n found=0
  for f in /run/aestun/stats-*.json; do
    [[ -r "$f" ]] || continue
    n="${f##*/stats-}"; n="${n%.json}"
    printf '%s:%s\n' "$n" "$f"; found=1
  done
  (( found )) && return 0
  [[ -r "$STATS" ]] && printf 'single:%s\n' "$STATS"
}

# aestun_units — the systemd units that are the tunnel on this host right now.
# The data sink is a test harness, not the tunnel, so it is left out.
aestun_units() {
  local u out=0
  while read -r u; do
    [[ -z "$u" || "$u" == aestun-mp-sink.service ]] && continue
    printf '%s\n' "$u"; out=1
  done < <(systemctl list-units 'aestun*.service' --state=active --no-legend --plain 2>/dev/null | awk '{print $1}')
  (( out )) || printf 'aestun.service\n'
}

# read_stats — aggregate every carrier's counters into S_* globals in one pass.
# Sums what adds up (bytes, packets, failures), takes the worst of what does not
# (loss), the longest uptime, and the freshest receive.
read_stats() {
  S_TXB=0; S_RXB=0; S_TXP=0; S_RXP=0; S_AF=0; S_RD=0; S_UP=0; S_LASTRX=0; S_NOW=0
  S_PROBES=0; S_SCANS=0; S_INJ=0; S_REPL=0; S_TTLA=0; S_BH=""; S_DPI=""
  S_PEER=""; S_CIPHER=""; S_REKEY=0; S_LOSS="-"; S_RTT="-"
  S_CARRIERS=(); S_NAMES=()
  local entry name f v worst
  while IFS= read -r entry; do
    [[ -z "$entry" ]] && continue
    name="${entry%%:*}"; f="${entry#*:}"
    js_load "$f" || continue
    jnorm
    S_NAMES+=("$name")
    S_TXB=$((     S_TXB    + J[tx_bytes] ));         S_RXB=$((   S_RXB   + J[rx_bytes] ))
    S_TXP=$((     S_TXP    + J[tx_packets] ));       S_RXP=$((   S_RXP   + J[rx_packets] ))
    S_AF=$((      S_AF     + J[auth_fail] ));        S_RD=$((    S_RD    + J[replay_drop] ))
    S_PROBES=$((  S_PROBES + J[dpi_probes] ));       S_SCANS=$(( S_SCANS + J[dpi_scans] ))
    S_INJ=$((     S_INJ    + J[dpi_injections] ));   S_REPL=$((  S_REPL  + J[dpi_replays] ))
    S_TTLA=$((    S_TTLA   + J[dpi_ttl_anomalies] ))
    v=${J[uptime_seconds]}; (( v > S_UP ))     && S_UP=$v
    v=${J[last_rx_unix]};   (( v > S_LASTRX )) && S_LASTRX=$v
    v=${J[now_unix]};       (( v > S_NOW ))    && S_NOW=$v
    v=${J[rekey_interval]}; (( v > S_REKEY ))  && S_REKEY=$v
    [[ -z "$S_PEER"   ]] && S_PEER="${J[peer]-}"
    [[ -z "$S_CIPHER" ]] && S_CIPHER="${J[cipher]-}"
    [[ "${J[dpi_enabled]-}"        == true ]] && S_DPI=true
    [[ "${J[dpi_blackholed_now]-}" == true ]] && S_BH=true
    S_CARRIERS+=("$name|${J[rx_bytes]:-0}|${J[tx_bytes]:-0}|${J[auth_fail]:-0}|${J[loss_pct]:--}|${J[rtt_ms]:--}")
    # Worst loss and worst RTT across carriers is what an operator needs to see.
    f100 "$S_LOSS"; worst=$_F; f100 "${J[loss_pct]-}"; (( _F > worst )) && S_LOSS="${J[loss_pct]}"
    f100 "$S_RTT";  worst=$_F; f100 "${J[rtt_ms]-}";   (( _F > worst )) && S_RTT="${J[rtt_ms]}"
  done < <(stats_files)
  (( ${#S_NAMES[@]} > 0 ))
}

# =============================================================================
#  Live log — follow the tunnel processes themselves
# =============================================================================
#  "Live from the tunnel process" is the point: this is the journal of whichever
#  aestun units are actually running, merged, so it works the same on a single-path
#  and a multi-protocol install. The DPI observer already writes its non-routine
#  findings to stdout, so those arrive on this stream too and no second source is
#  needed.
#
#  Ctrl+C returns to the menu instead of killing the manager: `trap ':' INT` makes
#  the interrupt tear down the foreground pipeline and leave this shell running.
LIVE_DIR="/var/log/aestun"

# colourise_log — highlight the lines that mean something. Line-buffered via fflush,
# or the follow would arrive in 4 KiB lumps and stop being live.
colourise_log() {
  awk -v R="$R" -v Y="$Y" -v G="$G" -v C="$C" -v D="$D" -v N="$N" '
    { l=$0
      if (l ~ /\[dpi\] high|blackhole|inject|replay|FATAL|fatal|panic/)        printf "%s%s%s\n", R, l, N
      else if (l ~ /\[dpi\] warn|warning|throttle|loss_burst|rtt_spike|error/) printf "%s%s%s\n", Y, l, N
      else if (l ~ /recovered|tunnel up|carrier up|traffic ready|Started/)     printf "%s%s%s\n", G, l, N
      else if (l ~ /\[dpi\]/)                                                  printf "%s%s%s\n", C, l, N
      else                                                                     print l
      fflush() }'
}

live_log() {
  local -a units sel=()
  mapfile -t units < <(aestun_units)
  local u; for u in "${units[@]}"; do sel+=(-u "$u"); done
  clear; hdr "Live tunnel log — following the tunnel processes"
  printf '%s\n' "${D}  units: ${units[*]}${N}"
  printf '%s\n' "${D}  red = high severity / blackhole / injection   yellow = warn / throttle / loss${N}"
  printf '%s\n\n' "${D}  Ctrl+C returns to the menu.${N}"
  trap ':' INT
  journalctl "${sel[@]}" -f -n 40 --no-hostname -o short-iso 2>/dev/null | colourise_log
  trap - INT
  printf '\n'; msg "stopped following."
  pause
}

# record_log — the same live stream, captured to a file.
#
# Separate from the viewer on purpose: watching and keeping are different jobs. This
# one is what you run before reproducing a problem, so there is something to read
# afterwards and something to send to somebody else.
record_log() {
  mkdir -p "$LIVE_DIR"
  local -a units sel=()
  mapfile -t units < <(aestun_units)
  local u; for u in "${units[@]}"; do sel+=(-u "$u"); done

  local dur; dur="$(ask_int 'Record for how many seconds (0 = until Ctrl+C)' '0')"
  local out="${LIVE_DIR}/live-$(date +%Y%m%d-%H%M%S).log"
  clear; hdr "Recording the live tunnel log"
  printf '%s\n'   "${D}  units : ${units[*]}${N}"
  printf '%s\n'   "  file  : ${W}${out}${N}"
  [[ "$dur" == 0 ]] && printf '%s\n\n' "${D}  Ctrl+C to stop.${N}" \
                    || printf '%s\n\n' "${D}  stopping automatically after ${dur}s (Ctrl+C to stop sooner).${N}"

  # A header in the file itself, so a capture is self-describing when it is read back
  # somewhere else with no idea what produced it.
  {
    printf '# aestun live capture\n# host    : %s\n# started : %s\n# units   : %s\n' \
      "$(hostname)" "$(date -Is)" "${units[*]}"
    printf '# wire    : %s+%s  peer %s\n#\n' \
      "$(json_get "$CONF" transport)" "$(json_get "$CONF" obfs)" "$(json_get "$CONF" peer)"
  } > "$out"

  trap ':' INT
  if (( dur > 0 )); then
    timeout "$dur" journalctl "${sel[@]}" -f -n 0 --no-hostname -o short-iso 2>/dev/null \
      | tee -a "$out" | colourise_log
  else
    journalctl "${sel[@]}" -f -n 0 --no-hostname -o short-iso 2>/dev/null \
      | tee -a "$out" | colourise_log
  fi
  trap - INT

  # grep -c prints the count and still exits 1 when that count is zero, so the usual
  # `|| echo 0` idiom appends a second zero and the summary reads "0 0".
  local lines size hi wa
  lines="$(grep -vc '^#' "$out" 2>/dev/null)"; : "${lines:=0}"
  size="$(human "$(stat -c%s "$out" 2>/dev/null || echo 0)")"
  printf '\n'
  msg "capture saved: ${out}  (${lines} lines, ${size})"
  # A capture nobody reads is wasted; say what is in it up front.
  hi="$(grep -ci 'high\|blackhole\|inject\|replay\|fatal\|panic' "$out" 2>/dev/null)"; : "${hi:=0}"
  wa="$(grep -ci 'warn\|throttle\|loss_burst\|rtt_spike' "$out" 2>/dev/null)"; : "${wa:=0}"
  printf '  %shigh-severity lines: %s%s%s%s   warnings: %s%s%s\n' \
    "$D" "$R" "$hi" "$N" "$D" "$Y" "$wa" "$N"
  printf '  %sread it with:  less -R %s%s\n' "$D" "$out" "$N"
  pause
}

# --------------------------------------------------------------------- live monitor
monitor() {
  [[ -f "$CONF" ]] || { err "Set up the tunnel first."; pause; return; }
  local iface; iface="$(json_get "$CONF" tun_name)"; iface="${iface:-tun0}"
  local prev_tx=0 prev_rx=0 first=1 prev_epoch
  prev_epoch="$(date +%s)"
  while true; do
    # One pass over whatever carriers exist — single-path or all four of them.
    if ! read_stats; then
      clear; err "No carrier is publishing stats yet."
      printf '%s\n' "${D}  Nothing is writing /run/aestun/stats*.json. Start the tunnel (menu 3),${N}"
      printf '%s\n' "${D}  or the multi-protocol carriers (menu m -> 5).${N}"
      printf '%s\n' "${D}press q to quit, any other key to retry${N}"
      read -r -t 2 -n 1 key || true; [[ "${key:-}" == "q" ]] && break
      continue
    fi

    local now_epoch el dtx=0 drx=0
    now_epoch="$(date +%s)"; el=$(( now_epoch - prev_epoch )); (( el < 1 )) && el=1
    if [[ $first -eq 0 ]]; then dtx=$(( (S_TXB - prev_tx) / el )); drx=$(( (S_RXB - prev_rx) / el )); fi
    (( dtx < 0 )) && dtx=0; (( drx < 0 )) && drx=0
    prev_tx=$S_TXB; prev_rx=$S_RXB; prev_epoch=$now_epoch; first=0

    # Under multipath the meaningful "service" state is how many carriers are alive,
    # not whether the single-path unit happens to be running.
    local mode="single-path" svc_state svc_c="$R" live=0 total=${#S_NAMES[@]}
    declare -A UP=()
    if [[ "${S_NAMES[0]}" != "single" ]]; then
      mode="multipath"
      # One systemctl call for every carrier rather than one each: this runs twice a
      # second, and `is-active` takes a list and answers in order.
      local -a want=() states=()
      local n; for n in "${S_NAMES[@]}"; do want+=("aestun-path@${n}.service"); done
      mapfile -t states < <(systemctl is-active "${want[@]}" 2>/dev/null)
      local i
      for i in "${!S_NAMES[@]}"; do
        UP[${S_NAMES[$i]}]="${states[$i]:-unknown}"
        [[ "${states[$i]:-}" == active ]] && live=$(( live + 1 ))
      done
      svc_state="${live}/${total} carriers up"
      (( live == total )) && svc_c="$G" || { (( live > 0 )) && svc_c="$Y"; }
    else
      svc_state="$(svc_active aestun)"; [[ "$svc_state" == active ]] && svc_c="$G"
    fi

    local link="down" link_c="$R"
    if [[ -d "/sys/class/net/$iface" ]]; then
      local op; read -r op < "/sys/class/net/$iface/operstate" 2>/dev/null || op=""
      [[ "$op" == up || "$op" == unknown ]] && { link="up"; link_c="$G"; }
    fi

    local age="-" age_c="$Y"
    if (( S_LASTRX > 0 && S_NOW > 0 )); then
      age=$(( S_NOW - S_LASTRX )); (( age <= 15 )) && age_c="$G"; age="${age}s"
    fi
    local rk="static"; (( S_REKEY > 0 )) && rk="every ${S_REKEY}s"

    clear
    printf '%s\n' "${BOLD}${C}+-- aestun live monitor -------------------------------+${N}"
    printf '  mode     : %-12s %s%s%s\n' "$mode" "$svc_c" "$svc_state" "$N"
    printf '  uptime   : %-12s last RX: %s%s%s ago   iface %s: %s%s%s\n' \
      "$(fmt_dur "$S_UP")" "$age_c" "$age" "$N" "$iface" "$link_c" "$link" "$N"
    printf '  peer     : %s%s%s\n' "$W" "${S_PEER:-–}" "$N"
    printf '%s\n' "${C}+-- traffic (all carriers) ----------------------------+${N}"
    printf '  TX : %s%12s%s  (%s%s%s/s)  packets: %s\n' "$W" "$(human "$S_TXB")" "$N" "$G" "$(human "$dtx")" "$N" "$S_TXP"
    printf '  RX : %s%12s%s  (%s%s%s/s)  packets: %s\n' "$W" "$(human "$S_RXB")" "$N" "$G" "$(human "$drx")" "$N" "$S_RXP"

    # Per-carrier breakdown: under multipath the aggregate hides the one dead carrier,
    # which is precisely the thing worth seeing.
    if [[ "$mode" == multipath ]]; then
      printf '%s\n' "${C}+-- per carrier ---------------------------------------+${N}"
      printf '  %-6s %10s %10s %8s %7s %8s\n' "NAME" "RX" "TX" "AUTHFAIL" "LOSS%" "RTT_ms"
      local row nm rxb txb afl lsp rtm cc
      for row in "${S_CARRIERS[@]}"; do
        IFS='|' read -r nm rxb txb afl lsp rtm <<<"$row"
        cc="$G"; [[ "${UP[$nm]-}" == active ]] || cc="$R"
        (( afl > 0 )) && cc="$Y"
        printf '  %b%-6s%b %10s %10s %8s %7s %8s\n' "$cc" "$nm" "$N" \
          "$(human "$rxb")" "$(human "$txb")" "$afl" "$lsp" "$rtm"
      done
    fi

    printf '%s\n' "${C}+-- security ------------------------------------------+${N}"
    printf '  auth failures (auth_fail) : %s%s%s\n' "$Y" "$S_AF" "$N"
    printf '  replay drops              : %s%s%s\n' "$Y" "$S_RD" "$N"
    printf '  key rotation              : %s\n' "$rk"

    if [[ "$S_DPI" == true ]]; then
      # Anything non-zero in the first row is somebody paying attention to this port.
      local pc="$G"; (( S_PROBES > 0 || S_REPL > 0 || S_INJ > 0 || S_TTLA > 0 )) && pc="$R"
      printf '%s\n' "${C}+-- DPI observer --------------------------------------+${N}"
      printf '  active probes / replays   : %s%s%s / %s%s%s\n' "$pc" "$S_PROBES" "$N" "$pc" "$S_REPL" "$N"
      printf '  injections / TTL anomalies: %s%s%s / %s%s%s\n' "$pc" "$S_INJ" "$N" "$pc" "$S_TTLA" "$N"
      printf '  background scanning       : %s\n' "$S_SCANS"
      printf '  worst loss / RTT          : %s%%  /  %s ms\n' "$S_LOSS" "$S_RTT"
      [[ "$S_BH" == true ]] && printf '  %scarrier looks BLOCKED — sending, nothing coming back%s\n' "$R" "$N"
    fi
    [[ -n "$S_CIPHER" ]] && printf '%s\n' "${D}  cipher: ${S_CIPHER}${N}"
    printf '%s\n' "${C}+-----------------------------------------------------+${N}"
    printf '%s\n' "${D}refresh every 2s — press l for the live log, r to record it, q to quit${N}"

    read -r -t 2 -n 1 key || true
    case "${key:-}" in
      q) break ;;
      l|L) live_log ;;
      r|R) record_log ;;
    esac
  done
}

# ------------------------------------------------------------------- connectivity
test_conn() {
  [[ -f "$CONF" ]] || { err "Set up the tunnel first."; pause; return; }
  local peer_ip; peer_ip="$(json_get "$CONF" peer_ip)"
  hdr "Connectivity test over the tunnel"
  [[ -z "$peer_ip" ]] && { err "peer_ip not set in config."; pause; return; }
  printf 'Pinging %s%s%s (peer tunnel IP)...\n\n' "$W" "$peer_ip" "$N"
  if ping -c 4 -W 2 "$peer_ip"; then
    printf '\n'; msg "Tunnel link is healthy."
  else
    printf '\n'
    if [[ "$(json_get "$CONF" transport)" == "icmp" ]]; then
      err "No reply. Check: both services active, ICMP echo allowed in BOTH cloud firewalls,"
      err "the same key/roles, and the same icmp.id_pool / icmp.mimic_ping on both servers."
    else
      err "No reply. Check: both services active, carrier port open, key/roles correct."
    fi
  fi
  pause
}

show_logs() {
  # Follows whatever is actually running. It used to name aestun.service outright, which
  # on a multi-protocol install is the one unit deliberately stopped — so this screen was
  # empty on exactly the deployment with four carriers to watch.
  local -a units sel=()
  mapfile -t units < <(aestun_units)
  local u; for u in "${units[@]}"; do sel+=(-u "$u"); done
  hdr "Live logs (Ctrl+C to exit)"
  printf '%s\n\n' "${D}units: ${units[*]}${N}"
  trap ':' INT
  journalctl "${sel[@]}" -f -n 50 --no-hostname 2>/dev/null || journalctl "${sel[@]}" -n 50 --no-pager
  trap - INT
}

edit_config() {
  [[ -f "$CONF" ]] || { err "No config present."; pause; return; }
  "${EDITOR:-nano}" "$CONF"
  if confirm "Restart the service to apply changes?"; then systemctl restart aestun && msg "restarted."; fi
  pause
}

do_keygen() {
  ensure_binary || { pause; return; }
  hdr "New key"
  local k; k="$("$BIN_DST" keygen)"
  printf 'Shared key (use the SAME on both servers):\n\n   %s%s%s\n\n' "$BOLD" "$k" "$N"
  pause
}

show_config() {
  hdr "Current config"
  if [[ -f "$CONF" ]]; then
    sed -E 's/("key"[[:space:]]*:[[:space:]]*")[^"]+(")/\1********\2/' "$CONF"
  else
    warn "Not configured yet."
  fi
  pause
}

# ----------------------------------------------------------- network optimization
netopt_menu() {
  while true; do
    hdr "Network optimization"
    cat <<EOF
  ${C}1${N}) show current settings
  ${C}2${N}) apply / re-apply tuning
  ${C}3${N}) remove tuning
  ${C}0${N}) back
EOF
    local __c; __c="$(ask 'Choose' '')" || { clear; exit 0; }
    case "$__c" in
      1) show_network_opt; pause ;;
      2)
        local cc buf fwd
        cc="$(ask 'Congestion control (bbr/cubic)' 'bbr')"
        buf="$(ask 'Max socket buffer size in bytes' '16777216')"
        if ask_yn 'Enable IP forwarding' 'Y'; then fwd=1; else fwd=0; fi
        apply_network_opt "$cc" "$buf" "$fwd"; pause ;;
      3) remove_network_opt; pause ;;
      0) return ;;
      *) warn "invalid option"; sleep 1 ;;
    esac
  done
}

# =============================================================================
#  zapret module (DPI desync on the tunnel carrier packets)
# =============================================================================
zap_installed() { [[ -x "$ZAP_BIN" ]]; }

# zap_install [quiet] — build nfqws from source. With "quiet" it never pauses and returns a
# status instead, so the installer can run it as one step of the wizard.
zap_install() {
  local quiet="${1:-}"
  local _p=pause; [[ "$quiet" == quiet ]] && _p=:
  zap_installed && { msg "zapret already built: ${ZAP_BIN}"; return 0; }
  hdr "Install zapret (builds nfqws from source)"
  # Upstream zapret ships NO prebuilt binaries in the git tree, so we build nfqws.
  ensure_deps
  export DEBIAN_FRONTEND=noninteractive
  msg "Installing build dependencies..."
  apt-get update -y >/dev/null 2>&1 || true
  if ! apt-get install -y git iptables build-essential zlib1g-dev \
        libnetfilter-queue-dev libnfnetlink-dev libmnl-dev libcap-dev >/dev/null 2>&1; then
    err "Failed to install build dependencies (apt)."; $_p; return 1
  fi

  if [[ -d "$ZAPRET_DIR/.git" ]]; then
    warn "Repo present; updating..."; ( cd "$ZAPRET_DIR" && git pull --ff-only ) >/dev/null 2>&1 || warn "git pull failed (continuing)."
  else
    msg "Cloning zapret..."
    git clone --depth 1 https://github.com/bol-van/zapret "$ZAPRET_DIR" \
      || { err "git clone failed (no route to GitHub from this server?)."; $_p; return 1; }
  fi

  msg "Building nfqws..."
  local rc=0
  if make -C "$ZAPRET_DIR/nfq" nfqws >/tmp/nfqws-build.log 2>&1 && zap_installed; then
    msg "zapret ready: ${ZAP_BIN}"
    "$ZAP_BIN" --version 2>/dev/null | head -1 || true
  else
    err "Build failed. Last lines of /tmp/nfqws-build.log:"; tail -8 /tmp/nfqws-build.log
    rc=1
  fi
  $_p
  return $rc
}

# zap_enable [quiet] — arm nfqws on the carrier. With "quiet" it never pauses, so the
# installer can turn it on without interrupting the wizard.
zap_enable() {
  local quiet="${1:-}"
  local _p=pause; [[ "$quiet" == quiet ]] && _p=:
  hdr "Enable zapret on the tunnel carrier"
  zap_installed || { err "Install zapret first (option 1)."; $_p; return 1; }
  [[ -f "$CONF" ]] || { err "Set up the tunnel first."; $_p; return 1; }

  local host port qnum=200 transport desync
  IFS='|' read -r host port transport < <(carrier_endpoint)
  if [[ "$transport" == "icmp" ]]; then
    # Stated plainly rather than half-applied. zapret's nfqws desyncs TCP and UDP flows via
    # NFQUEUE; it has no ICMP mode, and the carrier here is echo-request payloads. Arming it
    # would install rules that match nothing and report "active" while doing nothing at all,
    # which is worse than not running it. The ICMP carrier's own anti-DPI work is in the
    # binary instead: identifier rotation, ping mimicry and rate shaping (menu 'i').
    err "The carrier transport is \"icmp\". zapret/nfqws desyncs TCP and UDP only — it has no"
    err "ICMP mode, so enabling it here would arm rules that never match."
    warn "Use the ICMP carrier's own anti-DPI settings instead: menu 'i' (id rotation, ping"
    warn "mimicry) and \"rate_mbps\" in the config, which is what actually limits volumetric"
    warn "exposure on a ping carrier."
    $_p; return 1
  fi
  [[ -n "$port" ]] || { err "Could not read a carrier port from config."; $_p; return 1; }
  [[ -n "$host" ]] || { err "Could not read the peer host from config."; $_p; return 1; }

  # Cover ALL protocols in one nfqws using two profiles (matched first-to-last):
  #   1) TCP on the carrier port -> multisplit (fragments the TLS-record stream; the peer
  #      reassembles transparently so the tunnel is never corrupted, on-path DPI sees a split).
  #   2) everything else (the UDP carrier, and any other protocol) -> fake injection with
  #      --dpi-desync-any-protocol so it acts on the carrier's opaque payload regardless of L7.
  # The NFQUEUE rule (zap_rule) queues both tcp and udp, so whichever transport the tunnel
  # uses is desynced — and it keeps working if you switch transport later.
  desync="--filter-tcp=${port} --dpi-desync=multisplit --dpi-desync-split-pos=1,4,8"
  desync+=" --new --dpi-desync=fake --dpi-desync-any-protocol=1 --dpi-desync-cutoff=n8 --dpi-desync-repeats=2 --dpi-desync-fooling=badsum"
  printf 'Carrier = %s%s / %s:%s%s — desync covers TCP (multisplit) + UDP/any (fake)\n' "$W" "$transport" "$host" "$port" "$N"

  command -v conntrack >/dev/null 2>&1 || apt-get install -y conntrack >/dev/null 2>&1 || \
    warn "conntrack not installed — zapret will arm but never fire (see the 'rearm' step)."

  # Remove any previous rule (e.g. from an earlier port/proto) before regenerating.
  zap_rule del 2>/dev/null || true

  # Install this script where systemd can call it; the rule logic (zap-rule) reads
  # peer/port/transport from the config itself, so it is identical on both ends.
  install -m 0755 "$SELF" "$MGR_DST" || { err "could not install manager to ${MGR_DST}."; pause; return; }

  cat > "$ZAP_SERVICE" <<EOF
[Unit]
Description=aestun-zapret - DPI desync (nfqws) for the tunnel carrier
After=network-online.target
Wants=network-online.target
# Ordering only, never a requirement: if zapret fails, aestun must still come up.
# It has to precede aestun so the NFQUEUE rule is in place when the carrier flow
# opens — started afterwards, the flow is already past the connbytes window.
Before=aestun.service

[Service]
Type=simple
ExecStartPre=${MGR_DST} zap-rule add
# --dpi-desync-cutoff=n8 : hard stop after 8 packets, enforced inside nfqws.
#   Without it nfqws desyncs every packet, blocks on the raw-socket send buffer
#   (sock_alloc_send_pskb) and wedges — systemd still reports "active" while the
#   queue stops draining entirely. Second line of defence behind the connbytes match.
# --dpi-desync-repeats=2 : 6 multiplied outbound packets enough to congest the
#   uplink; measured tunnel loss went 1.7% -> 7.8%.
# --dpi-desync-fooling=badsum : fakes carry a bad checksum so the peer's kernel drops
#   them before aestun sees them. Without it they cross the whole path only to be
#   rejected by AEAD auth, wasting bandwidth and inflating auth_fail.
ExecStart=${ZAP_BIN} --qnum=${qnum} ${desync}
ExecStartPost=${MGR_DST} zap-rule rearm
ExecStopPost=${MGR_DST} zap-rule del
Restart=always
RestartSec=3
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable aestun-zapret >/dev/null 2>&1
  # restart (not just start) so ExecStopPost/ExecStartPre re-run and pick up the current port
  systemctl restart aestun-zapret >/dev/null 2>&1 && msg "zapret enabled (${transport}/${port} desync via nfqws)."
  sleep 5
  local fired; fired="$(awk -v q="$qnum" '$1==q {print $8}' /proc/net/netfilter/nfnetlink_queue 2>/dev/null)"
  if [[ -n "$fired" && "$fired" -gt 0 ]]; then
    msg "Desync fired on ${fired} carrier packet(s), then stopped — this is the expected steady state."
  else
    warn "Queue saw no packets. zapret is armed but did nothing; check that conntrack is installed."
  fi
  warn "If traffic breaks, disable this module. Tune the desync mode with zapret's blockcheck.sh."
  $_p
}

zap_disable() {
  systemctl disable --now aestun-zapret >/dev/null 2>&1 || true
  zap_rule del 2>/dev/null || true
  msg "zapret disabled."; pause
}

zap_status() {
  hdr "zapret status"
  if zap_installed; then msg "installed: yes (${ZAPRET_DIR})"; else warn "installed: no"; fi
  systemctl --no-pager status aestun-zapret 2>/dev/null | head -n 12 || warn "zapret service not active."
  printf '\niptables rules (mangle/OUTPUT):\n'
  iptables -t mangle -S OUTPUT 2>/dev/null | grep NFQUEUE || printf '  (none)\n'

  # systemd reporting "active" is not enough. nfqws can block on its raw-socket send
  # buffer and stop reading the queue entirely while the unit still looks healthy, so
  # check the kernel's own counters and where the process is parked.
  printf '\nqueue health:\n'
  local line pid qtotal qdrop udrop seq
  line="$(awk 'NR==1{print}' /proc/net/netfilter/nfnetlink_queue 2>/dev/null)"
  if [[ -z "$line" ]]; then
    warn "  no queue registered (nfqws not bound)"
  else
    read -r _ pid qtotal _ _ qdrop udrop seq _ <<<"$line"
    printf '  backlog=%s  queue_dropped=%s  user_dropped=%s  packets_seen=%s\n' \
           "$qtotal" "$qdrop" "$udrop" "$seq"
    local wchan; wchan="$(cat "/proc/${pid}/wchan" 2>/dev/null)"
    printf '  nfqws parked in: %s\n' "${wchan:-?}"
    if [[ "$wchan" == sock_alloc_send_pskb* ]]; then
      err "  WEDGED — blocked sending fakes, queue is not draining. Re-enable (option 2) to reset."
    elif (( qtotal > 100 )); then
      warn "  backlog is high; nfqws is not keeping up with the carrier."
    else
      msg "  healthy — desync fired on ${seq} packet(s) then went idle."
    fi
  fi
  pause
}

zap_remove() {
  zap_disable
  rm -f "$ZAP_SERVICE" "$ZAP_RULES"; systemctl daemon-reload
  confirm "Also delete the ${ZAPRET_DIR} directory?" && rm -rf "$ZAPRET_DIR"
  msg "zapret removed."; pause
}

zapret_menu() {
  while true; do
    local ins="no"; zap_installed && ins="yes"
    local act; act="$(svc_active aestun-zapret)"
    hdr "zapret — DPI bypass (installed: ${ins} | service: ${act})"
    if [[ -f "$CONF" && "$(json_get "$CONF" transport)" == "icmp" ]]; then
      # Said here as well as in zap_enable, because "active" on this menu with an ICMP
      # carrier is exactly the misleading state this module can get into.
      printf '  %sCarrier is ICMP: nfqws desyncs TCP and UDP only and cannot act on this\n' "$Y"
      printf '  carrier. Its equivalent is the native decoy-ping injector — menu x.%s\n' "$N"
    fi
    cat <<EOF
  ${C}1${N}) install / update zapret
  ${C}2${N}) enable on the tunnel port
  ${C}3${N}) disable
  ${C}4${N}) status
  ${C}5${N}) remove completely
  ${C}0${N}) back
EOF
    local __c; __c="$(ask 'Choose' '')" || { clear; exit 0; }
    case "$__c" in
      1) zap_install ;;
      2) zap_enable ;;
      3) zap_disable ;;
      4) zap_status ;;
      5) zap_remove ;;
      0) return ;;
      *) warn "invalid option"; sleep 1 ;;
    esac
  done
}

# --------------------------------------------------------------------- uninstall
uninstall_all() {
  hdr "Uninstall tunnel"
  confirm "Are you sure? service, binary and config will be removed" || return
  local port; port="$(json_get "$CONF" listen)"; port="${port##*:}"
  local iface; iface="$(json_get "$CONF" tun_name)"; iface="${iface:-tun0}"
  systemctl disable --now aestun >/dev/null 2>&1 || true
  zap_rule del 2>/dev/null || true
  systemctl disable --now aestun-zapret >/dev/null 2>&1 || true
  rm -f "$SERVICE" "$ZAP_SERVICE" "$ZAP_RULES" "$BIN_DST"
  systemctl daemon-reload
  ip link del "$iface" 2>/dev/null || true
  # The ICMP carrier installs echo-reply DROP rules that outlive the process. The binary
  # removes them on SIGTERM, but a rule left by an older build (or a hard kill) would stay
  # for ever and silently break ordinary ping to the peer, so sweep them by their comment.
  local r
  while read -r r; do
    [[ -n "$r" ]] && eval "iptables -w -D OUTPUT ${r#-A OUTPUT }" 2>/dev/null || true
  done < <(iptables -S OUTPUT 2>/dev/null | grep -- '--comment "aestun icmp carrier"' | sed 's/--comment "aestun icmp carrier"/--comment "aestun icmp carrier"/')
  nft delete table ip aestun 2>/dev/null || true
  [[ -n "$port" ]] && close_firewall "$port"
  confirm "Remove network optimization (sysctl tuning) too?" && remove_network_opt
  confirm "Delete config directory ${CONF_DIR}?" && rm -rf "$CONF_DIR"
  confirm "Delete zapret directory ${ZAPRET_DIR}?" && rm -rf "$ZAPRET_DIR"
  msg "Everything removed."
  pause
}

# ----------------------------------------------------------------- main menu
# =============================================================================
#  DPI / probe log
# =============================================================================
dpi_enabled_in_cfg() {
  [[ -f "$CONF" ]] || return 1
  # A config written before this feature existed has no dpi_log block at all; the daemon
  # defaults it on, so "absent" reads as enabled here too.
  grep -q '"dpi_log"' "$CONF" || return 0
  ! grep -q '"enabled"[[:space:]]*:[[:space:]]*false' "$CONF"
}

dpi_log_path() {
  local p
  p="$(sed -n 's/.*"path"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$CONF" 2>/dev/null | tail -1)"
  printf '%s' "${p:-$DPI_LOG}"
}

# dpi_set_enabled true|false — rewrite the dpi_log block in place.
dpi_set_enabled() {
  local want="$1" lp
  [[ -f "$CONF" ]] || { err "Set up the tunnel first."; return 1; }
  lp="$(dpi_log_path)"
  if grep -q '"dpi_log"' "$CONF"; then
    python3 - "$CONF" "$want" <<'PY'
import json,sys
p,want=sys.argv[1],sys.argv[2]=="true"
c=json.load(open(p))
c.setdefault("dpi_log",{})["enabled"]=want
json.dump(c,open(p,"w"),indent=2)
PY
  else
    python3 - "$CONF" "$want" "$lp" <<'PY'
import json,sys
p,want,lp=sys.argv[1],sys.argv[2]=="true",sys.argv[3]
c=json.load(open(p))
c["dpi_log"]={"enabled":want,"path":lp,"probe":True}
json.dump(c,open(p,"w"),indent=2)
PY
  fi
  chmod 600 "$CONF"
  msg "dpi_log.enabled = $want"
  if ask_yn "Restart aestun now to apply" "Y"; then systemctl restart aestun && msg "restarted."; fi
}

dpi_menu() {
  while true; do
    clear
    local state="off" sc="$R" lp sz
    dpi_enabled_in_cfg && { state="on"; sc="$G"; }
    lp="$(dpi_log_path)"
    sz="-"; [[ -f "$lp" ]] && sz="$(du -h "$lp" 2>/dev/null | cut -f1)"
    printf '%s\n' "${BOLD}${C}+-- DPI / probe log -----------------------------------+${N}"
    printf '  state: %s%s%s    log: %s (%s)\n\n' "$sc" "$state" "$N" "$lp" "$sz"
    printf '%s\n' "${D}  Records who talks to the carrier port from outside the tunnel-to-tunnel${N}"
    printf '%s\n' "${D}  conversation, and what the path does to the packets in flight.${N}"
    cat <<EOF

  ${C}1${N}) Report — last 24 hours
  ${C}2${N}) Report — last 7 days
  ${C}3${N}) Live tail (high/warn findings)
  ${C}4${N}) Raw log tail
  ${C}5${N}) Self-test: send probe traffic at THIS server and see it logged
  ${C}6${N}) Enable / disable
  ${C}7${N}) Clear the log
  ${C}0${N}) Back
EOF
    local c; c="$(ask 'Choose' '')" || return
    case "$c" in
      1) clear; "$BIN_DST" dpi-report -log "$lp" -hours 24 2>&1 | ${PAGER:-less} -R ;;
      2) clear; "$BIN_DST" dpi-report -log "$lp" -hours 168 2>&1 | ${PAGER:-less} -R ;;
      3) clear
         printf '%s\n' "${D}streaming findings — Ctrl-C to stop${N}"
         # journalctl carries the same lines because the daemon mirrors non-info events there.
         journalctl -u aestun -f -o cat 2>/dev/null | grep --line-buffered '\[dpi\]' ;;
      4) clear; tail -f "$lp" ;;
      5) dpi_selftest ;;
      6) if dpi_enabled_in_cfg; then dpi_set_enabled false; else dpi_set_enabled true; fi; pause ;;
      7) if confirm "Delete $lp and its rotated copies?"; then
           rm -f "$lp" "$lp".[0-9]; msg "cleared."
         fi; pause ;;
      0) return ;;
      *) warn "invalid option"; sleep 1 ;;
    esac
  done
}

# dpi_selftest — send this server's own carrier port the traffic a prober would, then show
# what the observer made of it. The point is that you can confirm the detector works on your
# own box instead of waiting to find out during a real incident.
dpi_selftest() {
  clear
  [[ -f "$CONF" ]] || { err "Set up the tunnel first."; pause; return; }
  if [[ "$(json_get "$CONF" transport)" == "icmp" ]]; then
    # The self-test sends UDP at the carrier's listen port. On the ICMP carrier nothing binds
    # a port, so every probe would land on a closed port and the observer would record
    # nothing — a green "no findings" that means only that the test missed.
    err "The carrier is ICMP, which binds no port — this self-test sends UDP probes and would"
    err "measure nothing at all."
    warn "The observer is still live on this carrier: it classifies stray echo requests that"
    warn "carry this tunnel's identifier but fail to authenticate, and reports the raw socket's"
    warn "own drop counter. Use option 1 (report) to read what it has actually seen."
    pause; return
  fi
  local port lp
  port="$(json_get "$CONF" listen)"; port="${port##*:}"
  lp="$(dpi_log_path)"
  hdr "DPI observer self-test"
  printf 'Sending probe traffic to 127.0.0.1:%s — the same port the tunnel listens on.\n' "$port"
  printf '%sThis is local traffic only; nothing leaves the machine.%s\n\n' "$D" "$N"

  # Probe in the handshake format this tunnel actually speaks, so the self-test exercises
  # the code path in use rather than one the config never reaches. obfs=none has no
  # handshake cover of its own, so it falls back to a QUIC Initial — which is exactly what
  # an unsolicited prober would send at it.
  local pmode; pmode="$(json_get "$CONF" obfs 2>/dev/null)"
  case "$pmode" in quic|quic2|dtls) ;; *) pmode="quic" ;; esac
  printf '  1/2  %s handshake (what an active prober sends)...\n' "$pmode"
  "$BIN_DST" probe -target "127.0.0.1:${port}" -mode "$pmode" -sni www.google.com -count 3 || true
  printf '  2/2  random datagrams (what a port scanner sends)...\n'
  "$BIN_DST" probe -target "127.0.0.1:${port}" -mode junk -count 25 -size 200 || true

  local flush=65
  printf '\nThe observer aggregates per source and flushes every %ss, so nothing appears\n' "$flush"
  printf 'instantly — that is what keeps a scan from writing one line per packet.\n'
  printf 'Waiting %ss' "$flush"
  for _ in $(seq 1 $flush); do printf '.'; sleep 1; done
  printf '\n\n'
  "$BIN_DST" dpi-report -log "$lp" -hours 1
  pause
}

# =============================================================================
#  Anti-DPI hardening menu (desync / junk / port-hop / split)
# =============================================================================
antidpi_state() { # prints e.g. "desync=on junk=off hop=off split=off"
  [[ -f "$CONF" ]] || { printf 'no-config'; return; }
  python3 - "$CONF" 2>/dev/null <<'PY' || printf 'parse-error'
import json,sys
c=json.load(open(sys.argv[1]))
def st(k):
    v=c.get(k,{})
    return "on" if isinstance(v,dict) and v.get("enabled") else "off"
print("obfs=%s desync=%s junk=%s hop=%s split=%s"%(c.get("obfs","none"),st("desync"),st("junk"),st("hop"),st("split")))
PY
}

# antidpi_set_obfs — change the wire disguise in place. Must be changed on BOTH servers:
# the two formats are not negotiated, so a mismatch means every packet fails to open.
antidpi_set_obfs() {
  [[ -f "$CONF" ]] || { err "No config."; return 1; }
  printf '\n%sWire disguise%s (must match on BOTH servers)\n' "$BOLD" "$N"
  printf '  %snone%s  raw high-entropy datagrams\n' "$C" "$N"
  printf '  %squic%s  QUIC v1 cover — note: Iranian carriers were measured dropping every\n' "$C" "$N"
  printf '        v1 long-header packet, so the cover never arrives (tunnel still runs)\n'
  printf '  %squic2%s QUIC v2 cover (RFC 9369) — passes where v1 is dropped\n' "$C" "$N"
  printf '  %sdtls%s  DTLS 1.2 records + ClientHello cover (UDP only)\n' "$C" "$N"
  local m; m="$(ask 'Mode (none/quic/quic2/dtls)' "$(json_get "$CONF" obfs)")" || return 1
  case "$m" in
    none|quic|quic2|dtls) ;;
    *) warn "Unknown mode '$m' — unchanged."; return 1 ;;
  esac
  python3 - "$CONF" "$m" <<'PY'
import json,sys
p=sys.argv[1]
c=json.load(open(p))
c["obfs"]=sys.argv[2]
if sys.argv[2]=="dtls" and c.get("transport")=="tcp":
    print("dtls is UDP-only; leaving transport tcp would fail to start — switching to udp.")
    c["transport"]="udp"
json.dump(c,open(p,"w"),indent=2)
PY
  chmod 600 "$CONF"
  msg "obfs set to '$m'. Set the SAME value on the other server, then restart both."
}

antidpi_set() { # antidpi_set MODULE true|false
  [[ -f "$CONF" ]] || { err "Set up the tunnel first."; return 1; }
  python3 - "$CONF" "$1" "$2" <<'PY'
import json,sys
p,mod,want=sys.argv[1],sys.argv[2],sys.argv[3]=="true"
c=json.load(open(p))
c.setdefault(mod,{})["enabled"]=want
# fill sane defaults if the block was absent, so a first enable is complete
d=c[mod]
if mod=="desync": d.setdefault("repeats",4); d.setdefault("autottl",True); d.setdefault("delta",-1); d.setdefault("badsum",False)
if mod=="junk":   d.setdefault("count",8); d.setdefault("min_ms",5); d.setdefault("max_ms",50)
if mod=="hop":    d.setdefault("ports",[443,8443,2053,2083,2087,2096]); d.setdefault("interval",30)
if mod=="split":  d.setdefault("frag_pos",24)
json.dump(c,open(p,"w"),indent=2)
PY
  chmod 600 "$CONF"
}

antidpi_set_hop_ports() {
  local hp; hp="$(ask "Port set (comma separated, IDENTICAL and same order on BOTH servers)" "443,8443,2053,2083,2087,2096")"
  hp="$(printf '%s' "$hp" | tr -d ' ')"
  python3 - "$CONF" "$hp" <<'PY'
import json,sys
p,ports=sys.argv[1],[int(x) for x in sys.argv[2].split(',') if x.strip().isdigit()]
c=json.load(open(p))
c.setdefault("hop",{})["ports"]=ports or [443,8443,2053,2083,2087,2096]
json.dump(c,open(p,"w"),indent=2)
PY
  chmod 600 "$CONF"
  local p
  for p in ${hp//,/ }; do open_firewall "$p"; done
  msg "hop ports set. Open them in the cloud firewall on BOTH servers."
}

# icmp_menu — the ICMP carrier's settings, live. Same split as the wizard: the top group is
# local to this host, the bottom group changes the wire and has to be mirrored on the peer.
icmp_menu() {
  [[ -f "$CONF" ]] || { err "Set up the tunnel first."; pause; return; }
  if [[ "$(json_get "$CONF" transport)" != "icmp" ]]; then
    warn "The carrier transport is not 'icmp' — these settings are ignored until it is."
    confirm "Show them anyway" || return
  fi
  while true; do
    clear
    local cur
    cur="$(python3 - "$CONF" 2>/dev/null <<'PY'
import json,sys
c=json.load(open(sys.argv[1])).get("icmp",{})
print("readers=%s batch=%s filter=%s suppress=%s id_pool=%s rotate=%ss mimic=%s" % (
  c.get("readers",0), c.get("batch",32), c.get("kernel_filter",True),
  c.get("suppress_replies",True), c.get("id_pool",1), c.get("id_rotate_sec",60),
  c.get("mimic_ping",False)))
PY
)"
    printf '%s\n' "${BOLD}${C}+-- ICMP carrier ------------------------------------+${N}"
    printf '  current: %s%s%s\n\n' "$W" "${cur:-unreadable}" "$N"
    printf '%s\n' "${D}  1-3 are local to this host and may differ between the two servers.${N}"
    printf '%s\n' "${D}  4-6 change the wire and MUST be identical on BOTH servers.${N}"
    cat <<EOF

  ${C}1${N}) receive goroutines      (0 = one per core, capped at 8)
  ${C}2${N}) messages per syscall    (sendmmsg/recvmmsg batch; 1 = off)
  ${C}3${N}) toggle kernel packet filter (BPF on the raw socket)
  ${C}4${N}) identifier pool size    (1 = no rotation, max 8)
  ${C}5${N}) identifier rotation interval
  ${C}6${N}) toggle ping mimicry     (16-byte timeval prefix)
  ${C}7${N}) toggle echo-reply suppression (firewall rule)
  ${C}0${N}) back (restart to apply)
EOF
    local c; c="$(ask 'Choose' '')" || return
    case "$c" in
      1) icmp_set readers "$(ask_int 'Receive goroutines' '0')" ;;
      2) icmp_set batch "$(ask_int 'Messages per syscall' '32')" ;;
      3) icmp_toggle kernel_filter ;;
      4) icmp_set id_pool "$(ask_int 'Identifiers in the set (1-8)' '1')"
         warn "Set the SAME id_pool on the other server, then restart both." ;;
      5) icmp_set id_rotate_sec "$(ask_int 'Seconds per identifier' '60')"
         warn "Set the SAME interval on the other server, then restart both." ;;
      6) icmp_toggle mimic_ping
         warn "Ping mimicry must match on BOTH servers, or every packet fails to authenticate." ;;
      7) icmp_toggle suppress_replies ;;
      0) if confirm "Restart aestun now to apply changes?"; then systemctl restart aestun && msg "restarted."; fi
         return ;;
      *) warn "invalid option"; sleep 1 ;;
    esac
  done
}

icmp_set() { # icmp_set KEY INT
  python3 - "$CONF" "$1" "$2" <<'PY'
import json,sys
p,k,v=sys.argv[1],sys.argv[2],int(sys.argv[3])
c=json.load(open(p)); c.setdefault("icmp",{})[k]=v
json.dump(c,open(p,"w"),indent=2)
PY
  chmod 600 "$CONF"
}

icmp_toggle() { # icmp_toggle KEY
  python3 - "$CONF" "$1" <<'PY'
import json,sys
p,k=sys.argv[1],sys.argv[2]
c=json.load(open(p)); d=c.setdefault("icmp",{})
d[k]=not d.get(k, k in ("kernel_filter","suppress_replies"))
json.dump(c,open(p,"w"),indent=2)
print("%s is now %s"%(k,d[k]))
PY
  chmod 600 "$CONF"
}

antidpi_menu() {
  if [[ -f "$CONF" && "$(json_get "$CONF" transport)" == "icmp" ]]; then
    # On a ping carrier obfs is refused by the binary and port hopping has no ports to hop.
    # desync and junk do apply — the binary dispatches "desync" to the ICMP injector (decoy
    # pings) rather than the QUIC one — so offer exactly those two.
    while true; do
      clear
      local st; st="$(antidpi_state)"
      printf '%s\n' "${BOLD}${C}+-- Anti-DPI hardening (ICMP carrier) ---------------+${N}"
      printf '  current: %s%s%s\n\n' "$W" "$st" "$N"
      printf '%s\n' "${D}  desync = a burst of ordinary 64-byte decoy pings carrying this tunnel's${N}"
      printf '%s\n' "${D}           identifier, at a TTL that expires before the peer${N}"
      printf '%s\n' "${D}  junk   = flow-start cover traffic${N}"
      printf '%s\n' "${D}  obfs and port hopping do not apply on this carrier; identifier rotation${N}"
      printf '%s\n' "${D}  and ping mimicry live in menu 'i'.${N}"
      cat <<EOF

  ${C}1${N}) toggle desync (decoy pings)
  ${C}2${N}) toggle junk
  ${C}0${N}) back (restart to apply)
EOF
      local ic; ic="$(ask 'Choose' '')" || return
      case "$ic" in
        1) if [[ "$st" == *desync=on* ]]; then antidpi_set desync false; else antidpi_set desync true; fi ;;
        2) if [[ "$st" == *junk=on* ]]; then antidpi_set junk false; else antidpi_set junk true; fi ;;
        0) if confirm "Restart aestun now to apply changes?"; then systemctl restart aestun && msg "restarted."; fi
           return ;;
        *) warn "invalid option"; sleep 1 ;;
      esac
    done
  fi
  while true; do
    clear
    local state; state="$(antidpi_state)"
    printf '%s\n' "${BOLD}${C}+-- Anti-DPI hardening --------------------------------+${N}"
    printf '  current: %s%s%s\n\n' "$W" "$state" "$N"
    printf '%s\n' "${D}  All off by default. Enable only what your path needs (README §15).${N}"
    printf '%s\n' "${D}  desync = in-process fake QUIC injector (replaces zapret)${N}"
    printf '%s\n' "${D}  junk   = flow-start cover traffic${N}"
    printf '%s\n' "${D}  hop    = keyed UDP port hopping (open ports on BOTH ends; disables offload)${N}"
    printf '%s\n' "${D}  split  = IP-fragment the desync fakes${N}"
    cat <<EOF

  ${C}1${N}) toggle desync
  ${C}2${N}) toggle junk
  ${C}3${N}) toggle port hopping
  ${C}4${N}) toggle split
  ${C}5${N}) set port-hopping ports
  ${C}6${N}) change wire disguise (none/quic/quic2/dtls)
  ${C}0${N}) back (restart to apply)
EOF
    local c; c="$(ask 'Choose' '')" || return
    case "$c" in
      1) if [[ "$state" == *desync=on* ]]; then antidpi_set desync false; else antidpi_set desync true; fi ;;
      2) if [[ "$state" == *junk=on* ]]; then antidpi_set junk false; else antidpi_set junk true; fi ;;
      3) if [[ "$state" == *hop=on* ]]; then antidpi_set hop false; else
           antidpi_set hop true
           warn "Port hopping needs the whole port set open on BOTH servers, and disables kernel offload."
           antidpi_set_hop_ports
         fi ;;
      4) if [[ "$state" == *split=on* ]]; then antidpi_set split false; else antidpi_set split true; fi ;;
      5) antidpi_set_hop_ports ;;
      6) antidpi_set_obfs; pause ;;
      0) if confirm "Restart aestun now to apply changes?"; then systemctl restart aestun && msg "restarted."; fi
         return ;;
      *) warn "invalid option"; sleep 1 ;;
    esac
  done
}

# =============================================================================
#  Auto-test — sweep every method/protocol on the LIVE tunnel, measure each, pick the
#  best, and apply it. Reconfigures BOTH ends, so it needs SSH to the foreign server;
#  the password is asked once, held in a 0600 temp file for sshpass, and shredded after.
# =============================================================================
autotest() {
  clear; hdr "Auto-test: sweep methods & protocols, apply the best"
  [[ -f "$CONF" ]] || { err "Set up the tunnel first."; pause; return; }
  local role; role="$(json_get "$CONF" role)"
  [[ "$role" == "a" ]] || { err "Run auto-test from the role 'a' (Iran/inside) server — it drives the sweep."; pause; return; }
  command -v jq >/dev/null 2>&1 || { err "jq is required."; pause; return; }
  command -v python3 >/dev/null 2>&1 || { err "python3 is required."; pause; return; }
  command -v sshpass >/dev/null 2>&1 || apt-get install -y sshpass >/dev/null 2>&1
  command -v sshpass >/dev/null 2>&1 || { err "sshpass is required (apt-get install sshpass)."; pause; return; }

  local peer host peerip; peer="$(json_get "$CONF" peer)"; host="${peer%:*}"
  printf '\n%sThis reconfigures BOTH servers repeatedly and briefly interrupts the tunnel\n' "$Y"
  printf '(~70s per variant, ~6 min total — the window is long ON PURPOSE so a delayed\n'
  printf 'volumetric throttle shows up and a doomed variant is not picked). Maintenance\n'
  printf 'window only, not peak hours.%s\n\n' "$N"
  local fuser fhost fpass
  fhost="$(ask 'Foreign (role b) SSH host' "$host")"
  fuser="$(ask 'Foreign SSH user' 'root')"
  printf '%sForeign SSH password%s (hidden): ' "$W" "$N"; read -rs fpass; printf '\n'
  [[ -n "$fpass" ]] || { err "No password."; pause; return; }

  local pwf; pwf="$(mktemp)"; chmod 600 "$pwf"; printf '%s' "$fpass" > "$pwf"; unset fpass
  local RSSH="sshpass -f $pwf ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 $fuser@$fhost"
  local RSCP="sshpass -f $pwf scp -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10"
  if ! $RSSH 'echo ok' >/dev/null 2>&1; then err "SSH to foreign failed."; shred -u "$pwf" 2>/dev/null||rm -f "$pwf"; pause; return; fi
  msg "SSH to foreign OK."

  # --- throughput measurement: make sure it can actually run -------------------------------
  # The Mbit/s column is produced by iperf3 running ACROSS the tunnel (client here, server on
  # the foreign end). iperf3 is not part of the install, so on a fresh pair of servers it is
  # missing and the sweep used to skip the measurement in silence — every variant reported a
  # bare "-" and the ranking collapsed to loss-only, because a missing rate scores as 0 for
  # every variant. Install it on BOTH ends up front, and if that is impossible say so once
  # here instead of leaving an unexplained empty column.
  local IPERF_OK=1
  if ! command -v iperf3 >/dev/null 2>&1; then
    msg "Installing iperf3 locally (needed for the Mbit/s column)..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y iperf3 >/dev/null 2>&1 \
      || { apt-get update -qq >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y iperf3 >/dev/null 2>&1; }
  fi
  command -v iperf3 >/dev/null 2>&1 || IPERF_OK=0
  if ! $RSSH 'command -v iperf3 >/dev/null 2>&1'; then
    msg "Installing iperf3 on the foreign server..."
    $RSSH 'DEBIAN_FRONTEND=noninteractive apt-get install -y iperf3 >/dev/null 2>&1 || { apt-get update -qq >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y iperf3 >/dev/null 2>&1; }' >/dev/null 2>&1
    $RSSH 'command -v iperf3 >/dev/null 2>&1' || IPERF_OK=0
  fi
  if [[ "$IPERF_OK" == 1 ]]; then
    msg "Throughput per variant: iperf3 across the tunnel (60 Mbit cap, 24s, 2 slices)."
  else
    warn "iperf3 is not available on both ends — falling back to a timed SSH bulk transfer"
    warn "over the tunnel for the Mbit/s column (approximate: ssh does its own crypto, so it"
    warn "under-reports on a fast link, but it is the same path for every variant)."
  fi

  # remote config path (assume the same /etc/aestun/config.json)
  local RCONF="/etc/aestun/config.json"
  # back up both configs
  cp -a "$CONF" "${CONF}.autotest.bak"
  $RSSH "cp -a $RCONF ${RCONF}.autotest.bak" >/dev/null 2>&1
  local peer_ip; peer_ip="$(json_get "$CONF" peer_ip)"; peer_ip="${peer_ip:-10.8.0.2}"

  # variant table: name|overrides(JSON merged onto BOTH ends)
  # The wire-format variants come first and are worth the time even on a link that already
  # works: a disguise whose handshake cover the network silently drops still carries traffic,
  # so a passing tunnel is not evidence that its cover is intact. Measured on two Iranian
  # carriers, quic (v1) is exactly that case — the tunnel runs, the cover does not arrive.
  local variants=(
    "baseline|{}"
    "quic-v1|{\"transport\":\"udp\",\"obfs\":\"quic\"}"
    "dtls|{\"transport\":\"udp\",\"obfs\":\"dtls\"}"
    "desync+split+junk|{\"transport\":\"udp\",\"obfs\":\"quic2\",\"desync\":{\"enabled\":true,\"repeats\":6},\"split\":{\"enabled\":true},\"junk\":{\"enabled\":true}}"
    "port-hop|{\"transport\":\"udp\",\"obfs\":\"quic2\",\"hop\":{\"enabled\":true,\"ports\":[443,2053,2083,2087,2096],\"interval\":20}}"
    "tcp+tls|{\"transport\":\"tcp\",\"obfs\":\"quic\",\"junk\":{\"enabled\":true}}"
    "tcp+tls+rotate|{\"transport\":\"tcp\",\"obfs\":\"quic\",\"junk\":{\"enabled\":true},\"tcp_rotate\":{\"enabled\":true,\"interval_sec\":15}}"
    # The ICMP carrier has to be in the sweep, because on the link this was built for it is
    # the method that wins outright: UDP lost ~42% at every offered rate in ~94 ms blackouts
    # and TCP was throttled to a blackhole within seconds, while ICMP echo crossed the same
    # path at the same moment at full rate. A sweep that cannot select it cannot find that.
    # It takes no obfs and no port hopping; "desync" here means the native decoy-ping
    # injector, which is the ICMP equivalent of a fake burst.
    "icmp|{\"transport\":\"icmp\",\"obfs\":\"none\",\"hop\":{\"enabled\":false}}"
    "icmp+desync|{\"transport\":\"icmp\",\"obfs\":\"none\",\"hop\":{\"enabled\":false},\"desync\":{\"enabled\":true,\"repeats\":4}}"
  )

  local best_name="" best_loss=100 best_rate="-" best_score=-1000000 best_over="{}"
  local SSH_FB_OK=1   # the no-iperf3 throughput fallback is still worth trying
  local RESULTFILE; RESULTFILE="$(mktemp)"
  printf '%-18s %6s %8s %9s %-7s %s\n' "VARIANT" "LOSS%" "PING_ms" "Mbit/s" "VIA" "NOTE" | tee "$RESULTFILE"
  printf '%s\n' "----------------------------------------------------------------------" | tee -a "$RESULTFILE"

  local v name over
  for v in "${variants[@]}"; do
    name="${v%%|*}"; over="${v#*|}"
    # build + push configs (merge onto each end's OWN base backup, preserving role/ip/peer)
    python3 - "$CONF" "$over" > "${CONF}.try" <<'PY'
import json,sys
c=json.load(open(sys.argv[1])); o=json.loads(sys.argv[2])
def m(a,b):
    for k,v in b.items():
        a[k]=m(a[k],v) if isinstance(v,dict) and isinstance(a.get(k),dict) else v
    return a
# reset the four method blocks to off first, so each variant is clean
for blk in ("desync","junk","hop","split","tcp_rotate"):
    c.setdefault(blk,{})["enabled"]=False
c["transport"]="udp"; c["obfs"]="quic2"
m(c,o); json.dump(c,sys.stdout)
PY
    cp "${CONF}.try" "$CONF"
    # foreign: same merge onto its own config
    $RSSH "python3 - $RCONF '$over' > ${RCONF}.try" <<'PY' 2>/dev/null
import json,sys
c=json.load(open(sys.argv[1])); o=json.loads(sys.argv[2])
def m(a,b):
    for k,v in b.items():
        a[k]=m(a[k],v) if isinstance(v,dict) and isinstance(a.get(k),dict) else v
    return a
for blk in ("desync","junk","hop","split","tcp_rotate"):
    c.setdefault(blk,{})["enabled"]=False
c["transport"]="udp"; c["obfs"]="quic2"
m(c,o); json.dump(c,sys.stdout)
PY
    $RSSH "cp ${RCONF}.try $RCONF" >/dev/null 2>&1
    printf '%s testing %-20s%s ' "$D" "$name" "$N"
    $RSSH 'systemctl restart aestun' >/dev/null 2>&1
    systemctl restart aestun >/dev/null 2>&1
    # wait up to ~16s for rx to climb
    local up=0 r1 r2 i
    for i in 1 2 3 4 5 6 7 8; do
      r1="$(json_get "$STATS" rx_packets)"; sleep 2; r2="$(json_get "$STATS" rx_packets)"
      [[ "${r2:-0}" -gt "${r1:-0}" ]] && { up=1; break; }
    done
    local loss pingms rate transport throttled=0
    local rate_via="-" rate_why=""
    transport="$(json_get "$CONF" transport)"; transport="${transport:-udp}"
    if [[ "$up" == 1 ]]; then
      # SUSTAINED measurement, not a quick burst. A volumetric throttle (the kind that kills a
      # long-lived TCP+TLS flow) only engages after ~30s, so a short test would rank a
      # doomed variant as "best" — which is exactly the trap that must be avoided. Measure
      # over a 45s window in 15s slices and treat a flow that STARTS fast then COLLAPSES as
      # throttled (disqualified), and rank on the SUSTAINED (last-slice) rate, not the peak.
      rate="-"; local r_start="-" r_end="-"
      if [[ "$IPERF_OK" == 1 ]]; then
        # Restart the receiver for THIS variant and VERIFY it came up. The tunnel was just
        # restarted, so an iperf3 left over from the previous variant is still bound to an
        # address on an interface that has since been torn down and re-created: it accepts
        # nothing, the client fails, and the rate silently goes missing. If binding the tunnel
        # IP fails (tun not up yet on the far end), fall back to binding every address —
        # the client still connects over the tunnel because peer_ip routes through it.
        $RSSH "pkill -x iperf3 >/dev/null 2>&1; sleep 1; iperf3 -s -B $peer_ip -D >/dev/null 2>&1; sleep 1; pgrep -x iperf3 >/dev/null 2>&1 || iperf3 -s -D >/dev/null 2>&1" >/dev/null 2>&1
        sleep 1
        # Rate-limited (60 Mbit) and shorter, so the sweep does NOT hammer the link at line
        # rate — sustained max-rate testing is exactly what trips an ISP volumetric block, and
        # the UDP preference in the scoring is the real safeguard against picking a TCP variant.
        # Two 12s slices are still enough to catch a gross throttle-collapse.
        #
        # Read the numbers from -J (JSON), not the human table. The table parse was wrong in
        # two ways: it took the value in front of ANY "bits/sec" token, so a slow variant
        # reporting "Kbits/sec" was recorded as if it were Mbit/s (and a plain "bits/sec" the
        # same), and the "(omitted)" warm-up line produced by -O 1 became r_start, which is
        # what the start-fast/collapse check compares against. The timeout is a backstop for a
        # variant whose path blackholes mid-transfer, so one bad variant cannot hang the sweep.
        local jf; jf="$(mktemp)"
        timeout 60 iperf3 -c "$peer_ip" -b 60M -t 24 -i 12 -O 1 -J >"$jf" 2>/dev/null
        local parsed; parsed="$(python3 - "$jf" <<'PY' 2>/dev/null
import json,sys
def out(a,b): print(a,b); sys.exit(0)
try:
    d=json.load(open(sys.argv[1]))
except Exception:
    out("-","-")
if d.get("error"): out("-","-")
r=[s["bits_per_second"]/1e6 for s in (i.get("sum",{}) for i in d.get("intervals",[]))
   if not s.get("omitted") and isinstance(s.get("bits_per_second"),(int,float))]
if not r:
    e=d.get("end",{}); s=e.get("sum_received") or e.get("sum_sent") or e.get("sum") or {}
    if isinstance(s.get("bits_per_second"),(int,float)): r=[s["bits_per_second"]/1e6]
if not r: out("-","-")
out("%.1f"%r[0], "%.1f"%r[-1])
PY
)"
        rm -f "$jf"
        read -r r_start r_end <<<"${parsed:-- -}"
        if [[ "$r_end" =~ ^[0-9.]+$ ]]; then
          rate="$r_end"; rate_via="iperf3"
        else
          rate_why="iperf3-failed"
        fi
        if [[ "$r_start" =~ ^[0-9.]+$ && "$r_end" =~ ^[0-9.]+$ ]]; then
          awk "BEGIN{exit !($r_start>20 && $r_end < $r_start*0.5)}" && throttled=1
        fi
      else
        rate_why="no-iperf3"
      fi
      if [[ ! "$rate" =~ ^[0-9.]+$ && "$SSH_FB_OK" == 1 ]]; then
        # Fallback so the column is never empty: push a fixed block of zeros to the peer's
        # TUNNEL IP over SSH and time it. It needs nothing installed (sshpass is already a
        # requirement) and it crosses the same carrier, which is all the ranking needs. The
        # cost of the SSH handshake is measured separately and subtracted, otherwise a fast
        # link would be dominated by connection setup rather than transfer.
        local SSHOPT="-o StrictHostKeyChecking=accept-new -o ConnectTimeout=8"
        local SZ=26214400 t0 t1 b0 b1 base_ns el_ns
        b0="$(date +%s%N)"
        sshpass -f "$pwf" ssh $SSHOPT "$fuser@$peer_ip" true >/dev/null 2>&1
        b1="$(date +%s%N)"; base_ns=$(( b1 - b0 )); (( base_ns < 0 )) && base_ns=0
        t0="$(date +%s%N)"
        # Feed the zeros in by redirection rather than a pipe: `set -o pipefail` is in effect
        # for this script, and in a pipe a SIGPIPE on head would mark a completed transfer as
        # a failure. This way the status is ssh's (or timeout's) alone.
        if timeout 90 sshpass -f "$pwf" ssh $SSHOPT "$fuser@$peer_ip" 'cat >/dev/null' \
             < <(head -c "$SZ" /dev/zero) 2>/dev/null; then
          t1="$(date +%s%N)"; el_ns=$(( t1 - t0 - base_ns )); (( el_ns < 1000000 )) && el_ns=1000000
          rate="$(awk -v n="$el_ns" -v sz="$SZ" 'BEGIN{printf "%.1f", sz*8/(n/1e9)/1e6}')"
          rate_via="ssh~"; rate_why=""
        else
          # sshd is not reachable on the tunnel IP. Do not retry it on the remaining variants:
          # each attempt burns two connect timeouts and the answer will not change.
          SSH_FB_OK=0
          rate_why="${rate_why:+$rate_why/}ssh-failed"
        fi
      fi
      # loss + latency from a 20s ping (also catches a blackhole the throttle causes)
      local pout; pout="$(ping -c 40 -i 0.5 -W 2 "$peer_ip" 2>/dev/null)"
      loss="$(printf '%s' "$pout" | sed -nE 's/.* ([0-9.]+)% packet loss.*/\1/p' | head -1)"
      pingms="$(printf '%s' "$pout" | sed -nE 's#.*= [0-9.]+/([0-9.]+)/.*#\1#p' | head -1)"
      # high sustained loss is itself a throttle/blackhole signature
      awk "BEGIN{exit !(${loss:-0} >= 25)}" && throttled=1
    else
      loss="100"; pingms="-"; rate="0"; rate_via="-"; rate_why="no-carrier"; throttled=1
    fi
    : "${loss:=100}" "${pingms:=-}" "${rate:=-}"
    local tag=""; [[ "$throttled" == 1 ]] && tag="THROTTLED"
    # Say WHY a rate is missing instead of printing a bare "-": an unmeasured variant scores as
    # 0 Mbit/s, so the operator has to be able to tell "this link is slow" from "nothing measured".
    [[ -n "$rate_why" ]] && tag="${tag:+$tag }${rate_why}"
    printf '%-18s %6s %8s %9s %-7s %s\n' "$name" "$loss" "$pingms" "$rate" "$rate_via" "$tag" | tee -a "$RESULTFILE"
    # Scoring: a throttled variant is disqualified outright. Otherwise rank on sustained
    # throughput, penalise loss hard, and give the datagram carriers a bonus — neither risks
    # the volumetric TCP throttle, and both report honest latency (the TCP path can report a
    # bogus sub-RTT ping). ICMP gets the same bonus as UDP rather than none: it is a datagram
    # carrier with the same properties, and on the link this was written for it is the only
    # one that survives the path at all. Leaving it unbonused would have the sweep pick a UDP
    # variant losing 42% over an ICMP one losing 0.4%.
    local score
    if [[ "$throttled" == 1 ]]; then
      score=-100000
    else
      score="$(awk -v r="$rate" -v l="$loss" -v t="$transport" 'BEGIN{
        rr=(r ~ /^[0-9.]+$/)?r:0; ll=(l ~ /^[0-9.]+$/)?l:100;
        printf "%.2f", rr - ll*5 + ((t=="udp"||t=="icmp")?40:0)}')"
    fi
    awk "BEGIN{exit !($score > $best_score)}" && {
      best_score="$score"; best_name="$name"; best_loss="$loss"; best_rate="$rate"; best_over="$over"
    }
  done

  $RSSH 'pkill -x iperf3 2>/dev/null' >/dev/null 2>&1
  echo
  hdr "Auto-test result"
  cat "$RESULTFILE"
  echo
  if [[ -n "$best_name" ]]; then
    local rate_txt="throughput not measured"
    [[ "$best_rate" =~ ^[0-9.]+$ ]] && rate_txt="~${best_rate} Mbit/s"
    msg "Best variant: ${BOLD}${best_name}${N} (loss ${best_loss}%, ${rate_txt})"
    if ask_yn "Apply '${best_name}' to BOTH servers now" "Y"; then
      # Apply the winning OVERRIDES onto EACH end's own pre-test base — never copy one end's
      # whole config to the other, which would clobber the role/listen/peer/IPs and blackhole
      # the tunnel. This is the same per-end merge the sweep used.
      autotest_merge "${CONF}.autotest.bak" "$best_over" "$CONF"
      $RSSH "$(autotest_merge_remote_cmd "${RCONF}.autotest.bak" "$best_over" "$RCONF")" >/dev/null 2>&1
      chmod 600 "$CONF"; $RSSH "chmod 600 $RCONF" >/dev/null 2>&1
      $RSSH 'systemctl restart aestun' >/dev/null 2>&1; systemctl restart aestun >/dev/null 2>&1
      msg "Applied. The tunnel is now running: ${best_name}."
      echo "Enabled: $(jq -c '{transport,obfs,desync:.desync.enabled,split:.split.enabled,junk:.junk.enabled,hop:.hop.enabled,tcp_rotate:.tcp_rotate.enabled}' "$CONF")"
    else
      cp "${CONF}.autotest.bak" "$CONF"; $RSSH "cp ${RCONF}.autotest.bak $RCONF" >/dev/null 2>&1
      $RSSH 'systemctl restart aestun' >/dev/null 2>&1; systemctl restart aestun >/dev/null 2>&1
      warn "Reverted to the pre-test config on both ends."
    fi
  else
    err "No variant came up cleanly; reverting."
    cp "${CONF}.autotest.bak" "$CONF"; $RSSH "cp ${RCONF}.autotest.bak $RCONF" >/dev/null 2>&1
    $RSSH 'systemctl restart aestun' >/dev/null 2>&1; systemctl restart aestun >/dev/null 2>&1
  fi
  shred -u "$pwf" 2>/dev/null || rm -f "$pwf"
  rm -f "${CONF}.try" "${CONF}.best" "$RESULTFILE"
  pause
}

# autotest_merge BASE OVERRIDES OUT — merge the variant overrides onto BASE (an end's own
# config, so role/listen/peer are preserved), resetting the method blocks first. Used at apply.
autotest_merge() {
  python3 - "$1" "$2" > "$3" <<'PY'
import json,sys
c=json.load(open(sys.argv[1])); o=json.loads(sys.argv[2])
def m(a,b):
    for k,v in b.items():
        a[k]=m(a[k],v) if isinstance(v,dict) and isinstance(a.get(k),dict) else v
    return a
for blk in ("desync","junk","hop","split","tcp_rotate"):
    c.setdefault(blk,{})["enabled"]=False
c["transport"]="udp"; c["obfs"]="quic2"
m(c,o); json.dump(c,sys.stdout)
PY
}

# autotest_merge_remote_cmd BASE OVERRIDES OUT — echoes a self-contained remote command that
# performs the same per-end merge on the foreign server (base64-packed so quoting is safe).
autotest_merge_remote_cmd() {
  local py; py=$(cat <<'PY'
import json,sys,base64
base,ovr,out=sys.argv[1],base64.b64decode(sys.argv[2]).decode(),sys.argv[3]
c=json.load(open(base)); o=json.loads(ovr)
def m(a,b):
    for k,v in b.items():
        a[k]=m(a[k],v) if isinstance(v,dict) and isinstance(a.get(k),dict) else v
    return a
for blk in ("desync","junk","hop","split","tcp_rotate"):
    c.setdefault(blk,{})["enabled"]=False
c["transport"]="udp"; c["obfs"]="quic2"
m(c,o); json.dump(c,open(out,"w"))
PY
)
  local ovr_b64; ovr_b64="$(printf '%s' "$2" | base64 -w0)"
  printf "python3 -c %q %q %q %q" "$py" "$1" "$ovr_b64" "$3"
}

status_line() {
  local st ins peer tr ob
  st="$(svc_active aestun)"
  ins="not configured"; [[ -f "$CONF" ]] && ins="configured"
  local st_c="$R"; [[ "$st" == active ]] && st_c="$G"
  peer="$(json_get "$CONF" peer 2>/dev/null)"
  # The wire format is the thing most likely to be wrong (it has to match on both ends and
  # there are now four of them), so it belongs on the status line rather than three menus in.
  tr="$(json_get "$CONF" transport 2>/dev/null)"; ob="$(json_get "$CONF" obfs 2>/dev/null)"
  printf '%s\n' "${D}status: ${st_c}${st}${N}${D} | ${ins} | peer: ${peer:-–} | wire: ${tr:-udp}+${ob:-none} | arch: $(arch_tag)${N}"
}

# =============================================================================
#  Multi-protocol carrier menu — front end for aestun-mp.sh
# =============================================================================
#  The supervisor itself is a separate script because it also runs unattended as
#  aestun-mp.service; this menu is only the operator's view of it.
MP="${MP_BIN:-/usr/local/sbin/aestun-mp.sh}"
mp_have() {
  [[ -x "$MP" ]] && return 0
  local here="${BASH_SOURCE[0]%/*}/aestun-mp.sh"
  [[ -x "$here" ]] && { MP="$here"; return 0; }
  return 1
}

multipath_menu() {
  while true; do
    clear; hdr "Multi-protocol tunnel (failover + multipath)"
    if ! mp_have; then
      err "aestun-mp.sh not found (expected $MP or next to this script)."; pause; return
    fi
    printf '%s\n' "${D}  Runs udp/quic2, udp/dtls, tcp/tls and icmp as four independent carriers at"
    printf '%s\n' "  once. Applications address one stable overlay IP; the supervisor decides"
    printf '%s\n' "  which protocol carries each packet and reroutes within seconds when one is"
    printf '%s\n' "  blocked. Run 'setup' on BOTH servers before 'start'.${N}"
    cat <<EOF

  ${C}1${N}) Status (carriers, health, current route)
  ${C}2${N}) Probe every protocol now
  ${C}3${N}) Send test data over each protocol
  ${C}4${N}) Setup   (generate a config per protocol — run on BOTH servers)
  ${C}5${N}) Start   (stand down single-path service, bring all carriers up)
  ${C}6${N}) Mode -> multipath   (all healthy protocols at once)
  ${C}7${N}) Mode -> failover    (first responsive protocol only)
  ${C}8${N}) Stop multipath
  ${C}9${N}) Revert to the single-path tunnel
  ${C}0${N}) Back
EOF
    local c; c="$(ask 'Choose' '')" || return
    case "$c" in
      1) "$MP" status; pause ;;
      2) "$MP" probe; pause ;;
      3) local sz; sz="$(ask 'MiB per protocol' '8')"; "$MP" bench "$sz"; pause ;;
      4) "$MP" setup; warn "Run the same option on the OTHER server too."; pause ;;
      5) ask_yn "Stop the single-path service and start all carriers" "Y" && { "$MP" start; }; pause ;;
      6) "$MP" mode multipath; pause ;;
      7) "$MP" mode failover; pause ;;
      8) ask_yn "Stop multipath" "N" && "$MP" stop; pause ;;
      9) ask_yn "Revert to the stock single-path tunnel" "N" && "$MP" revert; pause ;;
      0|"") return ;;
      *) ;;
    esac
  done
}

main_menu() {
  while true; do
    clear
    printf '%s\n' "${BOLD}${C}+==================================================+${N}"
    printf '%s\n' "${BOLD}${C}|   aestun — anti-DPI server-to-server tunnel      |${N}"
    printf '%s\n' "${BOLD}${C}+==================================================+${N}"
    status_line
    cat <<EOF

  ${C}1${N}) Setup / reconfigure tunnel (wizard)
  ${C}2${N}) Live monitoring dashboard
  ${C}3${N}) Service management (start/stop/restart/...)
  ${C}4${N}) Connectivity test (ping through tunnel)
  ${C}5${N}) Live logs
  ${C}l${N}) Live tunnel log            <- follow the tunnel processes themselves
  ${C}r${N}) Record live log to file    <- capture that stream for later / to send on
  ${C}6${N}) Show config
  ${C}7${N}) Edit config
  ${C}8${N}) Generate new key
  ${C}9${N}) Network optimization
  ${C}d${N}) DPI / probe log            <- who is probing, what the path is doing
  ${C}x${N}) Anti-DPI hardening         <- desync / junk / port-hop / split (native, §15)
  ${C}i${N}) ICMP carrier settings      <- readers / batching / id rotation / ping mimicry
  ${C}t${N}) Auto-test methods          <- sweep every method/protocol, apply the best (§16)
  ${C}m${N}) Multi-protocol tunnel      <- run 4 carriers at once: failover + multipath (§19)
  ${C}z${N}) zapret module (DPI bypass)
  ${C}u${N}) Uninstall tunnel
  ${C}0${N}) Exit
EOF
    local __c; __c="$(ask 'Choose' '')" || { clear; exit 0; }
    case "$__c" in
      1) interactive_setup; pause ;;
      2) monitor ;;
      3) service_menu ;;
      4) test_conn ;;
      5) show_logs ;;
      l|L) live_log ;;
      r|R) record_log ;;
      6) show_config ;;
      7) edit_config ;;
      8) do_keygen ;;
      9) netopt_menu ;;
      d|D) dpi_menu ;;
      x|X) antidpi_menu ;;
      i|I) icmp_menu ;;
      t|T) autotest ;;
      m|M) multipath_menu ;;
      z|Z) zapret_menu ;;
      u|U) uninstall_all ;;
      0) clear; exit 0 ;;
      *) warn "invalid option"; sleep 1 ;;
    esac
  done
}


# =============================================================================
#  zap-rule — NFQUEUE plumbing for the tunnel carrier (invoked by systemd).
#  Self-configuring: peer host/port and transport come from the aestun config,
#  so it is identical on both ends. Was the standalone zapret-rules.sh.
# =============================================================================
zap_rule() {
  local host port transport qnum=200
  IFS='|' read -r host port transport < <(carrier_endpoint)
  if [[ "$transport" == "icmp" ]]; then
    # nfqws filters on TCP and UDP; there is no ICMP mode, and an NFQUEUE rule on -p icmp
    # would round-trip the whole carrier through a userspace process that then does nothing
    # with it. Succeed quietly so the unit's ExecStartPre/ExecStopPost do not fail the
    # service — zap_enable is what refuses loudly.
    echo "zap-rule: carrier is ICMP; nfqws has no ICMP desync, nothing to do" >&2
    return 0
  fi
  [[ -n "$host" && -n "$port" ]] || { echo "zap-rule: cannot read peer host/port from $CONF" >&2; return 1; }

  # Cover BOTH transports on the carrier port. The tunnel uses one at a time, but queuing tcp
  # AND udp means the desync applies whatever the carrier is (and keeps working if you switch
  # transport) — and with --dpi-desync-any-protocol nfqws acts on the carrier's opaque payload
  # regardless of the L7 protocol. connbytes keeps nfqws on the opening packets only (DPI
  # classifies a flow at its start; round-tripping a multi-hundred-Mbit carrier through
  # userspace per packet costs real CPU). --queue-bypass lets a dead/wedged nfqws pass traffic
  # untouched rather than dropping every packet on an unread queue.
  local target=(-j NFQUEUE --queue-num "$qnum" --queue-bypass)
  _zap_match() { # _zap_match PROTO -> echoes the iptables match args
    printf '%s ' -d "$host" -p "$1" --dport "$port" \
      -m connbytes --connbytes-dir both --connbytes-mode packets --connbytes 1:8
  }

  local pr
  case "${1:-}" in
    add)
      for pr in tcp udp; do
        # shellcheck disable=SC2046
        iptables -t mangle -C OUTPUT $(_zap_match "$pr") "${target[@]}" 2>/dev/null \
          || iptables -t mangle -A OUTPUT $(_zap_match "$pr") "${target[@]}"
      done ;;
    del)
      for pr in tcp udp; do
        # shellcheck disable=SC2046
        iptables -t mangle -D OUTPUT $(_zap_match "$pr") "${target[@]}" 2>/dev/null || true
      done ;;
    rearm)
      # The carrier is one permanently-active fixed-5-tuple flow, so its conntrack entry
      # is refreshed forever and its packet counter never returns to the 1:8 window --
      # adding the rule to a running tunnel matches nothing. Dropping the entry makes the
      # next packets open a fresh flow that does pass through the rule. Wait for nfqws to
      # bind the queue first, or those opening packets sail through undesynced.
      command -v conntrack >/dev/null 2>&1 || return 0
      local i
      for i in $(seq 1 50); do
        awk -v q="$qnum" '$1==q {f=1} END{exit !f}' /proc/net/netfilter/nfnetlink_queue 2>/dev/null && break
        sleep 0.1
      done
      for pr in tcp udp; do
        conntrack -D -p "$pr" --src "$host" --dport "$port" >/dev/null 2>&1
        conntrack -D -p "$pr" --dst "$host" --dport "$port" >/dev/null 2>&1
      done
      return 0 ;;
    *) echo "usage: $0 zap-rule {add|del|rearm}" >&2; return 1 ;;
  esac
}

# =============================================================================
#  build — cross-compile a static Linux binary (dev machine with Go).
#    ./aestun.sh build [arch] [obfuscate]
#
#  "obfuscate" builds with garble (github.com/burrowers/garble): renamed symbols,
#  encrypted string literals, stripped build info, control-flow scrambling. This
#  raises the cost of reverse-engineering the binary. It is NOT "uncrackable" — any
#  binary that runs can be run under a debugger, and root on the box sees everything.
#  It buys time against casual analysis, nothing more; do not treat it as a secret store.
# =============================================================================
do_build() {
  local arch="${1:-amd64}" mode="${2:-plain}"
  command -v go >/dev/null 2>&1 || { err "Go is not installed."; return 1; }
  check_build_deps
  local out="aestun-linux-${arch}"

  if [[ "$mode" == "obfuscate" || "$mode" == "garble" ]]; then
    if ! command -v garble >/dev/null 2>&1; then
      warn "garble not found; installing (needs network + Go)..."
      go install mvdan.cc/garble@latest >/dev/null 2>&1 || go install github.com/burrowers/garble@latest >/dev/null 2>&1
      command -v garble >/dev/null 2>&1 || export PATH="$PATH:$(go env GOPATH)/bin"
    fi
    if command -v garble >/dev/null 2>&1; then
      out="aestun-linux-${arch}-obf"
      ( cd "$LIB_DIR" && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
          garble -tiny -literals build -trimpath -o "$out" . ) \
        && msg "built (obfuscated): ${out}" \
        && printf '   %sreminder:%s obfuscation slows analysis, it does not make the binary uncrackable.\n' "$Y" "$N" \
        && return 0
      err "garble build failed; falling back to a plain build."
    else
      err "could not obtain garble; doing a plain build instead."
    fi
  fi

  local tags=()
  if [[ "$mode" == "pprof" ]]; then
    # Profiling pulls net/http in and roughly doubles the binary, so it is opt-in.
    tags=(-tags pprof); out="${out}-pprof"
  fi
  ( cd "$LIB_DIR" && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build "${tags[@]}" -trimpath -ldflags "-s -w" -o "$out" . ) \
    || return 1
  msg "built: ${out}"
  # SHA256SUMS calls ./aestun "the core build for this host (run it directly)", so when the
  # build was for this host's own architecture that file has to move too. Without this, a
  # build refreshed the cross binary and left ./aestun as the previous program — the exact
  # stale-binary trap the header warns about, produced by the command meant to prevent it.
  if [[ "$mode" == "plain" && "$arch" == "$(arch_tag)" ]]; then
    ( cd "$LIB_DIR" && install -m 0755 "$out" aestun ) && msg "refreshed ./aestun (this host's arch)."
  fi
  printf '   copy to a server:  scp %s root@SERVER:/usr/local/bin/aestun\n' "$out"
  zap_refresh_sums "$out"
}

# zap_refresh_sums — keep SHA256SUMS in step with a binary that was just rebuilt.
#
# A checksum file that is not regenerated is worse than none: it certifies the previous
# binary, so the fallback path in ensure_binary would report a mismatch on a perfectly good
# build and an operator would learn to ignore it. Only the plain (untagged) builds are
# recorded — a pprof or garble build is a one-off, not something to ship.
zap_refresh_sums() {
  local out="$1"
  [[ "$out" =~ ^aestun-linux-(amd64|arm64)$ ]] || return 0
  command -v go >/dev/null 2>&1 || return 0
  ( cd "$LIB_DIR" || return 0
    {
      echo "# Prebuilt aestun binaries — built from the sources in this directory."
      echo "#"
      echo "# Go:      $(go version | awk '{print $3}')"
      echo "# Built:   $(date -u +%Y-%m-%dT%H:%M:%SZ)"
      echo "# Flags:   CGO_ENABLED=0 go build -trimpath -ldflags \"-s -w\""
      echo "#"
      echo "# The build is reproducible: -trimpath and CGO_ENABLED=0 mean the same Go version"
      echo "# over the same sources produces byte-identical output, so you can verify these"
      echo "# rather than trust them:"
      echo "#"
      echo "#   CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags \"-s -w\" -o /tmp/v ."
      echo "#   sha256sum /tmp/v aestun-linux-amd64      # the two hashes must match"
      echo "#"
      echo "# aestun.sh compiles from source whenever a Go toolchain is available or can be"
      echo "# fetched; these are the fallback for a box that has neither."
      echo ""
      local f
      # "aestun" is the host build of the same program — on an amd64 box it is byte-identical
      # to aestun-linux-amd64, and it is the one to run straight out of the directory.
      for f in aestun aestun-linux-amd64 aestun-linux-arm64; do
        [[ -f "$f" ]] && sha256sum "$f"
      done
      echo ""
      echo "# source fingerprint at build time:"
      sha256sum ./*.go go.mod go.sum 2>/dev/null | sha256sum | sed 's/^/# sources: /'
    } > SHA256SUMS
  ) && msg "SHA256SUMS refreshed."
}

# =============================================================================
#  upgrade — move an existing install onto a new binary and new config fields
#  without making the operator re-answer the whole wizard.
# =============================================================================
do_upgrade() {
  need_root
  [[ -f "$CONF" ]] || { err "Nothing to upgrade: $CONF does not exist. Run 'install' first."; exit 1; }
  hdr "aestun upgrade"

  local stamp bak
  stamp="$(date +%Y%m%d-%H%M%S)"
  bak="/root/aestun-upgrade-${stamp}"
  mkdir -p "$bak"
  cp -a "$CONF" "$bak/config.json"
  [[ -f "$BIN_DST" ]] && cp -a "$BIN_DST" "$bak/aestun.bin"
  msg "Rolled-back copies saved in $bak"

  ensure_binary || { err "no binary available"; return 1; }

  # --- cipher ---
  local cur rec hw cpuname
  cur="$(json_get "$CONF" cipher)"; cur="${cur:-aes-gcm}"
  rec="$("$BIN_DST" cipherinfo 2>/dev/null | tail -1)"; rec="${rec:-aes-gcm}"
  hw="$("$BIN_DST" cipherinfo 2>/dev/null | sed -n 's/^aes_hardware=//p')"
  cpuname="$("$BIN_DST" cipherinfo 2>/dev/null | sed -n 's/^cpu=//p')"
  printf '\n%sCipher%s  current: %s%s%s\n' "$BOLD" "$N" "$W" "$cur" "$N"
  printf '  this CPU: %s  (AES hardware: %s)\n' "${cpuname:-unknown}" "${hw:-unknown}"
  if [[ "$hw" != "true" ]]; then
    printf '  %sThis CPU has no AES-NI. AES-GCM runs in software here and will dominate CPU use.%s\n' "$Y" "$N"
  fi
  printf '  %sBoth servers must use the same value, and the link is only as fast as its slower\n' "$D"
  printf '  end — so if EITHER side lacks AES-NI, set chacha20-poly1305 on BOTH.%s\n' "$N"
  local newc; newc="$(ask "Cipher (aes-gcm/chacha20-poly1305)" "$cur")"
  [[ "$newc" == "aes-gcm" || "$newc" == "chacha20-poly1305" ]] || {
    warn "Unknown cipher '$newc' — keeping $cur."; newc="$cur"; }

  # --- wire disguise ---
  # Existing installs are the ones most likely to be sitting on obfs=quic, which on Iranian
  # carriers has its handshake cover dropped outright: the tunnel keeps working, so nothing
  # looks wrong, while the disguise it was configured for is simply not happening.
  local curo newo curtr
  curo="$(json_get "$CONF" obfs)"; curo="${curo:-none}"
  curtr="$(json_get "$CONF" transport)"; curtr="${curtr:-udp}"
  if [[ "$curtr" == "icmp" ]]; then
    # The binary refuses obfs on this carrier, so offering it here would only produce a
    # config that fails to start.
    newo="none"
    printf '\n%sWire disguise%s: not applicable — the ICMP carrier'"'"'s cover is the ping itself.\n' "$BOLD" "$N"
  else
  printf '\n%sWire disguise%s  current: %s%s%s\n' "$BOLD" "$N" "$W" "$curo" "$N"
  if [[ "$curo" == "quic" && "$(json_get "$CONF" transport)" != "tcp" ]]; then
    printf '  %squic2 is recommended over quic on Iranian links:%s every QUIC v1 long-header\n' "$Y" "$N"
    printf '  packet was measured dropped on AS25184 and AS34918, so the synthetic handshake\n'
    printf '  never arrives and the flow reads as 1-RTT packets with no handshake in front.\n'
    printf '  Same wire format for data, so throughput is unchanged. (README §10.2)\n'
  fi
  printf '  %snone%s / %squic%s / %squic2%s / %sdtls%s — must match on BOTH servers.\n' "$C" "$N" "$C" "$N" "$C" "$N" "$C" "$N"
  local defo="$curo"; [[ "$curo" == "quic" && "$(json_get "$CONF" transport)" != "tcp" ]] && defo="quic2"
  newo="$(ask "Obfuscation" "$defo")"
  case "$newo" in none|quic|quic2|dtls) ;; *) warn "Unknown obfs '$newo' — keeping $curo."; newo="$curo" ;; esac
  fi

  # --- socket buffers ---
  # 8/16 MiB was the old default and is pure bufferbloat on a fast link; see the note in
  # tunnel.go applyDefaults for the measurement behind 2 MiB.
  local curbuf newbuf
  curbuf="$(json_get "$CONF" rcvbuf)"; curbuf="${curbuf:-0}"
  newbuf="$curbuf"
  if [[ "$curbuf" =~ ^[0-9]+$ && "$curbuf" -gt 4194304 ]]; then
    printf '\n%sSocket buffers%s  current: %s bytes per direction\n' "$BOLD" "$N" "$curbuf"
    printf '  That buffer is a queue. Measured on a 650 Mbit/s link, 8 MiB held ~62 ms of\n'
    printf '  backlog (latency under load 80 -> 142 ms, jitter 35 ms); 2 MiB cut it to ~19 ms\n'
    printf '  (loaded latency ~99 ms, jitter ~10 ms) for about 4%% of throughput.\n'
    ask_yn "Reduce to 2 MiB (better latency, slightly lower peak throughput)" "Y" && newbuf=2097152
  fi

  # --- dpi log ---
  local dpion=true
  ask_yn "Enable DPI/probe logging" "Y" || dpion=false

  python3 - "$CONF" "$newc" "$dpion" "$DPI_LOG" "$newo" "$newbuf" <<'PY'
import json,sys
path,cipher,dpion,logpath=sys.argv[1],sys.argv[2],sys.argv[3]=="true",sys.argv[4]
obfs,buf=sys.argv[5],int(sys.argv[6])
c=json.load(open(path))
c["cipher"]=cipher
c["obfs"]=obfs
if buf:
    c["rcvbuf"]=buf
    c["sndbuf"]=buf
# Older configs predate these blocks entirely; add them disabled so every knob the menus
# offer is present in the file rather than silently defaulted inside the binary.
c.setdefault("tcp_rotate",{"enabled":False,"interval_sec":15})
c.setdefault("split",{"enabled":False,"frag_pos":24})
# The ICMP carrier's block. Every value here is the binary's own default, so adding it to an
# existing config changes nothing about how the tunnel behaves — it just makes the knobs
# visible to the menus and to anyone reading the file.
i=c.setdefault("icmp",{})
for k,v in (("readers",0),("batch",32),("kernel_filter",True),("suppress_replies",True),
            ("id",0),("id_pool",1),("id_rotate_sec",60),("mimic_ping",False)):
    i.setdefault(k,v)
d=c.setdefault("dpi_log",{})
d["enabled"]=dpion
d.setdefault("path",logpath)
d.setdefault("probe",True)
json.dump(c,open(path,"w"),indent=2)
PY
  chmod 600 "$CONF"
  msg "Config updated (cipher=$newc, obfs=$newo, buffers=${newbuf}, dpi_log.enabled=$dpion)."
  if [[ "$newo" != "$curo" ]]; then
    printf '\n%sThe wire disguise changed. Set obfs=%s on the OTHER server too — the formats are\n' "$Y" "$newo"
    printf 'not negotiated, so a mismatch means every packet fails to authenticate.%s\n' "$N"
  fi

  if [[ "$newc" != "$cur" ]]; then
    printf '\n%sThe cipher changed. The two ends will not talk until the OTHER server is set to\n' "$Y"
    printf '%s as well — expect the tunnel to be down until you do that.%s\n' "$newc" "$N"
    confirm "Restart aestun now anyway" || { warn "Not restarting. Run: systemctl restart aestun"; return 0; }
  fi
  systemctl restart aestun && msg "aestun restarted." || err "restart failed — see: journalctl -u aestun -n 50"
  sleep 2
  systemctl is-active --quiet aestun && msg "service is active." || {
    err "service is not active. Roll back with:"
    printf '   cp %s/config.json %s && cp %s/aestun.bin %s && systemctl restart aestun\n' "$bak" "$CONF" "$bak" "$BIN_DST"
  }
}

# =============================================================================
#  installer entry (was install.sh)
# =============================================================================
do_install() {
  need_root
  printf '%s\n' "${BOLD}${C}"
  cat <<'BANNER'
   +---------------------------------------------+
   |   aestun — AES-256-GCM anti-DPI tunnel      |
   |   server-to-server installer                |
   +---------------------------------------------+
BANNER
  printf '%s\n' "${N}"
  interactive_setup || { err "Setup aborted (no input / cancelled). Nothing was changed."; exit 1; }
  # Make this script callable by systemd for the zapret rule helper.
  install -m 0755 "$SELF" "$MGR_DST" 2>/dev/null || true
  printf '\n%sQuick checks:%s\n' "$BOLD" "$N"
  printf '   systemctl status aestun\n'
  printf '   journalctl -u aestun -f\n'
  printf '   %s            %s(management menu + live monitor)%s\n' "$SELF" "$D" "$N"
}

# =============================================================================
#  dispatcher
# =============================================================================
case "${1:-menu}" in
  zap-rule) shift; zap_rule "$@"; exit $? ;;   # systemd path — no menu, no root prompt
  build)    shift; do_build "$@"; exit $? ;;
  dpi-report) shift; "$BIN_DST" dpi-report -config "$CONF" "$@"; exit $? ;;
  install)  do_install; exit $? ;;
  upgrade)  do_upgrade; exit $? ;;
  menu|"")  need_root; install -m 0755 "$SELF" "$MGR_DST" 2>/dev/null || true; main_menu ;;
  -h|--help|help)
    cat <<'USAGE'
aestun.sh — one file: installer + manager + monitor + zapret + build

  sudo ./aestun.sh              management menu (default)
  sudo ./aestun.sh install      interactive installer (run on each server)
  sudo ./aestun.sh upgrade      move an existing install to a new binary/config
  ./aestun.sh build [arch] [pprof|obfuscate]
                                cross-compile a static binary (dev machine)
  ./aestun.sh dpi-report        summarise the DPI/probe log
  ./aestun.sh zap-rule VERB     NFQUEUE helper {add|del|rearm}, invoked by systemd
USAGE
    exit 0 ;;
  *) err "unknown command: $1  (try: install | menu | zap-rule | build)"; exit 1 ;;
esac
