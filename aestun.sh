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

# ---------------------------------------------------------------------- install bin
ensure_binary() {
  local tag; tag="$(arch_tag)"
  local pre="${LIB_DIR}/aestun-linux-${tag}"
  if [[ -f "$pre" ]]; then
    install -m 0755 "$pre" "$BIN_DST"
    msg "Installed prebuilt binary: $BIN_DST (${tag})"
    return 0
  fi
  if command -v go >/dev/null 2>&1 && [[ -f "${LIB_DIR}/main.go" ]]; then
    warn "No prebuilt binary found; building from source with Go..."
    ( cd "$LIB_DIR" && CGO_ENABLED=0 GOOS=linux GOARCH="$tag" go build -trimpath -ldflags "-s -w" -o "$BIN_DST" . )
    [[ -f "$BIN_DST" ]] && { msg "Built and installed."; return 0; }
  fi
  err "No suitable binary (aestun-linux-${tag}) found and Go is unavailable to build it."
  err "On a machine with Go run:  ./aestun.sh build ${tag}   then place the output next to this script."
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
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
RuntimeDirectory=aestun
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
  "rcvbuf": ${CFG_BUF:-8388608},
  "sndbuf": ${CFG_BUF:-8388608},
  "pad_max": ${CFG_PAD},
  "rekey_interval": ${CFG_REKEY},
  "keepalive": ${CFG_KA},
  "manage_ip": true,
  "stats_path": "${STATS}"
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

  # --- carrier transport ---
  # UDP is the default for a reason: the carrier multiplexes every inner connection.
  # Over TCP, one lost carrier segment head-of-line-blocks *all* of them at once
  # (and inner TCP retransmits on top of outer TCP), which shows up as every user
  # stalling in lockstep. Only pick TCP if UDP is blocked on your path.
  printf '\n%sCarrier transport%s — udp is strongly preferred.\n' "$BOLD" "$N"
  printf '  %sudp%s: a lost packet affects only the connection it carried\n' "$C" "$N"
  printf '  %stcp%s: survives UDP-blocking networks, but one loss stalls every connection\n' "$C" "$N"
  CFG_TRANSPORT="$(ask "Transport (udp/tcp)" "udp")"
  [[ "$CFG_TRANSPORT" == "udp" || "$CFG_TRANSPORT" == "tcp" ]] || {
    warn "Unknown transport '$CFG_TRANSPORT' — using udp."; CFG_TRANSPORT="udp"; }

  # --- wire obfuscation ---
  # The payload is already indistinguishable from random, which is the problem: nothing
  # else on the wire looks like that. "quic" gives each datagram a QUIC short header and
  # opens the flow with a real Initial packet, so it reads as an ordinary QUIC connection.
  printf '\n%sWire obfuscation%s — must match on BOTH servers.\n' "$BOLD" "$N"
  printf '  %snone%s: raw high-entropy datagrams (compatible with older builds)\n' "$C" "$N"
  printf '  %squic%s: presents as QUIC — short headers, synthetic handshake, shaped sizes\n' "$C" "$N"
  CFG_OBFS="$(ask "Obfuscation (none/quic)" "quic")"
  [[ "$CFG_OBFS" == "none" || "$CFG_OBFS" == "quic" ]] || {
    warn "Unknown obfs '$CFG_OBFS' — using none."; CFG_OBFS="none"; }
  if [[ "$CFG_OBFS" == "quic" ]]; then
    CFG_SNI="$(ask "Server name to present in the handshake" "www.cloudflare.com")"
  fi

  # --- network endpoints ---
  printf '\n'
  CFG_LISTEN_PORT="$(ask "${CFG_TRANSPORT^^} listen port on THIS server" "51820")"
  is_port "$CFG_LISTEN_PORT" || { CFG_LISTEN_PORT=51820; warn "Invalid port, using 51820."; }
  local phost pport
  phost="$(ask_req "Public IP/host of the OTHER server")" || return 1
  pport="$(ask "${CFG_TRANSPORT^^} port of the OTHER server" "$CFG_LISTEN_PORT")"
  is_port "$pport" || pport="$CFG_LISTEN_PORT"
  CFG_PEER="${phost}:${pport}"

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
  CFG_BUF="$(ask_int "Socket buffer per direction in bytes" "8388608")"

  write_config
  write_service
  systemctl daemon-reload
  systemctl enable --now aestun >/dev/null 2>&1 && msg "Service enabled and started."
  open_firewall "$CFG_LISTEN_PORT"

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

# --------------------------------------------------------------------- live monitor
monitor() {
  [[ -f "$CONF" ]] || { err "Set up the tunnel first."; pause; return; }
  local iface; iface="$(json_get "$CONF" tun_name)"; iface="${iface:-tun0}"
  local prev_tx=0 prev_rx=0 first=1 prev_epoch
  prev_epoch="$(date +%s)"
  while true; do
    local now_tx now_rx txp rxp af rd up peer lastrx nowu rekey
    now_tx="$(json_get "$STATS" tx_bytes)";  now_rx="$(json_get "$STATS" rx_bytes)"
    txp="$(json_get "$STATS" tx_packets)";   rxp="$(json_get "$STATS" rx_packets)"
    af="$(json_get "$STATS" auth_fail)";     rd="$(json_get "$STATS" replay_drop)"
    up="$(json_get "$STATS" uptime_seconds)"; peer="$(json_get "$STATS" peer)"
    lastrx="$(json_get "$STATS" last_rx_unix)"; nowu="$(json_get "$STATS" now_unix)"
    rekey="$(json_get "$STATS" rekey_interval)"
    : "${now_tx:=0}" "${now_rx:=0}" "${txp:=0}" "${rxp:=0}" "${af:=0}" "${rd:=0}" "${up:=0}" "${lastrx:=0}" "${nowu:=0}" "${rekey:=0}"

    local now_epoch el dtx=0 drx=0
    now_epoch="$(date +%s)"; el=$(( now_epoch - prev_epoch )); (( el < 1 )) && el=1
    if [[ $first -eq 0 ]]; then dtx=$(( (now_tx - prev_tx) / el )); drx=$(( (now_rx - prev_rx) / el )); fi
    (( dtx < 0 )) && dtx=0; (( drx < 0 )) && drx=0
    prev_tx=$now_tx; prev_rx=$now_rx; prev_epoch=$now_epoch; first=0

    local svc_state; svc_state="$(svc_active aestun)"
    local svc_c="$R"; [[ "$svc_state" == active ]] && svc_c="$G"

    local link="down" link_c="$R"
    if ip link show "$iface" >/dev/null 2>&1; then
      if ip link show "$iface" 2>/dev/null | grep -q "state UP\|UNKNOWN"; then link="up"; link_c="$G"; fi
    fi

    local age="-" age_c="$Y"
    if [[ "$lastrx" -gt 0 && "$nowu" -gt 0 ]]; then
      age=$(( nowu - lastrx )); (( age <= 15 )) && age_c="$G"; age="${age}s"
    fi

    local rk="static"; [[ "$rekey" -gt 0 ]] && rk="every ${rekey}s"

    clear
    printf '%s\n' "${BOLD}${C}+-- aestun live monitor -------------------------------+${N}"
    printf '  service  : %s%-8s%s   interface %s: %s%s%s\n' "$svc_c" "$svc_state" "$N" "$iface" "$link_c" "$link" "$N"
    printf '  uptime   : %-12s last RX: %s%s%s ago\n' "$(fmt_dur "$up")" "$age_c" "$age" "$N"
    printf '  peer     : %s%s%s\n' "$W" "${peer:-–}" "$N"
    printf '%s\n' "${C}+-- traffic -------------------------------------------+${N}"
    printf '  TX : %s%12s%s  (%s%s%s/s)  packets: %s\n' "$W" "$(human "$now_tx")" "$N" "$G" "$(human "$dtx")" "$N" "$txp"
    printf '  RX : %s%12s%s  (%s%s%s/s)  packets: %s\n' "$W" "$(human "$now_rx")" "$N" "$G" "$(human "$drx")" "$N" "$rxp"
    printf '%s\n' "${C}+-- security ------------------------------------------+${N}"
    printf '  auth failures (auth_fail) : %s%s%s\n' "$Y" "$af" "$N"
    printf '  replay drops              : %s%s%s\n' "$Y" "$rd" "$N"
    printf '  key rotation              : %s\n' "$rk"
    printf '%s\n' "${C}+-----------------------------------------------------+${N}"
    printf '%s\n' "${D}refresh every 2s — press q to quit${N}"

    read -r -t 2 -n 1 key || true
    [[ "${key:-}" == "q" ]] && break
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
    printf '\n'; err "No reply. Check: both services active, UDP port open, key/roles correct."
  fi
  pause
}

show_logs() {
  hdr "Live logs (Ctrl+C to exit)"
  journalctl -u aestun -f --no-hostname 2>/dev/null || journalctl -u aestun -n 50 --no-pager
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

zap_install() {
  hdr "Install zapret (builds nfqws from source)"
  # Upstream zapret ships NO prebuilt binaries in the git tree, so we build nfqws.
  ensure_deps
  export DEBIAN_FRONTEND=noninteractive
  msg "Installing build dependencies..."
  apt-get update -y >/dev/null 2>&1 || true
  if ! apt-get install -y git iptables build-essential zlib1g-dev \
        libnetfilter-queue-dev libnfnetlink-dev libmnl-dev libcap-dev >/dev/null 2>&1; then
    err "Failed to install build dependencies (apt)."; pause; return
  fi

  if [[ -d "$ZAPRET_DIR/.git" ]]; then
    warn "Repo present; updating..."; ( cd "$ZAPRET_DIR" && git pull --ff-only ) >/dev/null 2>&1 || warn "git pull failed (continuing)."
  else
    msg "Cloning zapret..."
    git clone --depth 1 https://github.com/bol-van/zapret "$ZAPRET_DIR" \
      || { err "git clone failed (no route to GitHub from this server?)."; pause; return; }
  fi

  msg "Building nfqws..."
  if make -C "$ZAPRET_DIR/nfq" nfqws >/tmp/nfqws-build.log 2>&1 && zap_installed; then
    msg "zapret ready: ${ZAP_BIN}"
    "$ZAP_BIN" --version 2>/dev/null | head -1 || true
  else
    err "Build failed. Last lines of /tmp/nfqws-build.log:"; tail -8 /tmp/nfqws-build.log
  fi
  pause
}

zap_enable() {
  hdr "Enable zapret on the tunnel port"
  zap_installed || { err "Install zapret first (option 1)."; pause; return; }
  [[ -f "$CONF" ]] || { err "Set up the tunnel first."; pause; return; }

  local peer host port qnum=200 transport desync
  peer="$(json_get "$CONF" peer)"; port="${peer##*:}"; host="${peer%:*}"
  [[ -z "$port" ]] && { err "Could not read peer port from config."; pause; return; }
  [[ -z "$host" ]] && { err "Could not read peer host from config."; pause; return; }
  transport="$(json_get "$CONF" transport)"; transport="${transport:-udp}"

  if [[ "$transport" == "tcp" ]]; then
    # multisplit only fragments the TCP payload: the peer reassembles transparently so the
    # raw tunnel stream is never corrupted, while on-path DPI sees a split connection start.
    desync="--dpi-desync=multisplit --dpi-desync-split-pos=1,4,8"
  else
    # Every one of these three flags is load-bearing; see the unit comments below.
    desync="--dpi-desync=fake --dpi-desync-any-protocol=1 --dpi-desync-cutoff=n8 --dpi-desync-repeats=2 --dpi-desync-fooling=badsum"
  fi
  printf 'Carrier = %s%s / %s:%s%s (from config transport)\n' "$W" "$transport" "$host" "$port" "$N"

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
  pause
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
  [[ -n "$port" ]] && close_firewall "$port"
  confirm "Remove network optimization (sysctl tuning) too?" && remove_network_opt
  confirm "Delete config directory ${CONF_DIR}?" && rm -rf "$CONF_DIR"
  confirm "Delete zapret directory ${ZAPRET_DIR}?" && rm -rf "$ZAPRET_DIR"
  msg "Everything removed."
  pause
}

# ----------------------------------------------------------------- main menu
status_line() {
  local st ins peer
  st="$(svc_active aestun)"
  ins="not configured"; [[ -f "$CONF" ]] && ins="configured"
  local st_c="$R"; [[ "$st" == active ]] && st_c="$G"
  peer="$(json_get "$CONF" peer 2>/dev/null)"
  printf '%s\n' "${D}status: ${st_c}${st}${N}${D} | ${ins} | peer: ${peer:-–} | arch: $(arch_tag)${N}"
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
  ${C}6${N}) Show config
  ${C}7${N}) Edit config
  ${C}8${N}) Generate new key
  ${C}9${N}) Network optimization
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
      6) show_config ;;
      7) edit_config ;;
      8) do_keygen ;;
      9) netopt_menu ;;
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
  local peer host port proto qnum=200
  peer="$(json_get "$CONF" peer)"; host="${peer%:*}"; port="${peer##*:}"
  proto="$(json_get "$CONF" transport)"; proto="${proto:-udp}"
  [[ -n "$host" && -n "$port" ]] || { echo "zap-rule: cannot read peer from $CONF" >&2; return 1; }

  # Scope to the peer host; connbytes keeps nfqws on the opening packets only (DPI
  # classifies a flow at its start, and round-tripping a multi-hundred-Mbit carrier
  # through userspace on every packet costs real CPU and latency). --connbytes-dir both
  # because after a flush whichever side sends first becomes conntrack's "original".
  local match=(-d "$host" -p "$proto" --dport "$port"
               -m connbytes --connbytes-dir both --connbytes-mode packets --connbytes 1:8)
  # --queue-bypass is load-bearing: a dead/wedged nfqws then lets the carrier flow
  # untouched instead of every packet hitting an unread queue and being dropped.
  local target=(-j NFQUEUE --queue-num "$qnum" --queue-bypass)

  case "${1:-}" in
    add)
      iptables -t mangle -C OUTPUT "${match[@]}" "${target[@]}" 2>/dev/null \
        || iptables -t mangle -A OUTPUT "${match[@]}" "${target[@]}" ;;
    del)
      iptables -t mangle -D OUTPUT "${match[@]}" "${target[@]}" 2>/dev/null || true ;;
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
      conntrack -D -p "$proto" --src "$host" --dport "$port" >/dev/null 2>&1
      conntrack -D -p "$proto" --dst "$host" --dport "$port" >/dev/null 2>&1
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

  ( cd "$LIB_DIR" && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -ldflags "-s -w" -o "$out" . ) \
    && msg "built: ${out}" \
    && printf '   copy to a server:  scp %s root@SERVER:/usr/local/bin/aestun\n' "$out"
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
  install)  do_install; exit $? ;;
  menu|"")  need_root; install -m 0755 "$SELF" "$MGR_DST" 2>/dev/null || true; main_menu ;;
  -h|--help|help)
    cat <<'USAGE'
aestun.sh — one file: installer + manager + monitor + zapret + build

  sudo ./aestun.sh              management menu (default)
  sudo ./aestun.sh install      interactive installer (run on each server)
  ./aestun.sh build [arch]      cross-compile a static binary (dev machine)
  ./aestun.sh zap-rule VERB     NFQUEUE helper {add|del|rearm}, invoked by systemd
USAGE
    exit 0 ;;
  *) err "unknown command: $1  (try: install | menu | zap-rule | build)"; exit 1 ;;
esac
