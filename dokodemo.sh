#!/usr/bin/env bash
# =============================================================================
#  dokodemo.sh — Dokodemo-Door tunnel manager + relay network tuning (Xray core)
#
#    sudo ./dokodemo.sh                  # tune the box, then ask for IP + ports
#    sudo ./dokodemo.sh menu             # management menu
#    sudo ./dokodemo.sh add 2522         # forward :2522 -> DEST:2522
#    sudo ./dokodemo.sh add 443 8443     # forward :443  -> DEST:8443
#    sudo ./dokodemo.sh del 2522
#    sudo ./dokodemo.sh list | status | restart | logs | tune | tune-off | uninstall
#
#  Network tuning is re-applied on every run and is deliberately scoped to the
#  relay: it only sets keys the aestun tunnel does NOT manage, and it never
#  touches aestun's config, its UDP carrier, tun0, or any firewall rule.
#  Set DOKO_TUNE=0 to skip tuning for one run.
# =============================================================================
set -uo pipefail

# ------------------------------------------------------------------ defaults
DEFAULT_DEST="${DOKO_DEST:-10.8.0.2}"     # tunnel-side address of the far end
DEFAULT_PORT="${DOKO_PORT:-2522}"         # first port suggested by the wizard
API_PORT=62789                            # Xray internal api inbound

CONF_DIR="/usr/local/etc/xray"
CONF="${CONF_DIR}/config.json"
XRAY_BIN="/usr/local/bin/xray"
INSTALL_URL="https://github.com/XTLS/Xray-install/raw/main/install-release.sh"

# Sorts AFTER 99-aestun.conf so the few keys shared with the tunnel resolve in
# our favour on boot; everything in it is inert for aestun's UDP carrier.
SYSCTL_FILE="/etc/sysctl.d/99-zz-dokodemo.conf"
UNIT_DROPIN_DIR="/etc/systemd/system/xray.service.d"
UNIT_DROPIN="${UNIT_DROPIN_DIR}/20-dokodemo-tuning.conf"

# Per-connection relay buffer, in KB. 81 ms RTT over the tunnel means a 100 Mbit
# flow has ~1 MB in flight, so a small buffer caps throughput. Costs roughly
# 2 x this per active connection — drop it to 128 if RAM gets tight.
BUFFER_KB="${DOKO_BUFFER_KB:-512}"

# -------------------------------------------------------------------- colors
if [[ -t 1 ]]; then
  R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; C=$'\e[36m'; D=$'\e[2m'; BOLD=$'\e[1m'; N=$'\e[0m'
else
  R=""; G=""; Y=""; C=""; D=""; BOLD=""; N=""
fi
msg()  { printf '%s\n' "${G}[OK]${N} $*"; }
warn() { printf '%s\n' "${Y}[!]${N} $*"; }
err()  { printf '%s\n' "${R}[X]${N} $*" >&2; }
hdr()  { printf '\n%s\n' "${BOLD}${C}== $* ==${N}"; }
pause(){ printf '\n%s' "${D}Press Enter to continue...${N}"; read -r _; }

need_root() { [[ $EUID -eq 0 ]] || { err "Run as root (sudo)."; exit 1; }; }

valid_port() { [[ "${1:-}" =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 )); }

# Accepts IPv4, IPv6 or a hostname — Xray is happy with any of them.
valid_addr() {
  local a="${1:-}"
  [[ -n "$a" ]] || return 1
  [[ "$a" =~ ^[0-9a-fA-F:.\-]+$ || "$a" =~ ^[A-Za-z0-9.-]+$ ]]
}

py() { python3 -c "$1" "${@:2}"; }

# =============================================================================
#  Network tuning
# =============================================================================
# Everything here is relay-scoped. aestun already owns congestion control (bbr),
# the qdisc (fq), socket-buffer ceilings, tcp_rmem/wmem, mtu_probing, fastopen
# and the UDP buffers — those are left exactly as the tunnel installer set them.
write_sysctl() {
  cat > "$SYSCTL_FILE" <<'EOF'
# Managed by dokodemo.sh — relay-side tuning only.
#
# Loaded after 99-aestun.conf on purpose. Nothing below changes congestion
# control, the qdisc, socket-buffer ceilings or the UDP buffers that the aestun
# tunnel depends on; those stay under the tunnel installer's control.

# --- Accept path -------------------------------------------------------------
# A dokodemo relay accepts far more TCP connections than the tunnel's single UDP
# socket ever will, and somaxconn caps the listen backlog Xray asks for.
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 16384

# --- Ephemeral ports ---------------------------------------------------------
# Each inbound connection consumes one local port for the leg toward the peer.
# The stock ~28k range is the first thing a busy relay runs out of.
net.ipv4.ip_local_port_range = 10240 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_max_tw_buckets = 262144

# --- Latency under load ------------------------------------------------------
# Cap what the relay may keep queued in its own send buffer, so a bulk transfer
# cannot push seconds of delay in front of an interactive flow on the same link.
net.ipv4.tcp_notsent_lowat = 131072

# --- Path metrics ------------------------------------------------------------
# RTT and cwnd over the tunnel move around a lot; seeding a new connection from
# a cached bad sample makes the first seconds worse, not better.
net.ipv4.tcp_no_metrics_save = 1
EOF
}

net_tune() {
  local quiet="${1:-}"
  write_sysctl
  # -p applies only this file, so a re-run never re-asserts anyone else's keys.
  if sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1; then
    [[ "$quiet" == "quiet" ]] || msg "Relay sysctl applied (${SYSCTL_FILE})."
  else
    warn "Some sysctl keys were rejected by this kernel:"
    sysctl -p "$SYSCTL_FILE" 2>&1 | grep -i "cannot\|error" | head -5
  fi

  mkdir -p "$UNIT_DROPIN_DIR"
  cat > "$UNIT_DROPIN" <<'EOF'
# Managed by dokodemo.sh. Separate drop-in so the official Xray unit and its
# 10-donot_touch_single_conf.conf stay untouched.
[Service]
LimitNOFILE=1048576
LimitNPROC=infinity
TasksMax=infinity
Restart=always
RestartSec=3
EOF
  systemctl daemon-reload
  [[ "$quiet" == "quiet" ]] || msg "Xray service limits applied (${UNIT_DROPIN})."
}

tune_off() {
  hdr "Reverting relay tuning"
  rm -f "$SYSCTL_FILE" "$UNIT_DROPIN"
  systemctl daemon-reload
  msg "Removed. aestun's own sysctl file was not touched."
  warn "Kernel values stay as-is until reboot (or run: sysctl --system)."
}

show_tuning() {
  hdr "Relay tuning in effect"
  sysctl -n net.core.somaxconn net.ipv4.ip_local_port_range net.ipv4.tcp_tw_reuse \
            net.ipv4.tcp_notsent_lowat net.ipv4.tcp_no_metrics_save 2>/dev/null |
  paste -d'|' - - - - - | while IFS='|' read -r a b c d e; do
    printf '  somaxconn=%s  local_ports=%s  tw_reuse=%s  notsent_lowat=%s  no_metrics_save=%s\n' \
      "$a" "$(echo $b)" "$c" "$d" "$e"
  done
  hdr "Left to aestun (unchanged)"
  printf '  congestion=%s  qdisc=%s  rmem_max=%s  mtu_probing=%s\n' \
    "$(sysctl -n net.ipv4.tcp_congestion_control)" \
    "$(sysctl -n net.core.default_qdisc)" \
    "$(sysctl -n net.core.rmem_max)" \
    "$(sysctl -n net.ipv4.tcp_mtu_probing)"
}

# =============================================================================
#  Xray config
# =============================================================================
backup_conf() {
  [[ -f "$CONF" ]] || return 0
  cp -a "$CONF" "${CONF}.bak.$(date +%Y%m%d-%H%M%S)"
  ls -1t "${CONF}".bak.* 2>/dev/null | tail -n +6 | xargs -r rm -f
}

# Guarantees the skeleton every Dokodemo config needs — log block, local api
# inbound, tuned freedom outbound and the connection policy — without touching
# forwarding rules. The Xray installer drops a near-empty config.json, so this
# runs on every edit rather than only when the file is missing.
ensure_conf() {
  mkdir -p "$CONF_DIR" /var/log/xray
  [[ -f "$CONF" ]] || echo '{}' > "$CONF"
  py '
import json, sys
conf, api_port, buf = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
try:
    with open(conf) as f: c = json.load(f)
except (ValueError, OSError):
    c = {}
if not isinstance(c, dict): c = {}

c["log"] = {
    "loglevel": "warning",
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log",
}

# handshake/connIdle are what actually reclaim sockets on a relay; bufferSize is
# sized for the tunnel bandwidth-delay product.
c["policy"] = {
    "levels": {"0": {
        "handshake": 4,
        "connIdle": 300,
        "uplinkOnly": 2,
        "downlinkOnly": 5,
        "bufferSize": buf,
    }},
    "system": {"statsInboundUplink": False, "statsInboundDownlink": False},
}

ibs = c.setdefault("inbounds", [])
ibs[:] = [i for i in ibs if i.get("tag") != "api"]
ibs.insert(0, {
    "listen": "127.0.0.1",
    "port": api_port,
    "protocol": "dokodemo-door",
    "settings": {"address": "127.0.0.1"},
    "tag": "api",
})

# The leg toward the peer rides tun0, so it gets the same socket treatment as
# the client-facing leg.
c["outbounds"] = [
    {
        "protocol": "freedom",
        "tag": "direct",
        "settings": {"domainStrategy": "AsIs"},
        "streamSettings": {"sockopt": {
            "tcpNoDelay": True,
            "tcpKeepAliveIdle": 60,
            "tcpKeepAliveInterval": 15,
            "tcpcongestion": "bbr",
        }},
    },
    {"protocol": "blackhole", "tag": "blocked"},
]

with open(conf, "w") as f: json.dump(c, f, indent=2); f.write("\n")
' "$CONF" "$API_PORT" "$BUFFER_KB" || { err "Could not normalise ${CONF}"; return 1; }
}

# add_rule LISTEN_PORT DEST_PORT DEST_ADDR
add_rule() {
  local lport="$1" dport="$2" daddr="$3"
  backup_conf; ensure_conf || return 1
  py '
import json, sys
conf, lport, dport, daddr = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
with open(conf) as f: c = json.load(f)
ibs = c.setdefault("inbounds", [])
ibs[:] = [i for i in ibs if not (i.get("protocol") == "dokodemo-door"
                                 and i.get("tag") != "api" and i.get("port") == lport)]
ibs.append({
    "listen": None,
    "port": lport,
    "protocol": "dokodemo-door",
    "settings": {
        "address": daddr,
        "followRedirect": False,
        "network": "tcp,udp",
        "port": dport,
    },
    "streamSettings": {"sockopt": {
        "tcpFastOpen": True,
        "tcpNoDelay": True,
        "tcpKeepAliveIdle": 60,
        "tcpKeepAliveInterval": 15,
        "tcpcongestion": "bbr",
    }},
    "tag": "inbound-%d" % lport,
})
with open(conf, "w") as f: json.dump(c, f, indent=2); f.write("\n")
' "$CONF" "$lport" "$dport" "$daddr" || { err "Failed to edit ${CONF}"; return 1; }
  msg "Rule set: ${BOLD}:${lport}${N} -> ${BOLD}${daddr}:${dport}${N}"
}

del_rule() {
  local lport="$1"
  [[ -f "$CONF" ]] || { err "No config at ${CONF}"; return 1; }
  backup_conf; ensure_conf || return 1
  local removed
  removed=$(py '
import json, sys
conf, lport = sys.argv[1], int(sys.argv[2])
with open(conf) as f: c = json.load(f)
ibs = c.get("inbounds", [])
before = len(ibs)
ibs[:] = [i for i in ibs if not (i.get("protocol") == "dokodemo-door"
                                 and i.get("tag") != "api" and i.get("port") == lport)]
with open(conf, "w") as f: json.dump(c, f, indent=2); f.write("\n")
print(before - len(ibs))
' "$CONF" "$lport") || { err "Failed to edit ${CONF}"; return 1; }
  if [[ "$removed" == "0" ]]; then warn "No rule was listening on ${lport}."
  else msg "Removed the rule on port ${lport}."; fi
}

list_rules() {
  [[ -f "$CONF" ]] || { printf '  (no config yet)\n'; return 0; }
  py '
import json, sys
try:
    with open(sys.argv[1]) as f: c = json.load(f)
except Exception:
    print("  (config unreadable)"); raise SystemExit
rows = [i for i in c.get("inbounds", [])
        if i.get("protocol") == "dokodemo-door" and i.get("tag") != "api"]
if not rows:
    print("  (no forwarding rules)")
else:
    print("  %-8s %-8s %-28s %s" % ("LISTEN", "PROTO", "DESTINATION", "TAG"))
    for i in sorted(rows, key=lambda r: r.get("port", 0)):
        s = i.get("settings", {})
        print("  %-8s %-8s %-28s %s" % (
            i.get("port"), s.get("network", "tcp"),
            "%s:%s" % (s.get("address"), s.get("port")), i.get("tag", "")))
' "$CONF"
}

# ------------------------------------------------------------------- install
install_xray() {
  if [[ -x "$XRAY_BIN" ]]; then
    msg "Xray present: $("$XRAY_BIN" version 2>/dev/null | head -1)"
    return 0
  fi
  hdr "Installing Xray core"
  command -v curl >/dev/null || { apt-get update -qq && apt-get install -y curl; }
  bash -c "$(curl -L "$INSTALL_URL")" @ install || { err "Xray install failed."; return 1; }
  [[ -x "$XRAY_BIN" ]] || { err "Xray binary missing after install."; return 1; }
  msg "Xray installed: $("$XRAY_BIN" version 2>/dev/null | head -1)"
}

apply() {
  hdr "Applying configuration"
  if ! "$XRAY_BIN" run -test -config "$CONF" >/dev/null 2>&1; then
    err "Config failed validation — service NOT restarted, the running tunnel is untouched:"
    "$XRAY_BIN" run -test -config "$CONF" 2>&1 | tail -10
    return 1
  fi
  msg "Config syntax is valid."
  systemctl enable xray >/dev/null 2>&1
  systemctl restart xray || { err "systemctl restart xray failed."; return 1; }
  sleep 1
  if systemctl is-active --quiet xray; then msg "xray is running."
  else err "xray is not running:"; journalctl -u xray -n 20 --no-pager; return 1; fi
}

show_status() {
  hdr "Services"
  printf '  xray:            %s\n' "$(systemctl is-active xray 2>/dev/null || echo not-installed)"
  printf '  aestun (tunnel): %s\n' "$(systemctl is-active aestun 2>/dev/null || echo absent)"
  hdr "Forwarding rules"
  list_rules
  hdr "Listening sockets"
  ss -tulnp 2>/dev/null | grep -i xray || echo "  (none)"
  hdr "Destination reachability"
  [[ -f "$CONF" ]] || return 0
  while read -r addr port; do
    [[ -n "${addr:-}" ]] || continue
    if timeout 4 bash -c "cat < /dev/null > /dev/tcp/${addr}/${port}" 2>/dev/null; then
      printf '  %s%s:%s reachable%s\n' "$G" "$addr" "$port" "$N"
    else
      printf '  %s%s:%s NOT reachable%s\n' "$R" "$addr" "$port" "$N"
    fi
  done < <(py '
import json, sys
try:
    with open(sys.argv[1]) as f: c = json.load(f)
except Exception:
    raise SystemExit
for i in c.get("inbounds", []):
    if i.get("protocol") == "dokodemo-door" and i.get("tag") != "api":
        s = i.get("settings", {})
        print(s.get("address"), s.get("port"))
' "$CONF")
  show_tuning
}

uninstall() {
  hdr "Removing Xray"
  bash -c "$(curl -L "$INSTALL_URL")" @ remove --purge
  tune_off
  msg "Done. ${CONF}.bak.* backups (if any) were left in place."
}

# =============================================================================
#  Wizard — destination address once, then as many ports as wanted
# =============================================================================
wizard() {
  local daddr lport dport ans ports p n=0

  hdr "Destination"
  printf '  Address on the far side of the tunnel [%s]: ' "$DEFAULT_DEST"
  read -r daddr; daddr="${daddr:-$DEFAULT_DEST}"
  valid_addr "$daddr" || { err "That does not look like an address."; return 1; }

  if timeout 3 ping -c 1 -W 2 "$daddr" >/dev/null 2>&1; then
    msg "$daddr answers ping."
  else
    warn "$daddr does not answer ping — continuing anyway (ICMP is often filtered)."
  fi

  hdr "Ports"
  printf '  %s\n' "${D}Enter one or several ports (space or comma separated).${N}"
  while true; do
    if (( n == 0 )); then
      printf '  Port(s) to forward [%s]: ' "$DEFAULT_PORT"
      read -r ports; ports="${ports:-$DEFAULT_PORT}"
    else
      printf '  Additional port(s): '
      read -r ports
      [[ -n "${ports// /}" ]] || break
    fi

    for p in ${ports//,/ }; do
      valid_port "$p" || { err "Skipping '${p}' — not a valid port."; continue; }
      if ss -tuln 2>/dev/null | grep -qE "[:.]${p}\b" && ! grep -q "\"port\": ${p},"  "$CONF" 2>/dev/null; then
        warn "Port ${p} already has a listener from another service."
        printf '  Use it anyway? [y/N]: '; read -r ans
        [[ "$ans" =~ ^[yY]$ ]] || continue
      fi
      printf '  Destination port for :%s [%s]: ' "$p" "$p"
      read -r dport; dport="${dport:-$p}"
      valid_port "$dport" || { err "Invalid destination port — skipping ${p}."; continue; }
      add_rule "$p" "$dport" "$daddr" && n=$((n+1))
    done

    printf '\n  Add another port? [y/N]: '; read -r ans
    [[ "$ans" =~ ^[yY]$ ]] || break
  done

  (( n > 0 )) || { warn "No rules were added."; return 1; }
  return 0
}

# ---------------------------------------------------------------------- menu
menu() {
  while true; do
    clear 2>/dev/null
    printf '%s\n' "${BOLD}${C}  Dokodemo-Door tunnel manager${N}"
    printf '%s\n' "${D}  Xray core · relay tuning applied · no panel required${N}"
    hdr "Current state"
    printf '  xray: %s   |   tunnel (aestun): %s\n' \
      "$(systemctl is-active xray 2>/dev/null || echo not-installed)" \
      "$(systemctl is-active aestun 2>/dev/null || echo absent)"
    list_rules
    printf '\n'
    printf '  1) Add forwarding rules (wizard)\n'
    printf '  2) Delete a forwarding rule\n'
    printf '  3) Status, reachability and tuning\n'
    printf '  4) Restart xray\n'
    printf '  5) Live logs\n'
    printf '  6) Edit config by hand (nano)\n'
    printf '  7) Re-apply network tuning\n'
    printf '  8) Revert network tuning\n'
    printf '  9) Uninstall Xray\n'
    printf '  0) Exit\n\n'
    printf '  Choice: '; read -r ch
    case "$ch" in
      1) install_xray && wizard && apply; pause ;;
      2) printf '  Listen port to delete: '; read -r p
         valid_port "$p" && { del_rule "$p" && apply; } || err "Invalid port."; pause ;;
      3) show_status; pause ;;
      4) apply; pause ;;
      5) journalctl -u xray -f --no-pager ;;
      6) ${EDITOR:-nano} "$CONF"; apply; pause ;;
      7) net_tune; pause ;;
      8) tune_off; pause ;;
      9) uninstall; pause ;;
      0) exit 0 ;;
      *) err "Unknown choice."; sleep 1 ;;
    esac
  done
}

# ---------------------------------------------------------------------- entry
need_root
command -v python3 >/dev/null || { apt-get update -qq && apt-get install -y python3; }

CMD="${1:-wizard}"

# Tuning belongs to the box, not to a single rule, so it is re-applied on every
# run — except for the read-only and teardown commands.
case "$CMD" in
  list|status|logs|tune-off|uninstall) : ;;
  *) [[ "${DOKO_TUNE:-1}" == "1" ]] && net_tune quiet ;;
esac

case "$CMD" in
  wizard)
    printf '%s\n' "${BOLD}${C}Dokodemo-Door setup${N}"
    printf '%s\n' "${D}Network tuning applied. aestun tunnel settings untouched.${N}"
    if [[ -f "$CONF" ]]; then hdr "Existing rules"; list_rules; fi
    install_xray || exit 1
    wizard || exit 1
    apply || exit 1
    show_status ;;
  install)
    install_xray || exit 1
    add_rule "${2:-$DEFAULT_PORT}" "${3:-${2:-$DEFAULT_PORT}}" "${4:-$DEFAULT_DEST}" || exit 1
    apply || exit 1
    show_status ;;
  add)
    valid_port "${2:-}" || { err "Usage: $0 add LISTEN_PORT [DEST_PORT] [DEST_ADDR]"; exit 1; }
    add_rule "$2" "${3:-$2}" "${4:-$DEFAULT_DEST}" && apply ;;
  del|delete|rm)
    valid_port "${2:-}" || { err "Usage: $0 del LISTEN_PORT"; exit 1; }
    del_rule "$2" && apply ;;
  list)      list_rules ;;
  status)    show_status ;;
  restart)   apply ;;
  logs)      journalctl -u xray -f --no-pager ;;
  tune)      net_tune; show_tuning ;;
  tune-off)  tune_off ;;
  uninstall) uninstall ;;
  menu)      menu ;;
  *) err "Unknown command: $CMD"; exit 1 ;;
esac
