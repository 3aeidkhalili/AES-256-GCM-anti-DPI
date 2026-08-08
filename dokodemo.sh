#!/usr/bin/env bash
# =============================================================================
#  dokodemo.sh — Dokodemo-Door tunnel manager (Xray core, no panel required)
#
#    sudo ./dokodemo.sh                     # interactive menu
#    sudo ./dokodemo.sh install             # install Xray + first forward rule
#    sudo ./dokodemo.sh add 2522            # forward :2522 -> DEST:2522
#    sudo ./dokodemo.sh add 443 8443        # forward :443  -> DEST:8443
#    sudo ./dokodemo.sh del 2522            # remove a rule
#    sudo ./dokodemo.sh list | status | restart | logs | uninstall
#
#  Defaults are taken from the aestun tunnel on this box: traffic hitting a
#  public port here is handed to the peer over tun0, so it leaves encrypted.
# =============================================================================
set -uo pipefail

# ------------------------------------------------------------------ defaults
DEFAULT_DEST="${DOKO_DEST:-10.8.0.2}"     # tunnel-side address of the far end
DEFAULT_PORT="${DOKO_PORT:-2522}"         # port to listen on / forward to
API_PORT=62789                            # Xray internal api inbound

CONF_DIR="/usr/local/etc/xray"
CONF="${CONF_DIR}/config.json"
XRAY_BIN="/usr/local/bin/xray"
INSTALL_URL="https://github.com/XTLS/Xray-install/raw/main/install-release.sh"

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

# -------------------------------------------------------------- config helpers
# All JSON edits go through python3 so a malformed hand-edit can never be
# silently overwritten — the script fails loudly instead.
py() { python3 -c "$1" "${@:2}"; }

# Guarantees the skeleton every Dokodemo config needs — log block, the local api
# inbound, and the freedom/blackhole outbounds — without touching forwarding
# rules. The Xray installer drops a near-empty config.json, so this runs on every
# edit rather than only when the file is missing.
ensure_conf() {
  mkdir -p "$CONF_DIR" /var/log/xray
  [[ -f "$CONF" ]] || echo '{}' > "$CONF"
  py '
import json, sys
conf, api_port = sys.argv[1], int(sys.argv[2])
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

ibs = c.setdefault("inbounds", [])
ibs[:] = [i for i in ibs if i.get("tag") != "api"]
ibs.insert(0, {
    "listen": "127.0.0.1",
    "port": api_port,
    "protocol": "dokodemo-door",
    "settings": {"address": "127.0.0.1"},
    "tag": "api",
})

obs = c.get("outbounds") or []
if not any(o.get("protocol") == "freedom" for o in obs):
    obs.insert(0, {"protocol": "freedom"})
if not any(o.get("protocol") == "blackhole" for o in obs):
    obs.append({"protocol": "blackhole", "tag": "blocked"})
c["outbounds"] = obs

with open(conf, "w") as f: json.dump(c, f, indent=2); f.write("\n")
' "$CONF" "$API_PORT" || { err "Could not normalise ${CONF}"; return 1; }
}

backup_conf() {
  [[ -f "$CONF" ]] || return 0
  cp -a "$CONF" "${CONF}.bak.$(date +%Y%m%d-%H%M%S)"
  # Keep the five most recent backups; older ones are noise.
  ls -1t "${CONF}".bak.* 2>/dev/null | tail -n +6 | xargs -r rm -f
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
  [[ -f "$CONF" ]] || { warn "No config at ${CONF} yet."; return 0; }
  py '
import json, sys
with open(sys.argv[1]) as f: c = json.load(f)
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
    msg "Xray already installed: $("$XRAY_BIN" version 2>/dev/null | head -1)"
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
  if "$XRAY_BIN" run -test -config "$CONF" >/dev/null 2>&1; then
    msg "Config syntax is valid."
  else
    err "Config failed validation — service NOT restarted:"
    "$XRAY_BIN" run -test -config "$CONF" 2>&1 | tail -10
    return 1
  fi
  systemctl enable xray >/dev/null 2>&1
  systemctl restart xray || { err "systemctl restart xray failed."; return 1; }
  sleep 1
  if systemctl is-active --quiet xray; then msg "xray is running."
  else err "xray is not running:"; journalctl -u xray -n 20 --no-pager; return 1; fi
}

show_status() {
  hdr "Service"
  printf '  xray: %s\n' "$(systemctl is-active xray 2>/dev/null || echo not-installed)"
  printf '  aestun (tunnel): %s\n' "$(systemctl is-active aestun 2>/dev/null || echo absent)"
  hdr "Forwarding rules"
  list_rules
  hdr "Listening sockets"
  ss -tulnp 2>/dev/null | grep -i xray || echo "  (none)"
  hdr "Reachability of destinations"
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
with open(sys.argv[1]) as f: c = json.load(f)
for i in c.get("inbounds", []):
    if i.get("protocol") == "dokodemo-door" and i.get("tag") != "api":
        s = i.get("settings", {})
        print(s.get("address"), s.get("port"))
' "$CONF")
}

uninstall() {
  hdr "Removing Xray"
  bash -c "$(curl -L "$INSTALL_URL")" @ remove --purge
  msg "Done. ${CONF}.bak.* backups (if any) were left in place."
}

# ---------------------------------------------------------------------- menu
menu() {
  while true; do
    clear 2>/dev/null
    printf '%s\n' "${BOLD}${C}  Dokodemo-Door tunnel manager${N}"
    printf '%s\n' "${D}  Xray core · no panel required${N}"
    hdr "Current state"
    printf '  xray: %s   |   tunnel (aestun): %s\n' \
      "$(systemctl is-active xray 2>/dev/null || echo not-installed)" \
      "$(systemctl is-active aestun 2>/dev/null || echo absent)"
    list_rules
    printf '\n'
    printf '  1) Install Xray and create the first rule\n'
    printf '  2) Add / update a forwarding rule\n'
    printf '  3) Delete a forwarding rule\n'
    printf '  4) Status and destination check\n'
    printf '  5) Restart xray\n'
    printf '  6) Live logs\n'
    printf '  7) Edit config by hand (nano)\n'
    printf '  8) Uninstall Xray\n'
    printf '  0) Exit\n\n'
    printf '  Choice: '; read -r ch
    case "$ch" in
      1) install_xray && prompt_rule && apply; pause ;;
      2) prompt_rule && apply; pause ;;
      3) printf '  Listen port to delete: '; read -r p
         valid_port "$p" && { del_rule "$p" && apply; } || err "Invalid port."; pause ;;
      4) show_status; pause ;;
      5) apply; pause ;;
      6) journalctl -u xray -f --no-pager ;;
      7) ${EDITOR:-nano} "$CONF"; apply; pause ;;
      8) uninstall; pause ;;
      0) exit 0 ;;
      *) err "Unknown choice."; sleep 1 ;;
    esac
  done
}

prompt_rule() {
  local lport dport daddr
  printf '  Listen port on this server [%s]: ' "$DEFAULT_PORT"; read -r lport
  lport="${lport:-$DEFAULT_PORT}"
  valid_port "$lport" || { err "Invalid port."; return 1; }
  printf '  Destination address over the tunnel [%s]: ' "$DEFAULT_DEST"; read -r daddr
  daddr="${daddr:-$DEFAULT_DEST}"
  printf '  Destination port [%s]: ' "$lport"; read -r dport
  dport="${dport:-$lport}"
  valid_port "$dport" || { err "Invalid destination port."; return 1; }
  add_rule "$lport" "$dport" "$daddr"
}

# ---------------------------------------------------------------------- entry
need_root
command -v python3 >/dev/null || { apt-get update -qq && apt-get install -y python3; }

case "${1:-menu}" in
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
  uninstall) uninstall ;;
  menu)      menu ;;
  *) err "Unknown command: $1"; exit 1 ;;
esac
