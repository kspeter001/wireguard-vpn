#!/usr/bin/env bash
# WireGuard VPN installer + toolkit + Telegram bot for Ubuntu 22.04 / 24.04 LTS
#
# Install (once, as root — always asks for Telegram BOT_TOKEN + AUTHORIZED_USER):
#   sudo bash wireguard-vpn.sh install
#   sudo bash wireguard-vpn.sh install 104.194.153.76
#
# CLI:
#   sudo vpn users | add | show | conf-path | delete | online | status | server
#
# Telegram (after install):
#   /users /add /show /conf /delete /online /status /server /help /id
#
# Reconfigure bot only:
#   sudo bash wireguard-vpn.sh bot
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

WG_DIR="/etc/wireguard"
WG_IF="wg0"
WG_CONF="${WG_DIR}/${WG_IF}.conf"
WG_PORT="51820"
VPN_NET="10.8.0"
SERVER_ADDR="${VPN_NET}.1/24"
CLIENTS_DIR="${WG_DIR}/clients"
ENDPOINT_FILE="${WG_DIR}/server_endpoint"
SERVER_PRIV_FILE="${WG_DIR}/server_private.key"
SERVER_PUB_FILE="${WG_DIR}/server_public.key"
VPN_BIN="/usr/local/bin/vpn"
BOT_DIR="/opt/vpn-telegram-bot"
BOT_ENV="${WG_DIR}/telegram-bot.env"
BOT_PY="${BOT_DIR}/telegram_vpn_bot.py"
BOT_VENV="${BOT_DIR}/venv"
BOT_SERVICE="vpn-telegram-bot.service"

die() { echo "ERROR: $*" >&2; exit 1; }
need_root() { [[ ${EUID:-$(id -u)} -eq 0 ]] || die "Run as root (sudo)."; }

wan_interface() {
  ip -4 route show default 2>/dev/null | awk '{print $5}' | head -n1
}

detect_public_ip() {
  local ip=""
  ip="$(curl -4 -fsS --max-time 8 https://ifconfig.me 2>/dev/null || true)"
  [[ -z "$ip" ]] && ip="$(curl -4 -fsS --max-time 8 https://api.ipify.org 2>/dev/null || true)"
  [[ -z "$ip" ]] && ip="$(curl -4 -fsS --max-time 8 https://icanhazip.com 2>/dev/null || true)"
  ip="$(tr -d '[:space:]' <<<"$ip")"
  [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  printf '%s\n' "$ip"
}

ubuntu_ok() {
  [[ -f /etc/os-release ]] || return 1
  # shellcheck disable=SC1091
  . /etc/os-release
  [[ "${ID:-}" == "ubuntu" ]] || return 1
  case "${VERSION_ID:-}" in
    22.04|24.04) return 0 ;;
    *) return 1 ;;
  esac
}

# ---------------------------------------------------------------------------
# Install /usr/local/bin/vpn toolkit
# ---------------------------------------------------------------------------
install_vpn_toolkit() {
  cat > "$VPN_BIN" <<'VPN'
#!/usr/bin/env bash
set -euo pipefail

WG_DIR="/etc/wireguard"
WG_IF="wg0"
WG_CONF="${WG_DIR}/${WG_IF}.conf"
WG_PORT="51820"
VPN_NET="10.8.0"
CLIENTS_DIR="${WG_DIR}/clients"
ENDPOINT_FILE="${WG_DIR}/server_endpoint"
SERVER_PUB_FILE="${WG_DIR}/server_public.key"
ONLINE_SECONDS=180

die() { echo "ERROR: $*" >&2; exit 1; }
need_root() { [[ ${EUID:-$(id -u)} -eq 0 ]] || die "Run as root (sudo)."; }

valid_name() {
  [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$ ]]
}

require_installed() {
  [[ -f "$WG_CONF" ]] || die "WireGuard not installed. Run: sudo bash wireguard-vpn.sh install"
  [[ -f "$SERVER_PUB_FILE" ]] || die "Missing $SERVER_PUB_FILE"
  [[ -f "$ENDPOINT_FILE" ]] || die "Missing $ENDPOINT_FILE (re-run install)"
  mkdir -p "$CLIENTS_DIR"
  chmod 700 "$CLIENTS_DIR" "$WG_DIR"
}

next_client_ip() {
  local used next
  used="$(grep -oE "${VPN_NET}\.[0-9]+" "$WG_CONF" 2>/dev/null | awk -F. '{print $4}' | sort -n -u || true)"
  for next in $(seq 2 254); do
    if ! grep -qx "$next" <<<"$used"; then
      printf '%s\n' "$next"
      return 0
    fi
  done
  return 1
}

handshake_age() {
  local pub="$1" ts now
  ts="$(wg show "$WG_IF" latest-handshakes 2>/dev/null | awk -v p="$pub" '$1 == p {print $2; exit}')"
  [[ -n "${ts:-}" && "$ts" != "0" ]] || { echo ""; return 1; }
  now="$(date +%s)"
  echo $((now - ts))
}

is_online() {
  local age
  age="$(handshake_age "$1" || true)"
  [[ -n "$age" && "$age" -le "$ONLINE_SECONDS" ]]
}

cmd_users() {
  if compgen -G "${CLIENTS_DIR}/*.conf" >/dev/null; then
    basename -a -s .conf "${CLIENTS_DIR}"/*.conf
  else
    echo "No users found"
  fi
}

cmd_add() {
  local name="" no_qr=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --no-qr|--quiet|-q) no_qr=1; shift ;;
      -*) die "Unknown option: $1" ;;
      *) name="$1"; shift ;;
    esac
  done

  [[ -n "$name" ]] || die "Usage: vpn add <name> [--no-qr]"
  valid_name "$name" || die "Name must be 1-32 chars: letters, numbers, . _ -"
  [[ -f "${CLIENTS_DIR}/${name}.conf" ]] && die "User '$name' already exists"
  command -v wg >/dev/null && command -v qrencode >/dev/null || die "wireguard-tools / qrencode missing"

  exec 9>"${WG_DIR}/clients.lock"
  flock 9

  local next_ip server_pub server_ip client_priv client_pub client_conf
  next_ip="$(next_client_ip)" || die "No free IPs left in ${VPN_NET}.0/24"
  server_pub="$(tr -d '\n' < "$SERVER_PUB_FILE")"
  server_ip="$(tr -d '[:space:]' < "$ENDPOINT_FILE")"
  client_priv="$(wg genkey)"
  client_pub="$(wg pubkey <<<"$client_priv")"

  umask 077
  printf '%s\n' "$client_priv" > "${CLIENTS_DIR}/${name}_private.key"
  printf '%s\n' "$client_pub" > "${CLIENTS_DIR}/${name}_public.key"

  cat >> "$WG_CONF" <<EOF

[Peer]
# ${name}
PublicKey = ${client_pub}
AllowedIPs = ${VPN_NET}.${next_ip}/32
EOF

  client_conf="${CLIENTS_DIR}/${name}.conf"
  cat > "$client_conf" <<EOF
[Interface]
PrivateKey = ${client_priv}
Address = ${VPN_NET}.${next_ip}/24
DNS = 1.1.1.1

[Peer]
PublicKey = ${server_pub}
Endpoint = ${server_ip}:${WG_PORT}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

  chmod 600 "$client_conf" \
    "${CLIENTS_DIR}/${name}_private.key" \
    "${CLIENTS_DIR}/${name}_public.key" \
    "$WG_CONF"

  if ip link show "$WG_IF" >/dev/null 2>&1; then
    wg set "$WG_IF" peer "$client_pub" allowed-ips "${VPN_NET}.${next_ip}/32"
  else
    systemctl start "wg-quick@${WG_IF}"
  fi

  echo "User created: ${name} (${VPN_NET}.${next_ip})"
  echo "Saved: ${client_conf}"
  if [[ "$no_qr" -eq 0 ]]; then
    echo "Scan QR below:"
    qrencode -t ansiutf8 < "$client_conf"
  fi
}

cmd_delete() {
  local name="${1:-}"
  local conf pub_file pubkey

  [[ -n "$name" ]] || die "Usage: vpn delete <name>"
  conf="${CLIENTS_DIR}/${name}.conf"
  pub_file="${CLIENTS_DIR}/${name}_public.key"
  [[ -f "$conf" ]] || die "User not found: $name"
  [[ -f "$pub_file" ]] || die "Missing public key for $name"

  exec 9>"${WG_DIR}/clients.lock"
  flock 9

  pubkey="$(tr -d '[:space:]' < "$pub_file")"

  python3 - "$WG_CONF" "$pubkey" "$name" <<'PY'
import sys

path, pubkey, name = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path) as f:
    lines = f.read().splitlines(keepends=True)

out = []
i = 0
while i < len(lines):
    if lines[i].strip() == "[Peer]":
        block = [lines[i]]
        j = i + 1
        while j < len(lines):
            if lines[j].startswith("[") and lines[j].strip() != "[Peer]":
                break
            if lines[j].strip() == "[Peer]":
                break
            block.append(lines[j])
            if lines[j].strip() == "" and any(l.startswith("PublicKey") for l in block):
                j += 1
                break
            j += 1
        pub = ""
        for bl in block:
            if bl.startswith("PublicKey"):
                pub = bl.split("=", 1)[1].strip()
                break
        comment_match = any(bl.strip() == f"# {name}" for bl in block)
        if pub == pubkey or comment_match:
            i = j
            continue
        out.extend(block)
        i = j
        continue
    out.append(lines[i])
    i += 1

with open(path, "w") as f:
    f.write("".join(out))
PY

  rm -f "${CLIENTS_DIR}/${name}.conf" \
        "${CLIENTS_DIR}/${name}_private.key" \
        "${CLIENTS_DIR}/${name}_public.key"

  if ip link show "$WG_IF" >/dev/null 2>&1; then
    wg set "$WG_IF" peer "$pubkey" remove || true
  else
    systemctl start "wg-quick@${WG_IF}" || true
  fi

  echo "User deleted: $name"
}

cmd_show() {
  local name="" no_qr=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --no-qr|--quiet|-q) no_qr=1; shift ;;
      -*) die "Unknown option: $1" ;;
      *) name="$1"; shift ;;
    esac
  done
  local conf
  [[ -n "$name" ]] || die "Usage: vpn show <name>"
  conf="${CLIENTS_DIR}/${name}.conf"
  [[ -f "$conf" ]] || die "User not found: $name"
  echo "Config: $conf"
  if [[ "$no_qr" -eq 0 ]]; then
    echo "QR for ${name}:"
    qrencode -t ansiutf8 < "$conf"
  fi
}

cmd_online() {
  local found=0 conf name pub age
  echo "Online users (handshake ≤ ${ONLINE_SECONDS}s):"
  if ! compgen -G "${CLIENTS_DIR}/*.conf" >/dev/null; then
    echo "(none)"
    return 0
  fi
  for conf in "${CLIENTS_DIR}"/*.conf; do
    name="$(basename "$conf" .conf)"
    [[ -f "${CLIENTS_DIR}/${name}_public.key" ]] || continue
    pub="$(tr -d '[:space:]' < "${CLIENTS_DIR}/${name}_public.key")"
    if is_online "$pub"; then
      age="$(handshake_age "$pub")"
      printf '%s  (~%ss ago)\n' "$name" "$age"
      found=1
    fi
  done
  [[ "$found" -eq 1 ]] || echo "(none)"
}

cmd_status() {
  local conf name pub age
  echo "User Status:"
  if ! compgen -G "${CLIENTS_DIR}/*.conf" >/dev/null; then
    echo "No users found"
    return 0
  fi
  printf '%-20s %-10s %s\n' "USER" "STATE" "LAST_HANDSHAKE"
  printf '%-20s %-10s %s\n' "----" "-----" "--------------"
  for conf in "${CLIENTS_DIR}"/*.conf; do
    name="$(basename "$conf" .conf)"
    if [[ ! -f "${CLIENTS_DIR}/${name}_public.key" ]]; then
      printf '%-20s %-10s %s\n' "$name" "UNKNOWN" "missing public key"
      continue
    fi
    pub="$(tr -d '[:space:]' < "${CLIENTS_DIR}/${name}_public.key")"
    if age="$(handshake_age "$pub")"; then
      if [[ "$age" -le "$ONLINE_SECONDS" ]]; then
        printf '%-20s %-10s %ss ago\n' "$name" "ONLINE" "$age"
      else
        printf '%-20s %-10s %ss ago\n' "$name" "OFFLINE" "$age"
      fi
    else
      printf '%-20s %-10s %s\n' "$name" "OFFLINE" "never"
    fi
  done
}

cmd_server() {
  local endpoint peers online_count=0 name pub
  endpoint="$(tr -d '[:space:]' < "$ENDPOINT_FILE" 2>/dev/null || echo unknown)"
  echo "WireGuard server"
  echo "  Interface : ${WG_IF}"
  echo "  Endpoint  : ${endpoint}:${WG_PORT}"
  echo "  PublicKey : $(tr -d '\n' < "$SERVER_PUB_FILE")"
  echo "  Address   : ${VPN_NET}.1/24"
  if systemctl is-active --quiet "wg-quick@${WG_IF}"; then
    echo "  Service   : active"
  else
    echo "  Service   : inactive"
  fi
  peers=0
  if compgen -G "${CLIENTS_DIR}/*.conf" >/dev/null; then
    peers="$(find "$CLIENTS_DIR" -maxdepth 1 -name '*.conf' | wc -l | tr -d ' ')"
    for conf in "${CLIENTS_DIR}"/*.conf; do
      name="$(basename "$conf" .conf)"
      [[ -f "${CLIENTS_DIR}/${name}_public.key" ]] || continue
      pub="$(tr -d '[:space:]' < "${CLIENTS_DIR}/${name}_public.key")"
      if is_online "$pub"; then
        online_count=$((online_count + 1))
      fi
    done
  fi
  echo "  Clients   : ${peers} total, ${online_count} online"
  echo
  if ip link show "$WG_IF" >/dev/null 2>&1; then
    wg show "$WG_IF"
  else
    echo "(interface ${WG_IF} is down)"
  fi
}

cmd_help() {
  cat <<EOF
VPN Toolkit Commands:
  vpn users
  vpn add <name> [--no-qr]
  vpn delete <name>
  vpn show <name> [--no-qr]
  vpn online
  vpn status
  vpn server

Shortcuts:
  vpn-users | vpn-delete | vpn-show | vpn-online | vpn-status | add-vpn-user
EOF
}

main() {
  need_root
  case "${1:-}" in
    users|list)
      require_installed
      cmd_users
      ;;
    add)
      require_installed
      shift
      cmd_add "$@"
      ;;
    delete|remove|rm)
      require_installed
      shift
      cmd_delete "${1:-}"
      ;;
    show|qr)
      require_installed
      shift
      cmd_show "$@"
      ;;
    online)
      require_installed
      cmd_online
      ;;
    status)
      require_installed
      cmd_status
      ;;
    server|info)
      require_installed
      cmd_server
      ;;
    -h|--help|help|"")
      cmd_help
      ;;
    *)
      die "Unknown command: $1 (try: vpn help)"
      ;;
  esac
}

main "$@"
VPN
  chmod 755 "$VPN_BIN"

  cat > /usr/local/bin/vpn-users <<'EOF'
#!/usr/bin/env bash
exec /usr/local/bin/vpn users "$@"
EOF
  cat > /usr/local/bin/vpn-delete <<'EOF'
#!/usr/bin/env bash
exec /usr/local/bin/vpn delete "$@"
EOF
  cat > /usr/local/bin/vpn-show <<'EOF'
#!/usr/bin/env bash
exec /usr/local/bin/vpn show "$@"
EOF
  cat > /usr/local/bin/vpn-online <<'EOF'
#!/usr/bin/env bash
exec /usr/local/bin/vpn online "$@"
EOF
  cat > /usr/local/bin/vpn-status <<'EOF'
#!/usr/bin/env bash
exec /usr/local/bin/vpn status "$@"
EOF
  cat > /usr/local/bin/add-vpn-user <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "list" || "${1:-}" == "-l" || "${1:-}" == "--list" ]]; then
  exec /usr/local/bin/vpn users
fi
exec /usr/local/bin/vpn add "$@"
EOF

  chmod 755 /usr/local/bin/vpn-users \
            /usr/local/bin/vpn-delete \
            /usr/local/bin/vpn-show \
            /usr/local/bin/vpn-online \
            /usr/local/bin/vpn-status \
            /usr/local/bin/add-vpn-user
}

# ---------------------------------------------------------------------------
# Telegram bot
# ---------------------------------------------------------------------------
prompt_telegram_config() {
  local token="" auth=""
  echo
  echo "========================================"
  echo " Telegram Bot configuration (required)"
  echo "========================================"
  echo "1) Talk to @BotFather → /newbot → copy the token"
  echo "2) Talk to @userinfobot → copy your numeric user id"
  echo "   (You can authorize multiple ids: 111,222)"
  echo

  if [[ ! -t 0 ]]; then
    token="${WG_BOT_TOKEN:-}"
    auth="${WG_AUTHORIZED_USER:-}"
    [[ -n "$token" && -n "$auth" ]] || die "Non-interactive install needs WG_BOT_TOKEN and WG_AUTHORIZED_USER"
  else
    while true; do
      read -r -p "BOT_TOKEN: " token
      token="$(tr -d '[:space:]' <<<"$token")"
      if [[ "$token" =~ ^[0-9]+:[A-Za-z0-9_-]{20,}$ ]]; then
        break
      fi
      echo "Invalid token format. Example: 123456:ABC-DEF..."
    done
    while true; do
      read -r -p "AUTHORIZED_USER (Telegram numeric id): " auth
      auth="$(tr -d '[:space:]' <<<"$auth")"
      if [[ "$auth" =~ ^[0-9]+(,[0-9]+)*$ ]]; then
        break
      fi
      echo "Invalid id. Use digits only, or comma-separated ids."
    done
  fi

  BOT_TOKEN_VALUE="$token"
  AUTHORIZED_USER_VALUE="$auth"
}

install_telegram_bot_files() {
  mkdir -p "$BOT_DIR"
  if [[ -f "${SCRIPT_DIR}/telegram_vpn_bot.py" ]]; then
    cp -f "${SCRIPT_DIR}/telegram_vpn_bot.py" "$BOT_PY"
  else
    die "Missing telegram_vpn_bot.py next to this installer (${SCRIPT_DIR})"
  fi
  chmod 755 "$BOT_PY"

  umask 077
  cat > "$BOT_ENV" <<EOF
BOT_TOKEN=${BOT_TOKEN_VALUE}
AUTHORIZED_USER=${AUTHORIZED_USER_VALUE}
VPN_CMD=${VPN_BIN}
CLIENT_DIR=${CLIENTS_DIR}
ENDPOINT_FILE=${ENDPOINT_FILE}
WG_IF=${WG_IF}
EOF
  chmod 600 "$BOT_ENV"

  apt-get install -y python3-venv python3-pip >/dev/null
  if [[ ! -d "$BOT_VENV" ]]; then
    python3 -m venv "$BOT_VENV"
  fi
  # shellcheck disable=SC1091
  source "${BOT_VENV}/bin/activate"
  pip install --upgrade pip >/dev/null
  pip install 'python-telegram-bot==21.6' 'qrcode[pil]==7.4.2' >/dev/null
  deactivate

  cat > "/etc/systemd/system/${BOT_SERVICE}" <<EOF
[Unit]
Description=WireGuard VPN Telegram Bot
After=network-online.target wg-quick@${WG_IF}.service
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${BOT_DIR}
EnvironmentFile=${BOT_ENV}
ExecStart=${BOT_VENV}/bin/python ${BOT_PY}
Restart=always
RestartSec=5
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable "$BOT_SERVICE"
  systemctl restart "$BOT_SERVICE"
  sleep 1
  if systemctl is-active --quiet "$BOT_SERVICE"; then
    echo "Telegram bot service: active (${BOT_SERVICE})"
  else
    echo "WARNING: bot service failed to start. Check: journalctl -u ${BOT_SERVICE} -n 50 --no-pager" >&2
  fi
}

cmd_bot_only() {
  need_root
  prompt_telegram_config
  install_telegram_bot_files
  echo
  echo "Bot updated. Credentials saved in ${BOT_ENV} (mode 600)."
  echo "Test in Telegram: /help"
}

cmd_install() {
  need_root
  ubuntu_ok || echo "WARNING: this script targets Ubuntu 22.04/24.04 LTS. Continuing anyway." >&2

  # Always ask first so install does not finish without bot config
  prompt_telegram_config

  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y wireguard wireguard-tools qrencode iptables curl ufw python3

  local wan endpoint requested="${1:-}"
  wan="$(wan_interface)"
  [[ -n "$wan" ]] || die "Could not detect the default network interface (no default route)."

  if [[ -n "$requested" ]]; then
    [[ "$requested" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "Endpoint must be an IPv4 address, got: $requested"
    endpoint="$requested"
  else
    endpoint="$(detect_public_ip)" || die "Could not detect public IP. Re-run: sudo bash $0 install <YOUR_PUBLIC_IP>"
  fi

  mkdir -p "$WG_DIR" "$CLIENTS_DIR"
  chmod 700 "$WG_DIR" "$CLIENTS_DIR"
  umask 077

  if [[ ! -f "$SERVER_PRIV_FILE" ]]; then
    wg genkey | tee "$SERVER_PRIV_FILE" | wg pubkey > "$SERVER_PUB_FILE"
    chmod 600 "$SERVER_PRIV_FILE" "$SERVER_PUB_FILE"
  fi

  local server_priv
  server_priv="$(tr -d '\n' < "$SERVER_PRIV_FILE")"
  printf '%s\n' "$endpoint" > "$ENDPOINT_FILE"
  chmod 600 "$ENDPOINT_FILE"

  if [[ -f "$WG_CONF" ]]; then
    echo "Keeping existing $WG_CONF"
  else
    cat > "$WG_CONF" <<EOF
[Interface]
Address = ${SERVER_ADDR}
ListenPort = ${WG_PORT}
PrivateKey = ${server_priv}

PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o ${wan} -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o ${wan} -j MASQUERADE
EOF
    chmod 600 "$WG_CONF"
  fi

  cat > /etc/sysctl.d/99-wireguard-forward.conf <<'EOF'
net.ipv4.ip_forward=1
EOF
  sysctl -p /etc/sysctl.d/99-wireguard-forward.conf >/dev/null

  if grep -q '^DEFAULT_FORWARD_POLICY=' /etc/default/ufw; then
    sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
  fi

  ufw allow "${WG_PORT}/udp" comment 'WireGuard'
  ufw allow OpenSSH
  ufw allow 22/tcp comment 'SSH'
  ufw --force enable
  ufw reload || true

  install_vpn_toolkit
  install_telegram_bot_files

  systemctl enable "wg-quick@${WG_IF}"
  systemctl restart "wg-quick@${WG_IF}"
  systemctl is-active --quiet "wg-quick@${WG_IF}" || die "wg-quick@${WG_IF} failed to start. Check: journalctl -u wg-quick@${WG_IF}"

  echo
  echo "WireGuard is up."
  echo "  Interface : ${WG_IF} on ${wan}"
  echo "  Endpoint  : ${endpoint}:${WG_PORT}"
  echo "  Public key: $(tr -d '\n' < "$SERVER_PUB_FILE")"
  echo "  Telegram  : ${BOT_SERVICE}"
  echo
  echo "CLI:"
  echo "  sudo vpn users | add | show | delete | online | status | server"
  echo
  echo "Telegram:"
  echo "  /users /add /show /conf /delete /online /status /server /help /id"
}

cmd_help() {
  cat <<EOF
Usage:
  sudo bash $0 install [PUBLIC_IP]   # always prompts for BOT_TOKEN + AUTHORIZED_USER
  sudo bash $0 bot                   # reconfigure Telegram bot only
  sudo bash $0 toolkit               # refresh /usr/local/bin/vpn only

After install:
  sudo vpn users
  sudo vpn add <name>
  sudo vpn delete <name>
  sudo vpn show <name>
  sudo vpn online
  sudo vpn status
  sudo vpn server
  sudo systemctl status vpn-telegram-bot
EOF
}

main() {
  case "${1:-}" in
    install)
      shift
      cmd_install "${1:-}"
      ;;
    bot|telegram)
      cmd_bot_only
      ;;
    toolkit)
      need_root
      install_vpn_toolkit
      echo "Updated: $VPN_BIN and shortcuts"
      ;;
    -h|--help|help|"")
      cmd_help
      ;;
    *)
      die "Unknown command: $1"
      ;;
  esac
}

main "$@"
