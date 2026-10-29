#!/usr/bin/env bash
# UpdateIP - Copyright (c) 2026 BluexDEV Softwares. All rights reserved.
# Creates a Debian 13 LXC container on this Proxmox host and installs UpdateIP in it (clean install, no data).
# Run as root in the Proxmox shell:
#   bash -c "$(curl -fsSL https://raw.githubusercontent.com/JuhaFIN1/UpdateIP_Cloudflare/main/install/updateip-lxc.sh)"
# Optional overrides (skip the menus): CTID=120 HOSTNAME_CT=updateip CORES=1 RAM=512 DISK=4 STORAGE=local-lvm
#   TPLSTORE=local BRIDGE=vmbr0 IPCFG=dhcp|192.168.1.50/24 GW=192.168.1.1 BRANCH=main NONINTERACTIVE=1
# A free BluexDEV account (auth.selaa.fi) and a licence key are required. The licence is free for now,
# but it may become paid at any time, without prior notice. See the LICENSE file.
set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO: $BASH_COMMAND" >&2' ERR

REPO_URL="https://github.com/JuhaFIN1/UpdateIP_Cloudflare.git"
BRANCH="${BRANCH:-main}"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_RED=$'\e[31m'; C_GRN=$'\e[32m'; C_YEL=$'\e[33m'; C_BLU=$'\e[34m'; C_CYN=$'\e[36m'; C_RST=$'\e[0m'; C_BLD=$'\e[1m'
else C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_CYN=""; C_RST=""; C_BLD=""; fi
msg_info()  { printf '%s➜%s %s\n' "$C_BLU" "$C_RST" "$*"; }
msg_ok()    { printf '%s✔%s %s\n' "$C_GRN" "$C_RST" "$*"; }
msg_warn()  { printf '%s⚠%s %s\n' "$C_YEL" "$C_RST" "$*"; }
msg_error() { printf '%s✖%s %s\n' "$C_RED" "$C_RST" "$*" >&2; }

[ "$(id -u)" = 0 ] || { msg_error "Run as root in the Proxmox shell."; exit 1; }
command -v pct >/dev/null || { msg_error "This must run on a Proxmox VE host (pct not found)."; exit 1; }

printf '%s%s UpdateIP - Cloudflare DNS updater, multi-WAN, NPM  (Proxmox LXC installer)%s\n\n' "$C_BLD" "$C_CYN" "$C_RST"
msg_warn "A free BluexDEV account (auth.selaa.fi) and a licence key are required. Free for now; may become paid at any time."

have_wt() { command -v whiptail >/dev/null 2>&1 && [ -t 0 ] && [ -t 1 ] && [ -z "${NONINTERACTIVE:-}" ]; }
ask() { # ask "Title" "Prompt" default
  if have_wt; then whiptail --title "$1" --inputbox "$2" 10 64 "$3" 3>&1 1>&2 2>&3 || { msg_warn "Cancelled."; exit 0; }
  elif [ -t 0 ] && [ -z "${NONINTERACTIVE:-}" ]; then local v; read -rp "$2 [$3]: " v; printf '%s\n' "${v:-$3}"
  else printf '%s\n' "$3"; fi
}
choose() { # choose "Title" "Prompt" tag1 "Desc1" tag2 "Desc2"
  local title="$1" prompt="$2"; shift 2
  if have_wt; then whiptail --title "$title" --menu "$prompt" 15 64 $(($# / 2)) "$@" 3>&1 1>&2 2>&3 || { msg_warn "Cancelled."; exit 0; }
  elif [ -t 0 ] && [ -z "${NONINTERACTIVE:-}" ]; then
    local tags=() i=1 n; printf '%s\n' "$prompt" >&2
    while [ $# -gt 1 ]; do tags+=("$1"); printf '  %d) %s\n' "$i" "$2" >&2; i=$((i + 1)); shift 2; done
    read -rp "Choice [1-${#tags[@]}]: " n; printf '%s\n' "${tags[$(( ${n:-1} - 1 ))]}"
  else printf '%s\n' "$3"; fi
}
first_storage() { pvesm status --content "$1" | awk 'NR>1 {print $1; exit}'; }

# An UpdateIP container made by this installer already exists: never create a second one.
EXIST="$(pct list | awk 'NR>1 && $NF=="updateip" {print $1; exit}')"
if [ -n "$EXIST" ] && [ -z "${CTID:-}" ] && [ -z "${HOSTNAME_CT:-}" ]; then
  msg_warn "A container named 'updateip' already exists (CT $EXIST); not creating another. Update it from inside the app (Settings -> Update)."
  exit 0
fi

CTID="${CTID:-$(pvesh get /cluster/nextid)}"
HOSTNAME_CT="${HOSTNAME_CT:-updateip}"; CORES="${CORES:-1}"; RAM="${RAM:-512}"; DISK="${DISK:-4}"
STORAGE="${STORAGE:-$(first_storage rootdir)}"; TPLSTORE="${TPLSTORE:-$(first_storage vztmpl)}"
BRIDGE="${BRIDGE:-vmbr0}"; IPCFG="${IPCFG:-dhcp}"; GW="${GW:-}"

MODE="$(choose "UpdateIP LXC" "Choose install type" default "Default (1 core, 512 MB, 4 GB, DHCP)" advanced "Advanced (choose every setting)")"
if [ "$MODE" = advanced ]; then
  CTID="$(ask "Container" "Container ID" "$CTID")"
  HOSTNAME_CT="$(ask "Container" "Hostname" "$HOSTNAME_CT")"
  CORES="$(ask "Resources" "CPU cores" "$CORES")"; RAM="$(ask "Resources" "RAM (MB)" "$RAM")"; DISK="$(ask "Resources" "Disk (GB)" "$DISK")"
  STORAGE="$(ask "Storage" "Container storage" "$STORAGE")"; TPLSTORE="$(ask "Storage" "Template storage" "$TPLSTORE")"
  BRIDGE="$(ask "Network" "Bridge" "$BRIDGE")"
  if [ "$(choose "Network" "IP configuration (static is recommended: this app updates DNS when the public IP changes)" dhcp "DHCP" static "Static IP")" = static ]; then
    IPCFG="$(ask "Network" "IP address with prefix" "192.168.1.50/24")"; GW="$(ask "Network" "Gateway" "192.168.1.1")"
  fi
fi
[ -n "$STORAGE" ] && [ -n "$TPLSTORE" ] || { msg_error "No usable storage found (rootdir/vztmpl)."; exit 1; }
NETOPT="name=eth0,bridge=$BRIDGE,ip=$IPCFG"; [ -n "$GW" ] && NETOPT="$NETOPT,gw=$GW"
msg_ok "CT $CTID '$HOSTNAME_CT': $CORES core(s), ${RAM} MB, ${DISK} GB on $STORAGE, net $IPCFG${GW:+ gw $GW}"

msg_info "Preparing Debian template"
pveam update >/dev/null
ARCH="$(dpkg --print-architecture)"   # amd64 vs arm64: sort -V alone could pick the wrong one
pick() { pveam available --section system | awk -v a="$ARCH" -v d="$1" '$2 ~ ("^debian-" d "-standard.*_" a "[.]tar[.]zst$") {print $2}' | sort -V | tail -1; }
TPL="$(pick 13)"
[ -n "$TPL" ] || { msg_error "No Debian 13 template for $ARCH is offered by this Proxmox yet. Update Proxmox and retry."; exit 1; }
pveam list "$TPLSTORE" | grep -q "$TPL" || pveam download "$TPLSTORE" "$TPL"
msg_ok "Template: $TPL"

msg_info "Creating container $CTID"
pct create "$CTID" "$TPLSTORE:vztmpl/$TPL" --hostname "$HOSTNAME_CT" --cores "$CORES" --memory "$RAM" --swap 256 \
  --rootfs "$STORAGE:$DISK" --net0 "$NETOPT" --unprivileged 1 --features nesting=1 --onboot 1
if ! pct start "$CTID"; then
  msg_error "Container $CTID failed to start. Removing the container this script just created."
  pct destroy "$CTID" --purge || msg_warn "Remove it manually: pct destroy $CTID --purge"; exit 1
fi
for _ in $(seq 1 40); do pct exec "$CTID" -- hostname -I 2>/dev/null | grep -q '[0-9]' && break; sleep 1; done
msg_ok "Container started"

SETUP="$(mktemp)"
cat > "$SETUP" <<'EOS'
#!/usr/bin/env bash
# Runs inside the container. Never asks anything. Verbose log: /var/log/updateip-install.log
set -Eeuxo pipefail
export DEBIAN_FRONTEND=noninteractive
REPO_URL="$1"; BRANCH="$2"; APP=/opt/updateip
apt-get update -qq
apt-get install -y -qq -o Dpkg::Options::=--force-confold git python3 python3-venv python3-pip nginx avahi-daemon ca-certificates curl </dev/null
systemctl enable --now avahi-daemon

git clone --branch "$BRANCH" "$REPO_URL" "$APP"
python3 -m venv "$APP/venv"
"$APP/venv/bin/pip" install --quiet --upgrade pip
"$APP/venv/bin/pip" install --quiet -r "$APP/requirements.txt"

# Database. The first start creates the login admin/admin; the app forces a new password at the first sign-in.
cd "$APP"
"$APP/venv/bin/python" -c "from database import init_db; init_db()"
# Console defaults: root auto-login, banner with IP/URL, apt never asks questions.
"$APP/venv/bin/python" -c "from console_setup import ensure_console_defaults; ensure_console_defaults()"

cat > /etc/systemd/system/updateip.service <<'CFG'
[Unit]
Description=UpdateIP - Cloudflare DNS Updater
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/updateip
ExecStart=/opt/updateip/venv/bin/gunicorn --bind 127.0.0.1:5000 --workers 1 --threads 2 --timeout 120 wsgi:app
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
CFG

cat > /etc/nginx/sites-available/updateip <<'CFG'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 120s;
    }
}
CFG
rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/updateip /etc/nginx/sites-enabled/updateip
nginx -t
systemctl daemon-reload
systemctl enable --now updateip nginx
systemctl restart nginx

for _ in $(seq 1 30); do
  code="$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1/login || true)"
  [ "$code" = 200 ] && exit 0
  sleep 1
done
echo "UpdateIP did not answer on port 80. See: journalctl -u updateip -n 50" >&2
exit 1
EOS
pct push "$CTID" "$SETUP" /root/updateip-setup.sh
rm -f "$SETUP"

msg_info "Installing inside CT $CTID (log: /var/log/updateip-install.log in the container)"
pct exec "$CTID" -- bash -c "bash /root/updateip-setup.sh '$REPO_URL' '$BRANCH' 2>&1 | tee /var/log/updateip-install.log; exit \${PIPESTATUS[0]}" \
  || { msg_error "Install failed. Log: pct exec $CTID -- cat /var/log/updateip-install.log"; exit 1; }
pct exec "$CTID" -- rm -f /root/updateip-setup.sh
pct exec "$CTID" -- systemctl is-active --quiet updateip || { msg_error "updateip service is not active: pct exec $CTID -- journalctl -u updateip -n 50"; exit 1; }

IP="$(pct exec "$CTID" -- hostname -I | awk '{print $1}')"
echo
printf '%s✔ UpdateIP ready%s  (CT %s, Debian 13)\n' "$C_GRN$C_BLD" "$C_RST" "$CTID"
printf '  Open:     %shttp://%s%s  (or http://updateip.local)\n' "$C_CYN" "$IP" "$C_RST"
printf '  Login:    admin / admin  (you must choose your own password at the first sign-in)
'
printf '  Tip:      use a static IP or a DHCP reservation for this container.\n'
printf '  Update:   in the app, Settings -> Update.  Log: pct exec %s -- cat /var/log/updateip-install.log\n' "$CTID"
printf '  %sLicence: a free BluexDEV account (auth.selaa.fi) and licence key are required. Free for now; may become paid at any time.%s\n\n' "$C_YEL" "$C_RST"
