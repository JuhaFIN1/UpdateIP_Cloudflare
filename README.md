# Update IP - Unifi multi Wan, Cloudflare and Nginx Proxy Manager all in one

A password-protected Flask web app that monitors your public IP address and automatically updates Cloudflare DNS records when it changes. Supports **multi-WAN** setups with **UniFi controller integration** for automatic WAN detection. Also integrates with **Nginx Proxy Manager** for proxy host management and **mDNS** for easy local network access.

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.x-green?logo=flask&logoColor=white)
![Bootstrap](https://img.shields.io/badge/Bootstrap-5-purple?logo=bootstrap&logoColor=white)
![License](https://img.shields.io/badge/License-Source%20Available-orange)

## Features

- **Multi-WAN Support** — Manage multiple WAN interfaces and assign each DNS record to a specific WAN
- **UniFi Integration** — Auto-detect WAN IPs and ISP info from UniFi Dream Machine (UDM, UDM-Pro, UDM-SE, UCG)
- **IP Monitoring** — Automatically detects public IP changes via multiple providers
- **Cloudflare DNS Updates** — Auto-updates selected A records when IP changes
- **DNS Record CRUD** — Create, edit, and delete DNS records of all types (A, AAAA, CNAME, MX, TXT, SRV, NS, CAA) directly via Cloudflare API
- **Per-Domain Grouping** — DNS records organized by domain with clear section headers
- **Multiple Accounts** — Manage multiple Cloudflare accounts and zones
- **Nginx Proxy Manager** — Full CRUD for proxy hosts on a remote NPM instance
- **Background Scheduler** — Configurable sync intervals for UniFi, Cloudflare, and NPM
- **Manual & Force Update** — Check & Update (only when IP changed) or Force Update All (push to all records regardless)
- **Change History** — Full log of IP changes and DNS update results
- **Timezone Support** — Configurable timezone for all displayed timestamps
- **mDNS / Bonjour** — Access the app via `updateip.local` on your network (configurable hostname via Avahi)
- **Mobile Responsive** — Collapsible sidebar navigation for phones and tablets
- **Backup & Restore** — Download full system backup as JSON; upload and selectively restore with preview comparison
- **App Updates** — Automatic daily check for GitHub updates with dashboard notification; one-click install with live progress
- **System Updates** — Run Debian apt update & upgrade directly from the Settings page with live terminal output
- **Dark Theme UI** — Clean Bootstrap 5 dark interface
- **Password Protected** — bcrypt-hashed passwords, session-based authentication

## Quick Start

### What you need

- A **Proxmox VE** host (the installer creates a Debian 13 LXC container; about 512 MB RAM, 4 GB disk, 1 core)
- Internet access from the host and the container
- A **free BluexDEV account** (auth.selaa.fi). A licence key is created for you when you link the account. **The app does not work without a licence.**
- A **Cloudflare API token** ([Zone:DNS:Edit + Zone:Zone:Read](https://dash.cloudflare.com/profile/api-tokens))
- *(Optional)* A UniFi gateway for multi-WAN detection, and a Nginx Proxy Manager instance

> **Licence:** free for now, but it may become paid at any time, without prior notice. See [LICENSE](LICENSE).

### Install on Proxmox (one command)

1. Create your free account at https://auth.selaa.fi (the installation guide is at https://auth.selaa.fi/start/updateip).
2. Open the **Proxmox shell** (as root) and run:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/JuhaFIN1/UpdateIP_Cloudflare/main/install/updateip-lxc.sh)"
```

3. Choose **Default** (1 core, 512 MB, 4 GB, DHCP) or **Advanced** (container ID, resources, storage, bridge, **static IP**). A static IP or a DHCP reservation is recommended.
4. When it finishes, open the address it prints (`http://<container-ip>` or `http://updateip.local`).
5. Sign in. The username and a random password are in the container:

```bash
pct exec <CTID> -- cat /root/updateip-admin.txt
```

6. The app opens the **Licence** page. Click **Link BluexDEV account**, open the link, sign in and approve the code. The app unlocks when the licence is valid.
7. Add your Cloudflare account (see Usage below).

The installer creates a clean container with no data in it, installs the app to `/opt/updateip`, and logs to `/var/log/updateip-install.log` inside the container. It never creates a second container if one named `updateip` already exists.

**Updating:** in the app, go to **Settings** and use the update button. Your data is kept.

### Manual install (advanced)

Debian/Ubuntu with Python 3.10+ (tested on Debian 13), as root:

```bash
git clone https://github.com/JuhaFIN1/UpdateIP_Cloudflare.git
cd UpdateIP_Cloudflare
bash setup.sh
```

`setup.sh` installs avahi, creates a Python virtual environment, initializes the database, sets up a systemd service (port 5000) and an Nginx reverse proxy (port 80 to 5000). The default login of a manual install is `admin` / `admin`: **change it immediately** in Settings. The licence page works the same way as above.

## Usage

### 1. Add a Cloudflare Account

Go to **Accounts** → **Add Account** → enter a name and API token. Zones and DNS records (all types) are fetched automatically.

### 2. Configure WAN Interfaces

Go to **WAN Interfaces** to set up your internet connections:

- **UniFi Controller** — Click **UniFi Connection**, enter your UDM gateway IP (e.g., `https://192.168.1.1`), username, and password. WANs are auto-detected with IPs and ISP names.
- **Manual** — Add WANs manually with auto-detect (external IP services), static IP, or UniFi source.

> **Tip:** Create a local-only admin account on your UniFi OS console for best security.

### 3. Select Records for Auto-Update

Go to **DNS Records** → records are grouped by domain. Toggle **Auto-Update** on A records you want to keep in sync with your public IP. Assign each record to a specific WAN if you have multiple.

### 4. Monitor

The **Dashboard** shows each WAN IP with ISP info and last-checked timestamp, all monitored records with status, and recent update activity. Use **Check & Update** to trigger an update only if your IP changed, or **Force Update All** to push current IPs to every auto-update record regardless.

### 5. mDNS / Local Access

The app is accessible at `updateip.local` on your network by default. To change the hostname, go to **Settings** → **mDNS Hostname**. Works on any device that supports mDNS/Bonjour (iOS, macOS, most Linux, Windows with Bonjour).

### 6. Configure Timezone

Go to **Settings** → **Timezone** to set your display timezone. All timestamps throughout the app will display in your local time.

### 7. Backup & Restore

Go to **Settings** → **Backup & Restore**. **Download Backup** exports all settings, Cloudflare accounts, zones, records, WAN interfaces, UniFi settings, NPM settings, and proxy hosts as a JSON file. To restore, upload the backup file to see a comparison preview (identical / differs / new) for each section, then selectively restore only what you need.

### 8. Nginx Proxy Manager (Optional)

Go to **Proxy Manager** → **Connection** → enter your NPM URL (e.g., `http://192.168.1.100:81`), admin email, and password. Then manage all proxy hosts directly from UpdateIP.

## Architecture

```
app.py              — Main Flask app: routes, auth, scheduler
database.py         — SQLite schema and helpers
cloudflare_api.py   — Cloudflare API v4 client
unifi_api.py        — UniFi OS controller API client (UDM/UDM-Pro/UDM-SE)
npm_api.py          — Nginx Proxy Manager API client
updater.py          — IP detection + DNS update logic (multi-WAN)
config.py           — App configuration
wsgi.py             — Gunicorn entry point
setup.sh            — Automated setup script
templates/          — Jinja2 templates (Bootstrap 5 dark theme)
  base.html         — Layout with sidebar navigation
  dashboard.html    — IP status per WAN, monitored records, activity
  accounts.html     — Cloudflare account management
  records.html      — DNS records grouped by domain
  wan.html          — WAN interfaces + UniFi connection
  npm.html          — NPM proxy host listing
  npm_form.html     — Add/edit proxy host form
  logs.html         — IP change & DNS update history
  settings.html     — Password, timezone, mDNS hostname, updates, sync intervals, backup/restore
  restore.html      — Restore preview with comparison
  login.html        — Login page
```

## Management

```bash
# Service control
sudo systemctl status updateip
sudo systemctl restart updateip
sudo systemctl stop updateip

# View logs
journalctl -u updateip -f

# Service files
/etc/systemd/system/updateip.service
/etc/nginx/sites-available/updateip
```

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python 3, Flask, Gunicorn |
| Database | SQLite (WAL mode) |
| Frontend | Jinja2, Bootstrap 5 (dark), Bootstrap Icons |
| Scheduler | Flask-APScheduler |
| Auth | bcrypt, Flask sessions |
| APIs | Cloudflare API v4, UniFi OS API, NPM REST API |
| Deploy | systemd + Nginx reverse proxy |

## License

Copyright (c) 2026 BluexDEV Softwares

Source Available — modifications and derivative works are not permitted. A free BluexDEV account (auth.selaa.fi) and a licence key are required. The licence is free for now, but it may become paid at any time, without prior notice. See [LICENSE](LICENSE) for details.
