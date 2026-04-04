# UpdateIP

A password-protected Flask web app that monitors your public IP address and automatically updates Cloudflare DNS records when it changes. Supports **multi-WAN** setups with **UniFi controller integration** for automatic WAN detection. Also integrates with **Nginx Proxy Manager** for proxy host management and **mDNS** for easy local network access.

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.x-green?logo=flask&logoColor=white)
![Bootstrap](https://img.shields.io/badge/Bootstrap-5-purple?logo=bootstrap&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-yellow)

## Features

- **Multi-WAN Support** — Manage multiple WAN interfaces and assign each DNS record to a specific WAN
- **UniFi Integration** — Auto-detect WAN IPs and ISP info from UniFi Dream Machine (UDM, UDM-Pro, UDM-SE, UCG)
- **IP Monitoring** — Automatically detects public IP changes via multiple providers
- **Cloudflare DNS Updates** — Auto-updates selected A records when IP changes
- **All Record Types** — View and manage A, CNAME, MX, TXT, and all other DNS record types
- **Per-Domain Grouping** — DNS records organized by domain with clear section headers
- **Multiple Accounts** — Manage multiple Cloudflare accounts and zones
- **Nginx Proxy Manager** — Full CRUD for proxy hosts on a remote NPM instance
- **Background Scheduler** — Configurable sync intervals for UniFi, Cloudflare, and NPM
- **Manual & Force Update** — Check & Update (only when IP changed) or Force Update All (push to all records regardless)
- **Change History** — Full log of IP changes and DNS update results
- **Timezone Support** — Configurable timezone for all displayed timestamps
- **mDNS / Bonjour** — Access the app via `updateip.local` on your network (configurable hostname via Avahi)
- **Mobile Responsive** — Collapsible sidebar navigation for phones and tablets
- **Dark Theme UI** — Clean Bootstrap 5 dark interface
- **Password Protected** — bcrypt-hashed passwords, session-based authentication

## Screenshots

| Dashboard | Proxy Manager |
|-----------|---------------|
| IP status, monitored records, recent activity | List, add, edit, delete NPM proxy hosts |

## Quick Start

### Requirements

- Debian/Ubuntu Linux (tested on Debian 13)
- Python 3.10+
- Cloudflare account with API token ([Zone:DNS:Edit + Zone:Zone:Read](https://dash.cloudflare.com/profile/api-tokens))
- *(Optional)* Nginx Proxy Manager instance for proxy host management

### Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/Updateip.git
cd Updateip

# Run the setup script (installs everything)
sudo bash setup.sh
```

The setup script will:
1. Install system dependencies (avahi-daemon for mDNS)
2. Create a Python virtual environment
3. Install all dependencies
4. Initialize the SQLite database
5. Configure a systemd service (port 5000)
6. Set up Nginx reverse proxy (port 80 → 5000)

### Default Login

```
Username: admin
Password: admin
```

> **Change the default password immediately** via Settings after first login.

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

### 7. Nginx Proxy Manager (Optional)

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
  settings.html     — Password, timezone, mDNS hostname, sync intervals
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

Source Available — free to use and share, but modifications and derivative works are not permitted. See [LICENSE](LICENSE) for details.
