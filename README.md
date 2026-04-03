# UpdateIP

A password-protected Flask web app that monitors your public IP address and automatically updates Cloudflare DNS A records when it changes. Also integrates with Nginx Proxy Manager for full proxy host management.

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.x-green?logo=flask&logoColor=white)
![Bootstrap](https://img.shields.io/badge/Bootstrap-5-purple?logo=bootstrap&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-yellow)

## Features

- **IP Monitoring** — Automatically detects public IP changes via multiple providers
- **Cloudflare DNS Updates** — Auto-updates selected A records when IP changes
- **Multiple Accounts** — Manage multiple Cloudflare accounts and zones
- **Nginx Proxy Manager** — Full CRUD for proxy hosts on a remote NPM instance
- **Background Scheduler** — Configurable interval (1 min – 24 hours, default 5 min)
- **Manual & Force Update** — One-click update or force-push to all records
- **Change History** — Full log of IP changes and DNS update results
- **Dark Theme UI** — Clean Bootstrap 5 dark interface with sidebar navigation
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
1. Create a Python virtual environment
2. Install all dependencies
3. Initialize the SQLite database
4. Configure a systemd service (port 5000)
5. Set up Nginx reverse proxy (port 80 → 5000)

### Default Login

```
Username: admin
Password: admin
```

> **Change the default password immediately** via Settings after first login.

## Usage

### 1. Add a Cloudflare Account

Go to **Accounts** → **Add Account** → enter a name and API token. Zones and DNS records are fetched automatically.

### 2. Select Records for Auto-Update

Go to **DNS Records** → toggle **Auto-Update** on for records you want to keep in sync with your public IP.

### 3. Monitor

The **Dashboard** shows your current IP, all monitored records with status, and recent update activity. The background scheduler checks for IP changes automatically.

### 4. Nginx Proxy Manager (Optional)

Go to **Proxy Manager** → **Connection** → enter your NPM URL (e.g., `http://192.168.1.100:81`), admin email, and password. Then manage all proxy hosts directly from UpdateIP.

## Architecture

```
app.py              — Main Flask app: routes, auth, scheduler
database.py         — SQLite schema and helpers
cloudflare_api.py   — Cloudflare API v4 client
npm_api.py          — Nginx Proxy Manager API client
updater.py          — IP detection + DNS update logic
config.py           — App configuration
wsgi.py             — Gunicorn entry point
setup.sh            — Automated setup script
templates/          — Jinja2 templates (Bootstrap 5 dark theme)
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
| APIs | Cloudflare API v4, NPM REST API |
| Deploy | systemd + Nginx reverse proxy |

## License

MIT License — free to use, modify, and distribute.
