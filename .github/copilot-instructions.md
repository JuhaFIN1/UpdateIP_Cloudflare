# UpdateIP — Copilot Instructions

## Project Overview

A password-protected Flask web app that monitors public IP changes across multiple WAN interfaces and auto-updates Cloudflare DNS records. Integrates with **UniFi controllers** for automatic WAN IP/ISP detection and with **Nginx Proxy Manager** for proxy host management.

## Tech Stack

- **Backend**: Python 3, Flask, Gunicorn
- **Database**: SQLite (WAL mode, foreign keys ON) — single file `updateip.db`
- **Frontend**: Jinja2 templates, Bootstrap 5 (dark theme), Bootstrap Icons
- **Scheduler**: Flask-APScheduler (background sync jobs)
- **Auth**: bcrypt password hashing, Flask session-based login
- **APIs**: Cloudflare API v4, UniFi OS API, Nginx Proxy Manager API
- **Deploy**: systemd service (`updateip.service`) + Nginx reverse proxy (port 80 → 5000)

## Architecture

```
app.py              — Main Flask app: routes, auth, scheduler setup
database.py         — SQLite schema, get_db(), init_db(), migrations
cloudflare_api.py   — Cloudflare REST client (zones, DNS records, token verify)
unifi_api.py        — UniFi OS controller API client (cached singleton, WAN detection)
npm_api.py          — Nginx Proxy Manager REST client (proxy hosts CRUD)
updater.py          — Multi-WAN IP detection + Cloudflare record update logic
config.py           — App config constants
wsgi.py             — Gunicorn entry point
templates/          — Jinja2 HTML templates (Bootstrap 5 dark theme)
  base.html         — Layout with sidebar nav
  login.html        — Standalone login page (no sidebar)
  dashboard.html    — WAN IPs, monitored records, recent activity
  accounts.html     — Cloudflare account management
  records.html      — DNS records grouped by domain with type badges
  wan.html          — WAN interfaces + UniFi connection settings
  npm.html          — NPM proxy host listing + connection settings modal
  npm_form.html     — Add/edit proxy host form
  logs.html         — IP change & DNS update history
  settings.html     — Password, timezone, system info with sync intervals
```

## Code Conventions

### Python
- Use raw SQLite via `sqlite3` — no ORM. Always call `get_db()` from `database.py`.
- Always close DB connections in routes (`db.close()`).
- All routes except `/login` require `@login_required` decorator.
- API clients (`cloudflare_api.py`, `npm_api.py`, `unifi_api.py`) are stateless modules — no Flask dependencies inside them.
- `unifi_api.py` uses a cached singleton client (`get_unifi_client()`) to avoid UDM login rate limiting.
- Use `logging.getLogger(__name__)` for module-level loggers.
- Secrets come from environment variables with fallback defaults.
- Timestamps displayed via `|localtime` Jinja filter using configured timezone (`zoneinfo` module).

### Templates
- All authenticated pages extend `base.html`.
- `login.html` is standalone (no sidebar).
- Use Bootstrap 5 dark theme (`data-bs-theme="dark"`), Bootstrap Icons for all icons.
- Flash messages rendered in `base.html` via `get_flashed_messages(with_categories=true)`.
- Sidebar highlights active page via `request.endpoint` checks.
- DNS records grouped by domain with type badges (A=blue, CNAME=cyan, MX=yellow, TXT=gray).

### Database
- Single settings row pattern: `WHERE id = 1` for `settings`, `npm_settings`, `unifi_settings` tables.
- Cloudflare IDs are TEXT (Cloudflare returns string UUIDs).
- Use `INSERT OR REPLACE` for synced Cloudflare data to handle re-sync.
- All timestamps use SQLite `CURRENT_TIMESTAMP` defaults.
- Key tables: `settings`, `wan_interfaces` (with isp_name), `unifi_settings`, `cf_records` (with wan_id), `cf_zones`, `cf_accounts`, `ip_log` (with wan_id), `update_log`.

## Build & Deploy

```bash
# Setup from scratch
bash setup.sh

# Restart after code changes
systemctl restart updateip

# View logs
journalctl -u updateip -f

# Service config
/etc/systemd/system/updateip.service
/etc/nginx/sites-available/updateip
```

## Key Patterns

- **UniFi sync + DNS update flow**: `scheduled_unifi_sync()` refreshes WAN IPs/ISP from UniFi (`stat/device` endpoint for WAN2, `stat/health` for WAN1), then calls `check_and_update_ip()` which compares stored IPs → updates Cloudflare records marked `auto_update=1` → logs to `ip_log` and `update_log`. This is a single merged job — no separate IP check job.
- **Multi-WAN**: Each `wan_interface` has a `detect_method` (unifi/static/auto). Each DNS record can be assigned to a specific WAN via `wan_id`. Unassigned records use auto-detected IP.
- **ISP detection**: UniFi provides ISP for WAN1 via `stat/health`. For WANs missing ISP info, `ip-api.com` is used as fallback.
- **Scheduler**: 3 APScheduler interval jobs: `unifi_sync` (WAN IPs + DNS updates), `cloudflare_sync` (re-sync records from Cloudflare), `npm_sync` (verify NPM connection). All intervals user-configurable (60s–86400s).
- **NPM integration**: `npm_api.py:NpmClient` authenticates via JWT token, stored credentials in `npm_settings` table. All proxy host CRUD goes through the NPM REST API.

## Important Notes

- Default login: `admin` / `admin` — user should change via Settings.
- The venv is at `/root/Updateip/venv/` — always activate before running Python manually.
- Cloudflare API tokens need `Zone:DNS:Edit` + `Zone:Zone:Read` permissions.
- NPM connection configured in-app via Proxy Manager page.
- UniFi controller connection configured in-app via WAN Interfaces page. Create a local-only admin on UniFi OS for best security.
