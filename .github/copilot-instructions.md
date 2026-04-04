# UpdateIP — Copilot Instructions

**Copyright (c) 2026 Juha Lempiäinen. All rights reserved.**

## Project Overview

A password-protected Flask web app that monitors public IP changes across multiple WAN interfaces and auto-updates Cloudflare DNS records. Integrates with **UniFi controllers** for automatic WAN IP/ISP detection, **Nginx Proxy Manager** for proxy host management, and **Avahi/mDNS** for local network discovery (default: `updateip.local`).

## Tech Stack

- **Backend**: Python 3, Flask, Gunicorn
- **Database**: SQLite (WAL mode, foreign keys ON) — single file `updateip.db`
- **Frontend**: Jinja2 templates, Bootstrap 5 (dark theme), Bootstrap Icons
- **Scheduler**: Flask-APScheduler (background sync jobs)
- **Auth**: bcrypt password hashing, Flask session-based login
- **APIs**: Cloudflare API v4, UniFi OS API, Nginx Proxy Manager API
- **Deploy**: systemd service (`updateip.service`) + Nginx reverse proxy (port 80 → 5000) + Avahi mDNS

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
  accounts.html     — Cloudflare accounts + UniFi connection + NPM connection (all-in-one)
  records.html      — DNS records grouped by domain with type badges
  wan.html          — WAN interfaces + UniFi sync (connection settings on accounts page)
  npm.html          — NPM proxy host listing (connection settings on accounts page)
  npm_form.html     — Add/edit proxy host form
  logs.html         — IP change & DNS update history
  settings.html     — Password, timezone, mDNS hostname, updates (app + system), system info with sync intervals, backup/restore
  restore.html      — Restore preview with comparison UI
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
- Timestamps displayed via `|localtime` Jinja filter using configured timezone (`zoneinfo` module). Relative times via `|timeago` filter.

### Templates
- All authenticated pages extend `base.html`.
- `base.html` is standalone (no sidebar).
- Use Bootstrap 5 dark theme (`data-bs-theme="dark"`), Bootstrap Icons for all icons.
- Sidebar uses `offcanvas-lg` — fixed column on desktop, slide-out menu on mobile with hamburger toggle.
- Flash messages rendered in `base.html` via `get_flashed_messages(with_categories=true)`.
- Sidebar highlights active page via `request.endpoint` checks.
- DNS records grouped by domain with type badges (A=blue, CNAME=cyan, MX=yellow, TXT=gray).

### Database
- Single settings row pattern: `WHERE id = 1` for `settings`, `npm_settings`, `unifi_settings` tables.
- Cloudflare IDs are TEXT (Cloudflare returns string UUIDs).
- Use `INSERT OR REPLACE` for synced Cloudflare data to handle re-sync.
- All timestamps use SQLite `CURRENT_TIMESTAMP` defaults.
- Key tables: `settings` (with mdns_hostname), `wan_interfaces` (with isp_name), `unifi_settings`, `cf_records` (with wan_id), `cf_zones`, `cf_accounts`, `ip_log` (with wan_id), `update_log`.
- Cloudflare sync uses `INSERT ... ON CONFLICT DO UPDATE` (not `INSERT OR REPLACE`) to avoid cascade-deleting records and losing `auto_update`/`wan_id` settings.

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
- **check_and_update_ip()**: Always iterates all `auto_update=1` records. Every check logs to `update_log` with three statuses: `no_change` (IP matches, no API call), `changed` (IP differed, pushed to Cloudflare), `error` (Cloudflare API failed). Records with an explicit `wan_id` **never** fall back to `auto_ip` — if their WAN IP is unavailable, they are skipped to prevent cross-WAN contamination. Only unassigned records (no `wan_id`) use `auto_ip`.
- **Dashboard**: Monitored records table shows "Last Checked" column with relative time ("5m ago") via `|timeago` filter (full timestamp on hover via `title`). Update-available banner shown if scheduled GitHub check found new commits — includes Install Update button with SSE streaming. Recent Activity section (last 10 `update_log` entries) shows status badges: **No Change** (green), **Changed** (yellow), **Skipped** (gray), **Error** (red). "Show All" links to logs page. Timestamps use `|localtime` filter.
- **Multi-WAN**: Each `wan_interface` has a `detect_method` (unifi/static/auto). Each DNS record can be assigned to a specific WAN via `wan_id`. Unassigned records use auto-detected IP. WAN-assigned records are protected from fallback — they will be skipped rather than updated with the wrong WAN's IP.
- **ISP detection**: UniFi provides ISP for WAN1 via `stat/health`. For WANs missing ISP info, `ip-api.com` is used as fallback.
- **Scheduler**: 4 APScheduler interval jobs: `unifi_sync` (WAN IPs + DNS updates), `cloudflare_sync` (re-sync records from Cloudflare), `npm_sync` (verify NPM connection), `update_check` (GitHub update check, every 24h, runs once on startup). First three intervals are user-configurable (60s–86400s). Update check result cached in `_update_info` dict (available/behind/changes/checked_at).
- **NPM integration**: `npm_api.py:NpmClient` authenticates via JWT token, stored credentials in `npm_settings` table. All proxy host CRUD goes through the NPM REST API.
- **mDNS**: `apply_mdns_hostname()` writes to `/etc/avahi/avahi-daemon.conf` and restarts avahi-daemon. Called on app startup from `create_app()` and when user saves hostname in Settings.
- **Backup/Restore**: `_build_backup()` exports all DB tables + live NPM proxy hosts as JSON. `restore_preview()` compares each section (identical/different/new) with diff details. `restore_apply()` selectively restores chosen sections using upserts for DB data and NPM API for proxy hosts. Backup stored in Flask session between preview and apply.
- **DNS CRUD**: Full create/edit/delete for all DNS record types via Cloudflare API. Routes: `record_add`, `record_edit`, `record_delete`. Records page uses modals for add/edit and confirmation modal for delete.
- **App Updates**: Settings page has Updates section: "Check for Updates" (manual GitHub check via `/settings/check-update`), "Install Update" (SSE stream via `/settings/update-app` — checkout main, pull, pip install, switch back to dev, restart service), "System Update" (SSE stream via `/settings/system-update` — apt update + upgrade). Dashboard also shows update banner when `_update_info['available']` is true, with same Install Update functionality.
- **Jinja filters**: `|localtime` converts UTC timestamps to configured timezone. `|timeago` converts UTC timestamps to relative strings ("5m ago", "2h ago", "3d ago").

## Important Notes

- Default login: `admin` / `admin` — user should change via Settings.
- The venv is at `/root/Updateip/venv/` — always activate before running Python manually.
- Cloudflare API tokens need `Zone:DNS:Edit` + `Zone:Zone:Read` permissions.
- NPM connection configured in-app via Accounts page.
- UniFi controller connection configured in-app via Accounts page. Create a local-only admin on UniFi OS for best security.
- All new Python files must include the copyright header: `# UpdateIP - Copyright (c) 2026 Juha Lempiäinen. All rights reserved.`
