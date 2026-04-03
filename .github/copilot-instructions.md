# UpdateIP — Copilot Instructions

## Project Overview

A password-protected Flask web app that monitors public IP changes and auto-updates Cloudflare DNS A records. Also integrates with a remote Nginx Proxy Manager instance for proxy host management.

## Tech Stack

- **Backend**: Python 3, Flask, Gunicorn
- **Database**: SQLite (WAL mode, foreign keys ON) — single file `updateip.db`
- **Frontend**: Jinja2 templates, Bootstrap 5 (dark theme), Bootstrap Icons
- **Scheduler**: Flask-APScheduler (background IP checks)
- **Auth**: bcrypt password hashing, Flask session-based login
- **APIs**: Cloudflare API v4, Nginx Proxy Manager API
- **Deploy**: systemd service (`updateip.service`) + Nginx reverse proxy (port 80 → 5000)

## Architecture

```
app.py              — Main Flask app: routes, auth, scheduler setup
database.py         — SQLite schema, get_db(), init_db()
cloudflare_api.py   — Cloudflare REST client (zones, DNS records, token verify)
npm_api.py          — Nginx Proxy Manager REST client (proxy hosts CRUD)
updater.py          — IP detection + Cloudflare record update logic
config.py           — App config constants
wsgi.py             — Gunicorn entry point
templates/          — Jinja2 HTML templates (Bootstrap 5 dark theme)
  base.html         — Layout with sidebar nav
  login.html        — Standalone login page (no sidebar)
  dashboard.html    — IP status, monitored records, recent activity
  accounts.html     — Cloudflare account management
  records.html      — DNS record listing with auto-update toggles
  npm.html          — NPM proxy host listing + connection settings modal
  npm_form.html     — Add/edit proxy host form
  logs.html         — IP change & DNS update history
  settings.html     — Password change, update interval
```

## Code Conventions

### Python
- Use raw SQLite via `sqlite3` — no ORM. Always call `get_db()` from `database.py`.
- Always close DB connections in routes (`db.close()`).
- All routes except `/login` require `@login_required` decorator.
- API clients (`cloudflare_api.py`, `npm_api.py`) are stateless modules — no Flask dependencies inside them.
- Use `logging.getLogger(__name__)` for module-level loggers.
- Secrets come from environment variables with fallback defaults.

### Templates
- All authenticated pages extend `base.html`.
- `login.html` is standalone (no sidebar).
- Use Bootstrap 5 dark theme (`data-bs-theme="dark"`), Bootstrap Icons for all icons.
- Flash messages rendered in `base.html` via `get_flashed_messages(with_categories=true)`.
- Sidebar highlights active page via `request.endpoint` checks.

### Database
- Single settings row pattern: `WHERE id = 1` for `settings` and `npm_settings` tables.
- Cloudflare IDs are TEXT (Cloudflare returns string UUIDs).
- Use `INSERT OR REPLACE` for synced Cloudflare data to handle re-sync.
- All timestamps use SQLite `CURRENT_TIMESTAMP` defaults.

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

- **IP update flow**: `updater.py:check_and_update_ip()` → detects IP via `cloudflare_api.py:get_public_ip()` → compares with stored IP → updates Cloudflare records marked `auto_update=1` → logs to `ip_log` and `update_log`.
- **NPM integration**: `npm_api.py:NpmClient` authenticates via JWT token, stored credentials in `npm_settings` table. All proxy host CRUD goes through the NPM REST API.
- **Scheduler**: APScheduler interval job calls `check_and_update_ip(force=False)`. Interval is user-configurable (60s–86400s) and persisted in `settings.update_interval`.

## Important Notes

- Default login: `admin` / `admin` — user should change via Settings.
- The venv is at `/root/Updateip/venv/` — always activate before running Python manually.
- Cloudflare API tokens need `Zone:DNS:Edit` + `Zone:Zone:Read` permissions.
- NPM runs on a separate LXC at `192.168.1.108:81` — connection configured in-app.
