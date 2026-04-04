import os
import json
import logging
import re
import secrets
import subprocess
from datetime import datetime, timezone
from functools import wraps
from zoneinfo import ZoneInfo, available_timezones

import bcrypt
from flask import (Flask, render_template, request, redirect, url_for,
                   flash, session, jsonify)
from flask_apscheduler import APScheduler

from database import get_db, init_db, DB_PATH
from cloudflare_api import (verify_token, list_zones, list_dns_records,
                            get_public_ip, create_dns_record,
                            update_dns_record as cf_update_record,
                            delete_dns_record as cf_delete_record)
from updater import check_and_update_ip
from npm_api import get_npm_client, NpmClient
from unifi_api import get_unifi_client, clear_cached_client, UnifiClient

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SCHEDULER_API_ENABLED'] = False

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(levelname)s %(name)s: %(message)s')
logger = logging.getLogger(__name__)

scheduler = APScheduler()


def apply_mdns_hostname(hostname):
    """Update avahi-daemon config and restart the service."""
    conf = '/etc/avahi/avahi-daemon.conf'
    try:
        with open(conf, 'r') as f:
            lines = f.readlines()
        new_lines = []
        in_server = False
        host_set = False
        for line in lines:
            if line.strip() == '[server]':
                in_server = True
                new_lines.append(line)
                continue
            if line.strip().startswith('[') and in_server:
                if not host_set:
                    new_lines.append(f'host-name={hostname}\n')
                    host_set = True
                in_server = False
            if in_server and line.lstrip().startswith(('host-name=', '#host-name=')):
                new_lines.append(f'host-name={hostname}\n')
                host_set = True
                continue
            new_lines.append(line)
        if not host_set:
            # Fallback: append to end
            new_lines.append(f'\n[server]\nhost-name={hostname}\n')
        with open(conf, 'w') as f:
            f.writelines(new_lines)
        subprocess.run(['systemctl', 'restart', 'avahi-daemon'],
                       capture_output=True, timeout=10)
        logger.info('mDNS hostname set to %s.local', hostname)
    except Exception as e:
        logger.error('Failed to apply mDNS hostname: %s', e)

# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def check_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed.encode())


# ---------------------------------------------------------------------------
# Bootstrap: create default admin user if none exists
# ---------------------------------------------------------------------------

def ensure_admin():
    db = get_db()
    user = db.execute('SELECT id FROM users LIMIT 1').fetchone()
    if not user:
        db.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)',
                   ('admin', hash_password('admin')))
        db.commit()
    db.close()

# ---------------------------------------------------------------------------
# Scheduler jobs
# ---------------------------------------------------------------------------

def scheduled_unifi_sync():
    """Background job: refresh WAN IPs from UniFi, then check & update DNS."""
    with app.app_context():
        client = get_unifi_client()
        if client and client.is_connected():
            wan_details = client.get_wan_details()
            if wan_details:
                db = get_db()
                for unifi_name, info in wan_details.items():
                    ip = info.get('ip', '')
                    isp = info.get('isp_name', '') or info.get('isp_org', '')
                    existing = db.execute(
                        'SELECT id FROM wan_interfaces WHERE unifi_wan_name = ?', (unifi_name,)
                    ).fetchone()
                    if existing:
                        db.execute(
                            'UPDATE wan_interfaces SET current_ip = ?, isp_name = ?, last_checked = CURRENT_TIMESTAMP WHERE id = ?',
                            (ip, isp, existing['id']))
                db.commit()
                db.close()
                logger.info(f'UniFi sync: updated {len(wan_details)} WAN(s)')

        # After refreshing WAN IPs, check for changes and update DNS
        logger.info('Scheduled IP check running')
        result = check_and_update_ip(force=False)
        logger.info(f'Scheduled update result: {result.get("message", "")}')


def scheduled_cloudflare_sync():
    """Background job: re-sync DNS records from all Cloudflare accounts."""
    with app.app_context():
        db = get_db()
        accounts = db.execute('SELECT id FROM cf_accounts').fetchall()
        db.close()
        for acc in accounts:
            _sync_account(acc['id'])
        logger.info(f'Cloudflare sync: synced {len(accounts)} account(s)')


def scheduled_npm_sync():
    """Background job: refresh NPM proxy host data."""
    with app.app_context():
        client = get_npm_client()
        if not client or not client.test_connection():
            return
        # Just verify connection is alive; NPM data is fetched live on page load
        logger.info('NPM sync: connection verified')


def reschedule_job():
    db = get_db()
    row = db.execute('SELECT unifi_interval, cloudflare_interval, npm_interval FROM settings WHERE id = 1').fetchone()
    db.close()

    jobs = [
        ('unifi_sync', scheduled_unifi_sync, row['unifi_interval'] if row else 300),
        ('cloudflare_sync', scheduled_cloudflare_sync, row['cloudflare_interval'] if row else 3600),
        ('npm_sync', scheduled_npm_sync, row['npm_interval'] if row else 3600),
    ]

    for job_id, func, interval in jobs:
        if scheduler.get_job(job_id):
            scheduler.remove_job(job_id)
        scheduler.add_job(
            id=job_id,
            func=func,
            trigger='interval',
            seconds=interval,
            replace_existing=True
        )
        logger.info(f'Scheduler: {job_id} set to every {interval}s')

# ---------------------------------------------------------------------------
# Routes: Auth
# ---------------------------------------------------------------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        db.close()
        if user and check_password(password, user['password_hash']):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('dashboard'))
        flash('Invalid username or password', 'danger')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ---------------------------------------------------------------------------
# Routes: Dashboard
# ---------------------------------------------------------------------------

@app.route('/')
@login_required
def dashboard():
    db = get_db()
    settings = db.execute('SELECT current_ip, update_interval FROM settings WHERE id = 1').fetchone()
    wans = db.execute('SELECT * FROM wan_interfaces ORDER BY name').fetchall()
    records = db.execute('''
        SELECT r.*, z.name as zone_name, a.name as account_name,
               w.name as wan_name
        FROM cf_records r
        JOIN cf_zones z ON r.zone_id = z.id
        JOIN cf_accounts a ON r.account_id = a.id
        LEFT JOIN wan_interfaces w ON r.wan_id = w.id
        WHERE r.auto_update = 1
        ORDER BY a.name, z.name, r.name
    ''').fetchall()
    recent_logs = db.execute(
        'SELECT * FROM update_log ORDER BY updated_at DESC LIMIT 20'
    ).fetchall()
    db.close()
    return render_template('dashboard.html',
                           settings=settings,
                           wans=wans,
                           records=records,
                           recent_logs=recent_logs)

# ---------------------------------------------------------------------------
# Routes: Accounts
# ---------------------------------------------------------------------------

@app.route('/accounts')
@login_required
def accounts():
    db = get_db()
    accs = db.execute('SELECT * FROM cf_accounts ORDER BY name').fetchall()
    db.close()
    return render_template('accounts.html', accounts=accs)


@app.route('/accounts/add', methods=['POST'])
@login_required
def account_add():
    name = request.form.get('name', '').strip()
    token = request.form.get('api_token', '').strip()
    if not name or not token:
        flash('Name and API token are required', 'danger')
        return redirect(url_for('accounts'))

    if not verify_token(token):
        flash('Invalid Cloudflare API token', 'danger')
        return redirect(url_for('accounts'))

    db = get_db()
    db.execute('INSERT INTO cf_accounts (name, api_token) VALUES (?, ?)', (name, token))
    db.commit()
    account_id = db.execute('SELECT last_insert_rowid()').fetchone()[0]
    db.close()

    # Auto-fetch zones
    _sync_account(account_id)
    flash(f'Account "{name}" added and zones synced', 'success')
    return redirect(url_for('accounts'))


@app.route('/accounts/<int:account_id>/delete', methods=['POST'])
@login_required
def account_delete(account_id):
    db = get_db()
    db.execute('DELETE FROM cf_records WHERE account_id = ?', (account_id,))
    db.execute('DELETE FROM cf_zones WHERE account_id = ?', (account_id,))
    db.execute('DELETE FROM cf_accounts WHERE id = ?', (account_id,))
    db.commit()
    db.close()
    flash('Account deleted', 'success')
    return redirect(url_for('accounts'))


@app.route('/accounts/<int:account_id>/sync', methods=['POST'])
@login_required
def account_sync(account_id):
    _sync_account(account_id)
    flash('Zones and records synced', 'success')
    return redirect(url_for('records'))


def _sync_account(account_id):
    db = get_db()
    acc = db.execute('SELECT * FROM cf_accounts WHERE id = ?', (account_id,)).fetchone()
    if not acc:
        db.close()
        return

    zones = list_zones(acc['api_token'])
    for z in zones:
        db.execute('''INSERT INTO cf_zones (id, account_id, name) VALUES (?, ?, ?)
                      ON CONFLICT(id) DO UPDATE SET account_id=excluded.account_id, name=excluded.name''',
                   (z['id'], account_id, z['name']))

        # Fetch ALL record types
        dns_records = list_dns_records(acc['api_token'], z['id'], record_type=None)
        for rec in dns_records:
            db.execute('''INSERT INTO cf_records
                          (id, zone_id, account_id, name, type, content, proxied)
                          VALUES (?, ?, ?, ?, ?, ?, ?)
                          ON CONFLICT(id) DO UPDATE SET
                            zone_id=excluded.zone_id, account_id=excluded.account_id,
                            name=excluded.name, type=excluded.type,
                            content=excluded.content, proxied=excluded.proxied''',
                       (rec['id'], z['id'], account_id, rec['name'], rec['type'],
                        rec['content'], 1 if rec.get('proxied') else 0))
    db.commit()
    db.close()

# ---------------------------------------------------------------------------
# Routes: Records
# ---------------------------------------------------------------------------

@app.route('/records')
@login_required
def records():
    db = get_db()
    accs = db.execute('SELECT * FROM cf_accounts ORDER BY name').fetchall()
    wans = db.execute('SELECT * FROM wan_interfaces ORDER BY name').fetchall()
    zone_list = db.execute('''
        SELECT z.id, z.name, z.account_id, a.name as account_name
        FROM cf_zones z JOIN cf_accounts a ON z.account_id = a.id
        ORDER BY z.name
    ''').fetchall()
    recs = db.execute('''
        SELECT r.*, z.name as zone_name, a.name as account_name,
               w.name as wan_name
        FROM cf_records r
        JOIN cf_zones z ON r.zone_id = z.id
        JOIN cf_accounts a ON r.account_id = a.id
        LEFT JOIN wan_interfaces w ON r.wan_id = w.id
        ORDER BY z.name, r.type, r.name
    ''').fetchall()
    # Group records by zone_name
    from collections import OrderedDict
    zones = OrderedDict()
    for r in recs:
        zn = r['zone_name']
        if zn not in zones:
            zones[zn] = []
        zones[zn].append(r)
    db.close()
    return render_template('records.html', zones=zones, accounts=accs, wans=wans, zone_list=zone_list)


@app.route('/records/toggle', methods=['POST'])
@login_required
def record_toggle():
    record_id = request.form.get('record_id', '')
    auto_update = 1 if request.form.get('auto_update') == '1' else 0
    wan_id = request.form.get('wan_id', '')
    wan_id_val = int(wan_id) if wan_id and wan_id != '0' else None
    db = get_db()
    db.execute('UPDATE cf_records SET auto_update = ?, wan_id = ? WHERE id = ?',
               (auto_update, wan_id_val, record_id))
    db.commit()
    db.close()
    return redirect(url_for('records'))


@app.route('/records/add', methods=['POST'])
@login_required
def record_add():
    zone_id = request.form.get('zone_id', '').strip()
    record_type = request.form.get('type', 'A').strip().upper()
    name = request.form.get('name', '').strip()
    content = request.form.get('content', '').strip()
    proxied = request.form.get('proxied') == '1'
    priority = request.form.get('priority', '').strip()
    priority_val = int(priority) if priority and record_type == 'MX' else None

    if not zone_id or not name or not content:
        flash('Zone, name, and value are required', 'danger')
        return redirect(url_for('records'))

    db = get_db()
    zone = db.execute('SELECT z.*, a.api_token FROM cf_zones z JOIN cf_accounts a ON z.account_id = a.id WHERE z.id = ?',
                       (zone_id,)).fetchone()
    if not zone:
        db.close()
        flash('Zone not found', 'danger')
        return redirect(url_for('records'))

    success, result = create_dns_record(
        zone['api_token'], zone_id, record_type, name, content,
        proxied=proxied, priority=priority_val
    )
    if success:
        rec = result  # Cloudflare returns the created record
        db.execute('''INSERT INTO cf_records (id, zone_id, account_id, name, type, content, proxied)
                      VALUES (?, ?, ?, ?, ?, ?, ?)
                      ON CONFLICT(id) DO UPDATE SET
                        name=excluded.name, type=excluded.type,
                        content=excluded.content, proxied=excluded.proxied''',
                   (rec['id'], zone_id, zone['account_id'], rec['name'], rec['type'],
                    rec['content'], 1 if rec.get('proxied') else 0))
        db.commit()
        flash(f'Record {rec["name"]} created', 'success')
    else:
        flash(f'Failed to create record: {result}', 'danger')
    db.close()
    return redirect(url_for('records'))


@app.route('/records/edit', methods=['POST'])
@login_required
def record_edit():
    record_id = request.form.get('record_id', '').strip()
    record_type = request.form.get('type', 'A').strip().upper()
    name = request.form.get('name', '').strip()
    content = request.form.get('content', '').strip()
    proxied = request.form.get('proxied') == '1'
    priority = request.form.get('priority', '').strip()
    priority_val = int(priority) if priority and record_type == 'MX' else None

    if not record_id or not name or not content:
        flash('Record ID, name, and value are required', 'danger')
        return redirect(url_for('records'))

    db = get_db()
    rec = db.execute('''
        SELECT r.*, a.api_token FROM cf_records r
        JOIN cf_accounts a ON r.account_id = a.id
        WHERE r.id = ?
    ''', (record_id,)).fetchone()
    if not rec:
        db.close()
        flash('Record not found', 'danger')
        return redirect(url_for('records'))

    success, msg = cf_update_record(
        rec['api_token'], rec['zone_id'], record_id, name, content,
        proxied=proxied, record_type=record_type, priority=priority_val
    )
    if success:
        db.execute('UPDATE cf_records SET name = ?, type = ?, content = ?, proxied = ? WHERE id = ?',
                   (name, record_type, content, 1 if proxied else 0, record_id))
        db.commit()
        flash(f'Record {name} updated', 'success')
    else:
        flash(f'Failed to update record: {msg}', 'danger')
    db.close()
    return redirect(url_for('records'))


@app.route('/records/delete', methods=['POST'])
@login_required
def record_delete():
    record_id = request.form.get('record_id', '').strip()
    confirm = request.form.get('confirm', '')
    if confirm != 'yes':
        flash('Delete not confirmed', 'warning')
        return redirect(url_for('records'))

    db = get_db()
    rec = db.execute('''
        SELECT r.*, a.api_token FROM cf_records r
        JOIN cf_accounts a ON r.account_id = a.id
        WHERE r.id = ?
    ''', (record_id,)).fetchone()
    if not rec:
        db.close()
        flash('Record not found', 'danger')
        return redirect(url_for('records'))

    success, msg = cf_delete_record(rec['api_token'], rec['zone_id'], record_id)
    if success:
        db.execute('DELETE FROM cf_records WHERE id = ?', (record_id,))
        db.commit()
        flash(f'Record {rec["name"]} deleted', 'success')
    else:
        flash(f'Failed to delete record: {msg}', 'danger')
    db.close()
    return redirect(url_for('records'))


# ---------------------------------------------------------------------------
# Routes: Manual / Force update
# ---------------------------------------------------------------------------

@app.route('/update', methods=['POST'])
@login_required
def manual_update():
    result = check_and_update_ip(force=False)
    if result['success']:
        flash(result['message'], 'success')
    else:
        flash(result['message'], 'danger')
    return redirect(url_for('dashboard'))


@app.route('/force-update', methods=['POST'])
@login_required
def force_update():
    result = check_and_update_ip(force=True)
    if result['success']:
        flash(result['message'], 'success')
    else:
        flash(result['message'], 'danger')
    return redirect(url_for('dashboard'))

# ---------------------------------------------------------------------------
# Routes: Logs
# ---------------------------------------------------------------------------

@app.route('/logs')
@login_required
def logs():
    db = get_db()
    ip_logs = db.execute(
        'SELECT l.*, w.name AS wan_name FROM ip_log l '
        'LEFT JOIN wan_interfaces w ON l.wan_id = w.id '
        'ORDER BY l.changed_at DESC LIMIT 100'
    ).fetchall()
    update_logs = db.execute('SELECT * FROM update_log ORDER BY updated_at DESC LIMIT 200').fetchall()
    db.close()
    return render_template('logs.html', ip_logs=ip_logs, update_logs=update_logs)

# ---------------------------------------------------------------------------
# Routes: Settings
# ---------------------------------------------------------------------------

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    db = get_db()
    if request.method == 'POST':
        action = request.form.get('action', '')

        if action == 'password':
            current = request.form.get('current_password', '')
            new_pw = request.form.get('new_password', '')
            confirm = request.form.get('confirm_password', '')
            user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
            if not check_password(current, user['password_hash']):
                flash('Current password is incorrect', 'danger')
            elif len(new_pw) < 4:
                flash('Password must be at least 4 characters', 'danger')
            elif new_pw != confirm:
                flash('Passwords do not match', 'danger')
            else:
                db.execute('UPDATE users SET password_hash = ? WHERE id = ?',
                           (hash_password(new_pw), session['user_id']))
                db.commit()
                flash('Password updated', 'success')

        elif action == 'sync_intervals':
            def _clamp(val, lo=60, hi=86400, default=300):
                try:
                    v = int(val)
                    return max(lo, min(hi, v))
                except (ValueError, TypeError):
                    return default
            unifi_int = _clamp(request.form.get('unifi_interval'), default=300)
            cf_int = _clamp(request.form.get('cloudflare_interval'), default=3600)
            npm_int = _clamp(request.form.get('npm_interval'), default=3600)
            db.execute('UPDATE settings SET unifi_interval = ?, cloudflare_interval = ?, npm_interval = ? WHERE id = 1',
                       (unifi_int, cf_int, npm_int))
            db.commit()
            flash('Sync intervals updated', 'success')
            reschedule_job()

        elif action == 'timezone':
            tz = request.form.get('timezone', 'UTC').strip()
            if tz not in available_timezones() and tz != 'UTC':
                flash('Invalid timezone selected', 'danger')
            else:
                db.execute('UPDATE settings SET timezone = ? WHERE id = 1', (tz,))
                db.commit()
                flash(f'Timezone set to {tz}', 'success')

        elif action == 'mdns':
            hostname = request.form.get('mdns_hostname', 'updateip').strip().lower()
            # Sanitise: allow only a-z, 0-9, hyphens; 1-63 chars
            if not re.match(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$', hostname):
                flash('Invalid hostname. Use lowercase letters, numbers, and hyphens (1-63 chars).', 'danger')
            else:
                db.execute('UPDATE settings SET mdns_hostname = ? WHERE id = 1', (hostname,))
                db.commit()
                apply_mdns_hostname(hostname)
                flash(f'mDNS hostname set to {hostname}.local', 'success')

        db.close()
        return redirect(url_for('settings'))

    s = db.execute('SELECT * FROM settings WHERE id = 1').fetchone()
    wans = db.execute('SELECT * FROM wan_interfaces ORDER BY name').fetchall()
    db.close()
    timezones = sorted(available_timezones())
    return render_template('settings.html', settings=s, wans=wans, timezones=timezones)


# ---------------------------------------------------------------------------
# Routes: Backup / Restore
# ---------------------------------------------------------------------------

def _build_backup():
    """Collect all system data into a dict for backup."""
    db = get_db()
    s = db.execute('SELECT * FROM settings WHERE id = 1').fetchone()
    backup = {
        'version': 1,
        'created_at': datetime.now(timezone.utc).isoformat(),
        'settings': {
            'timezone': s['timezone'] if s else 'UTC',
            'mdns_hostname': s['mdns_hostname'] if s else 'updateip',
            'unifi_interval': s['unifi_interval'] if s else 300,
            'cloudflare_interval': s['cloudflare_interval'] if s else 3600,
            'npm_interval': s['npm_interval'] if s else 3600,
        },
        'cf_accounts': [dict(r) for r in db.execute(
            'SELECT id, name, api_token, created_at FROM cf_accounts ORDER BY name').fetchall()],
        'cf_zones': [dict(r) for r in db.execute(
            'SELECT id, account_id, name FROM cf_zones ORDER BY name').fetchall()],
        'cf_records': [dict(r) for r in db.execute(
            'SELECT id, zone_id, account_id, name, type, content, proxied, auto_update, wan_id FROM cf_records ORDER BY name').fetchall()],
        'wan_interfaces': [dict(r) for r in db.execute(
            'SELECT id, name, detect_method, static_ip, current_ip, unifi_wan_name, isp_name FROM wan_interfaces ORDER BY name').fetchall()],
        'unifi_settings': {},
        'npm_settings': {},
        'npm_proxy_hosts': [],
    }
    u = db.execute('SELECT url, username, password, site_name, verify_ssl FROM unifi_settings WHERE id = 1').fetchone()
    if u:
        backup['unifi_settings'] = dict(u)
    n = db.execute('SELECT url, email, password FROM npm_settings WHERE id = 1').fetchone()
    if n:
        backup['npm_settings'] = dict(n)
    db.close()
    # Fetch live NPM proxy hosts
    client = get_npm_client()
    if client and client.test_connection():
        hosts = client.list_proxy_hosts()
        for h in hosts:
            backup['npm_proxy_hosts'].append({
                'id': h.get('id'),
                'domain_names': h.get('domain_names', []),
                'forward_scheme': h.get('forward_scheme', 'http'),
                'forward_host': h.get('forward_host', ''),
                'forward_port': h.get('forward_port', 80),
                'certificate_id': h.get('certificate_id', 0),
                'ssl_forced': h.get('ssl_forced', 0),
                'block_exploits': h.get('block_exploits', 0),
                'caching_enabled': h.get('caching_enabled', 0),
                'allow_websocket_upgrade': h.get('allow_websocket_upgrade', 0),
                'http2_support': h.get('http2_support', 0),
                'hsts_enabled': h.get('hsts_enabled', 0),
                'hsts_subdomains': h.get('hsts_subdomains', 0),
                'enabled': h.get('enabled', 1),
                'access_list_id': h.get('access_list_id', 0),
                'advanced_config': h.get('advanced_config', ''),
                'locations': h.get('locations', []),
            })
    return backup


@app.route('/backup', methods=['POST'])
@login_required
def backup_download():
    backup = _build_backup()
    data = json.dumps(backup, indent=2, default=str)
    hostname = backup['settings'].get('mdns_hostname', 'updateip')
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'{hostname}_backup_{ts}.json'
    from flask import Response
    return Response(
        data,
        mimetype='application/json',
        headers={'Content-Disposition': f'attachment; filename={filename}'}
    )


def _compare_section(label, backup_items, current_items, key_fn, compare_fields):
    """Compare backup items vs current. Returns list of dicts with status info."""
    current_map = {}
    for item in current_items:
        k = key_fn(item)
        current_map[k] = item

    results = []
    for bitem in backup_items:
        k = key_fn(bitem)
        entry = {'key': k, 'data': bitem, 'status': 'new', 'differences': []}
        if k in current_map:
            citem = current_map[k]
            diffs = []
            for field in compare_fields:
                bval = bitem.get(field, '')
                cval = citem.get(field, '') if isinstance(citem, dict) else (citem[field] if field in citem.keys() else '')
                if str(bval) != str(cval):
                    diffs.append({'field': field, 'backup': str(bval), 'current': str(cval)})
            if diffs:
                entry['status'] = 'different'
                entry['differences'] = diffs
            else:
                entry['status'] = 'identical'
        results.append(entry)
    return results


@app.route('/restore/preview', methods=['POST'])
@login_required
def restore_preview():
    f = request.files.get('backup_file')
    if not f or not f.filename:
        flash('No file uploaded', 'danger')
        return redirect(url_for('settings'))
    try:
        raw = f.read()
        backup = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        flash('Invalid backup file', 'danger')
        return redirect(url_for('settings'))

    if not isinstance(backup, dict) or 'version' not in backup:
        flash('Invalid backup format', 'danger')
        return redirect(url_for('settings'))

    db = get_db()
    preview = {}

    # Settings
    if backup.get('settings'):
        bs = backup['settings']
        cs = db.execute('SELECT * FROM settings WHERE id = 1').fetchone()
        s_diffs = []
        for field in ['timezone', 'mdns_hostname', 'unifi_interval', 'cloudflare_interval', 'npm_interval']:
            bval = str(bs.get(field, ''))
            cval = str(cs[field]) if cs and field in cs.keys() else ''
            if bval != cval:
                s_diffs.append({'field': field, 'backup': bval, 'current': cval})
        preview['settings'] = {
            'data': bs,
            'status': 'different' if s_diffs else 'identical',
            'differences': s_diffs,
        }

    # Cloudflare accounts
    if backup.get('cf_accounts'):
        cur = [dict(r) for r in db.execute('SELECT id, name, api_token, created_at FROM cf_accounts').fetchall()]
        preview['cf_accounts'] = _compare_section(
            'Cloudflare Accounts', backup['cf_accounts'], cur,
            key_fn=lambda x: str(x.get('name', '')),
            compare_fields=['name', 'api_token']
        )

    # Cloudflare zones
    if backup.get('cf_zones'):
        cur = [dict(r) for r in db.execute('SELECT id, account_id, name FROM cf_zones').fetchall()]
        preview['cf_zones'] = _compare_section(
            'Cloudflare Zones', backup['cf_zones'], cur,
            key_fn=lambda x: str(x.get('id', '')),
            compare_fields=['name', 'account_id']
        )

    # DNS records
    if backup.get('cf_records'):
        cur = [dict(r) for r in db.execute(
            'SELECT id, zone_id, account_id, name, type, content, proxied, auto_update, wan_id FROM cf_records').fetchall()]
        preview['cf_records'] = _compare_section(
            'DNS Records', backup['cf_records'], cur,
            key_fn=lambda x: str(x.get('id', '')),
            compare_fields=['name', 'type', 'content', 'proxied', 'auto_update']
        )

    # WAN interfaces
    if backup.get('wan_interfaces'):
        cur = [dict(r) for r in db.execute(
            'SELECT id, name, detect_method, static_ip, current_ip, unifi_wan_name, isp_name FROM wan_interfaces').fetchall()]
        preview['wan_interfaces'] = _compare_section(
            'WAN Interfaces', backup['wan_interfaces'], cur,
            key_fn=lambda x: str(x.get('name', '')),
            compare_fields=['name', 'detect_method', 'static_ip', 'unifi_wan_name']
        )

    # UniFi settings
    if backup.get('unifi_settings'):
        bu = backup['unifi_settings']
        cu = db.execute('SELECT url, username, password, site_name, verify_ssl FROM unifi_settings WHERE id = 1').fetchone()
        u_diffs = []
        for field in ['url', 'username', 'password', 'site_name', 'verify_ssl']:
            bval = str(bu.get(field, ''))
            cval = str(cu[field]) if cu and field in cu.keys() else ''
            if bval != cval:
                u_diffs.append({'field': field, 'backup': bval, 'current': cval})
        preview['unifi_settings'] = {
            'data': bu,
            'status': 'different' if u_diffs else 'identical',
            'differences': u_diffs,
        }

    # NPM settings
    if backup.get('npm_settings'):
        bn = backup['npm_settings']
        cn = db.execute('SELECT url, email, password FROM npm_settings WHERE id = 1').fetchone()
        n_diffs = []
        for field in ['url', 'email', 'password']:
            bval = str(bn.get(field, ''))
            cval = str(cn[field]) if cn and field in cn.keys() else ''
            if bval != cval:
                n_diffs.append({'field': field, 'backup': bval, 'current': cval})
        preview['npm_settings'] = {
            'data': bn,
            'status': 'different' if n_diffs else 'identical',
            'differences': n_diffs,
        }

    # NPM proxy hosts
    if backup.get('npm_proxy_hosts'):
        client = get_npm_client()
        current_hosts = []
        if client and client.test_connection():
            current_hosts = client.list_proxy_hosts()
        # Build map by domain list (sorted, joined)
        cur_map = {}
        for h in current_hosts:
            k = ','.join(sorted(h.get('domain_names', [])))
            cur_map[k] = h
        npm_results = []
        for bh in backup['npm_proxy_hosts']:
            k = ','.join(sorted(bh.get('domain_names', [])))
            entry = {'key': k, 'data': bh, 'status': 'new', 'differences': []}
            if k in cur_map:
                ch = cur_map[k]
                diffs = []
                for field in ['forward_scheme', 'forward_host', 'forward_port', 'ssl_forced',
                              'block_exploits', 'caching_enabled', 'allow_websocket_upgrade']:
                    bval = str(bh.get(field, ''))
                    cval = str(ch.get(field, ''))
                    if bval != cval:
                        diffs.append({'field': field, 'backup': bval, 'current': cval})
                entry['status'] = 'different' if diffs else 'identical'
                entry['differences'] = diffs
            npm_results.append(entry)
        preview['npm_proxy_hosts'] = npm_results

    db.close()

    # Store backup data in session for the apply step
    session['pending_restore'] = backup

    return render_template('restore.html', preview=preview, backup=backup)


@app.route('/restore/apply', methods=['POST'])
@login_required
def restore_apply():
    backup = session.pop('pending_restore', None)
    if not backup:
        flash('No pending restore data. Please upload the backup file again.', 'danger')
        return redirect(url_for('settings'))

    selected = request.form.getlist('sections')
    if not selected:
        flash('No sections selected for restore', 'warning')
        return redirect(url_for('settings'))

    db = get_db()
    restored = []

    if 'settings' in selected and backup.get('settings'):
        bs = backup['settings']
        db.execute('UPDATE settings SET timezone=?, mdns_hostname=?, unifi_interval=?, cloudflare_interval=?, npm_interval=? WHERE id=1',
                   (bs.get('timezone', 'UTC'), bs.get('mdns_hostname', 'updateip'),
                    bs.get('unifi_interval', 300), bs.get('cloudflare_interval', 3600),
                    bs.get('npm_interval', 3600)))
        if bs.get('mdns_hostname'):
            apply_mdns_hostname(bs['mdns_hostname'])
        restored.append('Settings')

    if 'cf_accounts' in selected and backup.get('cf_accounts'):
        for acc in backup['cf_accounts']:
            existing = db.execute('SELECT id FROM cf_accounts WHERE name = ?', (acc['name'],)).fetchone()
            if not existing:
                db.execute('INSERT INTO cf_accounts (name, api_token) VALUES (?, ?)',
                           (acc['name'], acc['api_token']))
            else:
                db.execute('UPDATE cf_accounts SET api_token = ? WHERE name = ?',
                           (acc['api_token'], acc['name']))
        restored.append('Cloudflare Accounts')

    if 'cf_zones' in selected and backup.get('cf_zones'):
        for z in backup['cf_zones']:
            db.execute('''INSERT INTO cf_zones (id, account_id, name) VALUES (?, ?, ?)
                          ON CONFLICT(id) DO UPDATE SET account_id=excluded.account_id, name=excluded.name''',
                       (z['id'], z['account_id'], z['name']))
        restored.append('Cloudflare Zones')

    if 'cf_records' in selected and backup.get('cf_records'):
        for rec in backup['cf_records']:
            db.execute('''INSERT INTO cf_records (id, zone_id, account_id, name, type, content, proxied, auto_update, wan_id)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                          ON CONFLICT(id) DO UPDATE SET
                            zone_id=excluded.zone_id, account_id=excluded.account_id,
                            name=excluded.name, type=excluded.type,
                            content=excluded.content, proxied=excluded.proxied,
                            auto_update=excluded.auto_update, wan_id=excluded.wan_id''',
                       (rec['id'], rec['zone_id'], rec['account_id'], rec['name'],
                        rec['type'], rec['content'], rec.get('proxied', 0),
                        rec.get('auto_update', 0), rec.get('wan_id')))
        restored.append('DNS Records')

    if 'wan_interfaces' in selected and backup.get('wan_interfaces'):
        for w in backup['wan_interfaces']:
            existing = db.execute('SELECT id FROM wan_interfaces WHERE name = ?', (w['name'],)).fetchone()
            if not existing:
                db.execute('''INSERT INTO wan_interfaces (name, detect_method, static_ip, current_ip, unifi_wan_name, isp_name)
                              VALUES (?, ?, ?, ?, ?, ?)''',
                           (w['name'], w.get('detect_method', 'auto'), w.get('static_ip', ''),
                            w.get('current_ip', ''), w.get('unifi_wan_name', ''), w.get('isp_name', '')))
            else:
                db.execute('''UPDATE wan_interfaces SET detect_method=?, static_ip=?, unifi_wan_name=?, isp_name=?
                              WHERE name=?''',
                           (w.get('detect_method', 'auto'), w.get('static_ip', ''),
                            w.get('unifi_wan_name', ''), w.get('isp_name', ''), w['name']))
        restored.append('WAN Interfaces')

    if 'unifi_settings' in selected and backup.get('unifi_settings'):
        bu = backup['unifi_settings']
        db.execute('UPDATE unifi_settings SET url=?, username=?, password=?, site_name=?, verify_ssl=? WHERE id=1',
                   (bu.get('url', ''), bu.get('username', ''), bu.get('password', ''),
                    bu.get('site_name', 'default'), bu.get('verify_ssl', 0)))
        restored.append('UniFi Settings')

    if 'npm_settings' in selected and backup.get('npm_settings'):
        bn = backup['npm_settings']
        db.execute('UPDATE npm_settings SET url=?, email=?, password=? WHERE id=1',
                   (bn.get('url', ''), bn.get('email', ''), bn.get('password', '')))
        restored.append('NPM Settings')

    db.commit()
    db.close()

    # NPM proxy hosts - restore via API
    if 'npm_proxy_hosts' in selected and backup.get('npm_proxy_hosts'):
        client = get_npm_client()
        if client and client.test_connection():
            existing = client.list_proxy_hosts()
            existing_map = {}
            for h in existing:
                k = ','.join(sorted(h.get('domain_names', [])))
                existing_map[k] = h
            npm_ok = 0
            npm_err = 0
            for bh in backup['npm_proxy_hosts']:
                k = ','.join(sorted(bh.get('domain_names', [])))
                payload = {
                    'domain_names': bh.get('domain_names', []),
                    'forward_scheme': bh.get('forward_scheme', 'http'),
                    'forward_host': bh.get('forward_host', ''),
                    'forward_port': bh.get('forward_port', 80),
                    'certificate_id': bh.get('certificate_id', 0),
                    'ssl_forced': bh.get('ssl_forced', 0),
                    'block_exploits': bh.get('block_exploits', 0),
                    'caching_enabled': bh.get('caching_enabled', 0),
                    'allow_websocket_upgrade': bh.get('allow_websocket_upgrade', 0),
                    'http2_support': bh.get('http2_support', 0),
                    'hsts_enabled': bh.get('hsts_enabled', 0),
                    'hsts_subdomains': bh.get('hsts_subdomains', 0),
                    'access_list_id': bh.get('access_list_id', 0),
                    'advanced_config': bh.get('advanced_config', ''),
                    'locations': bh.get('locations', []),
                    'meta': {'letsencrypt_agree': False, 'dns_challenge': False},
                }
                if k in existing_map:
                    ok, _ = client.update_proxy_host(existing_map[k]['id'], payload)
                else:
                    ok, _ = client.create_proxy_host(payload)
                if ok:
                    npm_ok += 1
                else:
                    npm_err += 1
            restored.append(f'NPM Proxy Hosts ({npm_ok} ok, {npm_err} errors)')
        else:
            restored.append('NPM Proxy Hosts (skipped — not connected)')

    if restored:
        reschedule_job()
        flash(f'Restored: {", ".join(restored)}', 'success')
    else:
        flash('Nothing was restored', 'info')
    return redirect(url_for('settings'))


# ---------------------------------------------------------------------------
# Routes: Nginx Proxy Manager
# ---------------------------------------------------------------------------

@app.route('/npm')
@login_required
def npm_hosts():
    client = get_npm_client()
    hosts = []
    connected = False
    if client:
        connected = client.test_connection()
        if connected:
            hosts = client.list_proxy_hosts()
    db = get_db()
    npm = db.execute('SELECT * FROM npm_settings WHERE id = 1').fetchone()
    db.close()
    return render_template('npm.html', hosts=hosts, npm=npm, connected=connected)


@app.route('/npm/settings', methods=['POST'])
@login_required
def npm_settings_save():
    url = request.form.get('url', '').strip().rstrip('/')
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '')
    if not url or not email or not password:
        flash('All NPM connection fields are required', 'danger')
        return redirect(url_for('npm_hosts'))
    # Test connection
    client = NpmClient(url, email, password)
    if not client.test_connection():
        flash('Could not connect to NPM. Check URL and credentials.', 'danger')
        return redirect(url_for('npm_hosts'))
    db = get_db()
    db.execute('UPDATE npm_settings SET url = ?, email = ?, password = ? WHERE id = 1',
               (url, email, password))
    db.commit()
    db.close()
    flash('NPM connection saved and verified', 'success')
    return redirect(url_for('npm_hosts'))


@app.route('/npm/add', methods=['GET', 'POST'])
@login_required
def npm_host_add():
    client = get_npm_client()
    if not client:
        flash('Configure NPM connection first', 'danger')
        return redirect(url_for('npm_hosts'))
    if request.method == 'POST':
        data = _build_proxy_host_data(request.form)
        success, result = client.create_proxy_host(data)
        if success:
            flash('Proxy host created', 'success')
            return redirect(url_for('npm_hosts'))
        else:
            flash(f'Failed: {result}', 'danger')
    certs = client.list_certificates()
    access_lists = client.list_access_lists()
    return render_template('npm_form.html', host=None, certs=certs,
                           access_lists=access_lists, action='Add')


@app.route('/npm/<int:host_id>/edit', methods=['GET', 'POST'])
@login_required
def npm_host_edit(host_id):
    client = get_npm_client()
    if not client:
        flash('Configure NPM connection first', 'danger')
        return redirect(url_for('npm_hosts'))
    if request.method == 'POST':
        data = _build_proxy_host_data(request.form)
        success, result = client.update_proxy_host(host_id, data)
        if success:
            flash('Proxy host updated', 'success')
            return redirect(url_for('npm_hosts'))
        else:
            flash(f'Failed: {result}', 'danger')
    host = client.get_proxy_host(host_id)
    if not host:
        flash('Proxy host not found', 'danger')
        return redirect(url_for('npm_hosts'))
    certs = client.list_certificates()
    access_lists = client.list_access_lists()
    return render_template('npm_form.html', host=host, certs=certs,
                           access_lists=access_lists, action='Edit')


@app.route('/npm/<int:host_id>/delete', methods=['POST'])
@login_required
def npm_host_delete(host_id):
    client = get_npm_client()
    if not client:
        flash('Configure NPM connection first', 'danger')
        return redirect(url_for('npm_hosts'))
    success, msg = client.delete_proxy_host(host_id)
    if success:
        flash('Proxy host deleted', 'success')
    else:
        flash(f'Delete failed: {msg}', 'danger')
    return redirect(url_for('npm_hosts'))


def _build_proxy_host_data(form):
    """Build NPM proxy host API payload from form data."""
    domain_names = [d.strip() for d in form.get('domain_names', '').split(',') if d.strip()]
    forward_port = int(form.get('forward_port', 80))
    data = {
        'domain_names': domain_names,
        'forward_scheme': form.get('forward_scheme', 'http'),
        'forward_host': form.get('forward_host', '').strip(),
        'forward_port': forward_port,
        'block_exploits': form.get('block_exploits') == 'on',
        'caching_enabled': form.get('caching_enabled') == 'on',
        'allow_websocket_upgrade': form.get('allow_websocket_upgrade') == 'on',
        'http2_support': form.get('http2_support') == 'on',
        'hsts_enabled': form.get('hsts_enabled') == 'on',
        'hsts_subdomains': form.get('hsts_subdomains') == 'on',
        'ssl_forced': form.get('ssl_forced') == 'on',
        'access_list_id': 0,
        'certificate_id': 0,
        'meta': {'letsencrypt_agree': False, 'dns_challenge': False},
        'advanced_config': form.get('advanced_config', ''),
        'locations': [],
    }
    cert_id = form.get('certificate_id', '0')
    if cert_id and cert_id != '0':
        data['certificate_id'] = int(cert_id)
    acl_id = form.get('access_list_id', '0')
    if acl_id and acl_id != '0':
        data['access_list_id'] = int(acl_id)
    return data


# ---------------------------------------------------------------------------
# API endpoint: current status (for AJAX refresh)
# ---------------------------------------------------------------------------

@app.route('/api/status')
@login_required
def api_status():
    db = get_db()
    settings = db.execute('SELECT current_ip, update_interval FROM settings WHERE id = 1').fetchone()
    wans = db.execute('SELECT id, name, current_ip, detect_method FROM wan_interfaces ORDER BY name').fetchall()
    records = db.execute('''
        SELECT r.name, r.content, r.last_status, r.last_updated,
               z.name as zone_name, w.name as wan_name
        FROM cf_records r
        JOIN cf_zones z ON r.zone_id = z.id
        LEFT JOIN wan_interfaces w ON r.wan_id = w.id
        WHERE r.auto_update = 1
    ''').fetchall()
    db.close()
    return jsonify({
        'ip': settings['current_ip'] if settings else '',
        'interval': settings['update_interval'] if settings else 300,
        'wans': [dict(w) for w in wans],
        'records': [dict(r) for r in records]
    })


# ---------------------------------------------------------------------------
# Routes: WAN Interfaces
# ---------------------------------------------------------------------------

@app.route('/wan')
@login_required
def wan_list():
    db = get_db()
    unifi = db.execute('SELECT * FROM unifi_settings WHERE id = 1').fetchone()
    # Check UniFi connection & get live WAN details (reuses cached session)
    unifi_connected = False
    unifi_wans = {}  # {name: {ip, isp_name, isp_org, status, ...}}
    client = get_unifi_client()
    if client:
        unifi_connected = client.is_connected()
        if unifi_connected:
            unifi_wans = client.get_wan_details()
            # Auto-sync: create/update WAN interfaces from UniFi
            for unifi_name, info in unifi_wans.items():
                ip = info.get('ip', '')
                isp = info.get('isp_name', '') or info.get('isp_org', '')
                display_name = f"{unifi_name} ({isp})" if isp else unifi_name
                existing = db.execute(
                    'SELECT id, name FROM wan_interfaces WHERE unifi_wan_name = ?', (unifi_name,)
                ).fetchone()
                if not existing:
                    db.execute(
                        'INSERT INTO wan_interfaces (name, detect_method, unifi_wan_name, current_ip, isp_name) '
                        'VALUES (?, ?, ?, ?, ?)',
                        (display_name, 'unifi', unifi_name, ip, isp))
                else:
                    db.execute(
                        'UPDATE wan_interfaces SET current_ip = ?, isp_name = ?, last_checked = CURRENT_TIMESTAMP WHERE id = ?',
                        (ip, isp, existing['id']))
            db.commit()
    wans = db.execute('SELECT * FROM wan_interfaces ORDER BY name').fetchall()
    db.close()
    return render_template('wan.html', wans=wans, unifi=unifi,
                           unifi_connected=unifi_connected,
                           unifi_wans=unifi_wans)


@app.route('/wan/add', methods=['POST'])
@login_required
def wan_add():
    name = request.form.get('name', '').strip()
    detect_method = request.form.get('detect_method', 'auto')
    static_ip = request.form.get('static_ip', '').strip()
    unifi_wan_name = request.form.get('unifi_wan_name', '').strip()
    if not name:
        flash('WAN name is required', 'danger')
        return redirect(url_for('wan_list'))
    if detect_method not in ('auto', 'static', 'unifi'):
        detect_method = 'auto'
    db = get_db()
    db.execute(
        'INSERT INTO wan_interfaces (name, detect_method, static_ip, unifi_wan_name) VALUES (?, ?, ?, ?)',
        (name, detect_method, static_ip, unifi_wan_name))
    db.commit()
    db.close()
    flash(f'WAN "{name}" added', 'success')
    return redirect(url_for('wan_list'))


@app.route('/wan/<int:wan_id>/edit', methods=['POST'])
@login_required
def wan_edit(wan_id):
    name = request.form.get('name', '').strip()
    detect_method = request.form.get('detect_method', 'auto')
    static_ip = request.form.get('static_ip', '').strip()
    unifi_wan_name = request.form.get('unifi_wan_name', '').strip()
    if not name:
        flash('WAN name is required', 'danger')
        return redirect(url_for('wan_list'))
    if detect_method not in ('auto', 'static', 'unifi'):
        detect_method = 'auto'
    db = get_db()
    db.execute(
        'UPDATE wan_interfaces SET name = ?, detect_method = ?, static_ip = ?, unifi_wan_name = ? WHERE id = ?',
        (name, detect_method, static_ip, unifi_wan_name, wan_id))
    db.commit()
    db.close()
    flash(f'WAN "{name}" updated', 'success')
    return redirect(url_for('wan_list'))


@app.route('/wan/<int:wan_id>/delete', methods=['POST'])
@login_required
def wan_delete(wan_id):
    db = get_db()
    db.execute('UPDATE cf_records SET wan_id = NULL WHERE wan_id = ?', (wan_id,))
    db.execute('DELETE FROM wan_interfaces WHERE id = ?', (wan_id,))
    db.commit()
    db.close()
    flash('WAN interface deleted', 'success')
    return redirect(url_for('wan_list'))


@app.route('/wan/unifi-settings', methods=['POST'])
@login_required
def wan_unifi_settings():
    url = request.form.get('url', '').strip().rstrip('/')
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    site_name = request.form.get('site_name', 'default').strip() or 'default'
    verify_ssl = 1 if request.form.get('verify_ssl') == 'on' else 0
    if not url or not username or not password:
        flash('All UniFi connection fields are required', 'danger')
        return redirect(url_for('wan_list'))
    # Clear cached client since credentials are changing
    clear_cached_client()
    client = UnifiClient(url, username, password, site=site_name, verify_ssl=bool(verify_ssl))
    if not client.test_connection():
        flash('Could not connect to UniFi controller. Check URL and credentials.', 'danger')
        return redirect(url_for('wan_list'))
    db = get_db()
    db.execute(
        'UPDATE unifi_settings SET url = ?, username = ?, password = ?, site_name = ?, verify_ssl = ? WHERE id = 1',
        (url, username, password, site_name, verify_ssl))
    db.commit()
    db.close()
    # Force new cached client with the saved credentials
    clear_cached_client()
    flash('UniFi connection saved and verified', 'success')
    return redirect(url_for('wan_list'))


@app.route('/wan/unifi-sync', methods=['POST'])
@login_required
def wan_unifi_sync():
    """Force re-sync WAN interfaces from UniFi controller."""
    client = get_unifi_client()
    if not client:
        flash('Configure UniFi connection first', 'danger')
        return redirect(url_for('wan_list'))
    if not client.is_connected():
        flash('Could not connect to UniFi controller', 'danger')
        return redirect(url_for('wan_list'))
    wan_details = client.get_wan_details()
    if not wan_details:
        flash('No WAN interfaces found on UniFi controller', 'warning')
        return redirect(url_for('wan_list'))
    db = get_db()
    created = 0
    for unifi_name, info in wan_details.items():
        ip = info.get('ip', '')
        isp = info.get('isp_name', '') or info.get('isp_org', '')
        display_name = f"{unifi_name} ({isp})" if isp else unifi_name
        existing = db.execute(
            'SELECT id FROM wan_interfaces WHERE unifi_wan_name = ?', (unifi_name,)
        ).fetchone()
        if not existing:
            db.execute(
                'INSERT INTO wan_interfaces (name, detect_method, unifi_wan_name, current_ip, isp_name) '
                'VALUES (?, ?, ?, ?, ?)',
                (display_name, 'unifi', unifi_name, ip, isp))
            created += 1
        else:
            db.execute(
                'UPDATE wan_interfaces SET current_ip = ?, isp_name = ?, last_checked = CURRENT_TIMESTAMP WHERE id = ?',
                (ip, isp, existing['id']))
    db.commit()
    db.close()
    flash(f'Synced {len(wan_details)} WAN(s) from UniFi. {created} new interface(s) created.', 'success')
    return redirect(url_for('wan_list'))


# ---------------------------------------------------------------------------
# Jinja filters
# ---------------------------------------------------------------------------

@app.template_filter('localtime')
def localtime_filter(value):
    """Convert a UTC timestamp string to the configured timezone."""
    if not value:
        return ''
    try:
        db = get_db()
        tz_name = db.execute('SELECT timezone FROM settings WHERE id = 1').fetchone()['timezone']
        db.close()
        tz = ZoneInfo(tz_name)
    except Exception:
        tz = ZoneInfo('UTC')
    try:
        if isinstance(value, str):
            dt = datetime.fromisoformat(value).replace(tzinfo=timezone.utc)
        else:
            dt = value.replace(tzinfo=timezone.utc)
        return dt.astimezone(tz).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return str(value)


# ---------------------------------------------------------------------------
# Init & run
# ---------------------------------------------------------------------------

def create_app():
    init_db()
    ensure_admin()
    # Apply mDNS hostname from settings
    try:
        db = get_db()
        s = db.execute('SELECT mdns_hostname FROM settings WHERE id = 1').fetchone()
        db.close()
        if s and s['mdns_hostname']:
            apply_mdns_hostname(s['mdns_hostname'])
    except Exception:
        pass
    scheduler.init_app(app)
    scheduler.start()
    reschedule_job()
    return app


if __name__ == '__main__':
    create_app()
    app.run(host='0.0.0.0', port=5000, debug=False)
