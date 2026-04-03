import os
import logging
import secrets
from datetime import datetime, timezone
from functools import wraps

import bcrypt
from flask import (Flask, render_template, request, redirect, url_for,
                   flash, session, jsonify)
from flask_apscheduler import APScheduler

from database import get_db, init_db, DB_PATH
from cloudflare_api import (verify_token, list_zones, list_dns_records,
                            get_public_ip)
from updater import check_and_update_ip
from npm_api import get_npm_client, NpmClient

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
# Scheduler job
# ---------------------------------------------------------------------------

def scheduled_update():
    with app.app_context():
        logger.info('Scheduled IP check running')
        result = check_and_update_ip(force=False)
        logger.info(f'Scheduled update result: {result.get("message", "")}')


def reschedule_job():
    db = get_db()
    row = db.execute('SELECT update_interval FROM settings WHERE id = 1').fetchone()
    db.close()
    interval = row['update_interval'] if row else 300

    if scheduler.get_job('ip_update'):
        scheduler.remove_job('ip_update')
    scheduler.add_job(
        id='ip_update',
        func=scheduled_update,
        trigger='interval',
        seconds=interval,
        replace_existing=True
    )
    logger.info(f'Scheduler set to every {interval}s')

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
    records = db.execute('''
        SELECT r.*, z.name as zone_name, a.name as account_name
        FROM cf_records r
        JOIN cf_zones z ON r.zone_id = z.id
        JOIN cf_accounts a ON r.account_id = a.id
        WHERE r.auto_update = 1
        ORDER BY a.name, z.name, r.name
    ''').fetchall()
    recent_logs = db.execute(
        'SELECT * FROM update_log ORDER BY updated_at DESC LIMIT 20'
    ).fetchall()
    db.close()
    return render_template('dashboard.html',
                           settings=settings,
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
        db.execute('INSERT OR REPLACE INTO cf_zones (id, account_id, name) VALUES (?, ?, ?)',
                   (z['id'], account_id, z['name']))

        dns_records = list_dns_records(acc['api_token'], z['id'])
        for rec in dns_records:
            existing = db.execute('SELECT auto_update FROM cf_records WHERE id = ?',
                                  (rec['id'],)).fetchone()
            auto_update = existing['auto_update'] if existing else 0
            db.execute('''INSERT OR REPLACE INTO cf_records
                          (id, zone_id, account_id, name, type, content, proxied, auto_update)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                       (rec['id'], z['id'], account_id, rec['name'], rec['type'],
                        rec['content'], 1 if rec.get('proxied') else 0, auto_update))
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
    recs = db.execute('''
        SELECT r.*, z.name as zone_name, a.name as account_name
        FROM cf_records r
        JOIN cf_zones z ON r.zone_id = z.id
        JOIN cf_accounts a ON r.account_id = a.id
        ORDER BY a.name, z.name, r.name
    ''').fetchall()
    db.close()
    return render_template('records.html', records=recs, accounts=accs)


@app.route('/records/toggle', methods=['POST'])
@login_required
def record_toggle():
    record_id = request.form.get('record_id', '')
    auto_update = 1 if request.form.get('auto_update') == '1' else 0
    db = get_db()
    db.execute('UPDATE cf_records SET auto_update = ? WHERE id = ?', (auto_update, record_id))
    db.commit()
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
    ip_logs = db.execute('SELECT * FROM ip_log ORDER BY changed_at DESC LIMIT 100').fetchall()
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

        elif action == 'interval':
            try:
                interval = int(request.form.get('update_interval', 300))
                if interval < 60:
                    interval = 60
                if interval > 86400:
                    interval = 86400
            except ValueError:
                interval = 300
            db.execute('UPDATE settings SET update_interval = ? WHERE id = 1', (interval,))
            db.commit()
            flash(f'Update interval set to {interval} seconds', 'success')
            reschedule_job()

        db.close()
        return redirect(url_for('settings'))

    s = db.execute('SELECT * FROM settings WHERE id = 1').fetchone()
    db.close()
    return render_template('settings.html', settings=s)


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
    records = db.execute('''
        SELECT r.name, r.content, r.last_status, r.last_updated, z.name as zone_name
        FROM cf_records r
        JOIN cf_zones z ON r.zone_id = z.id
        WHERE r.auto_update = 1
    ''').fetchall()
    db.close()
    return jsonify({
        'ip': settings['current_ip'] if settings else '',
        'interval': settings['update_interval'] if settings else 300,
        'records': [dict(r) for r in records]
    })


# ---------------------------------------------------------------------------
# Init & run
# ---------------------------------------------------------------------------

def create_app():
    init_db()
    ensure_admin()
    scheduler.init_app(app)
    scheduler.start()
    reschedule_job()
    return app


if __name__ == '__main__':
    create_app()
    app.run(host='0.0.0.0', port=5000, debug=False)
