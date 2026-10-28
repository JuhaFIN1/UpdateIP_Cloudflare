# UpdateIP - Copyright (c) 2026 BluexDEV Softwares. All rights reserved.
# https://github.com/JuhaFIN1/UpdateIP_Cloudflare
"""Software licence client.

UpdateIP needs a free BluexDEV account (auth.selaa.fi) and a licence key. The licence is free for now, but it may
become paid at any time, without prior notice. There is no trial period: without a valid licence the app is locked.

The account is linked with the auth.selaa.fi device login (no callback address, so a changing IP does not matter):
  start()  -> the user opens verification_url and approves the code
  poll()   -> returns an install_token once approved (given once); it is stored in license.json (chmod 600, never logged)
  check()  -> asks the server whether the licence is valid; the last good answer is trusted for GRACE_SECONDS offline.
"""
import json
import logging
import os
import socket
import threading
import time

import requests

logger = logging.getLogger(__name__)

DEFAULT_BASE = 'https://auth.selaa.fi'
SLUG = 'updateip'
STATE_PATH = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'license.json')
GRACE_SECONDS = 30 * 86400      # trust the last successful "licensed" answer for 30 days when offline
MIN_CHECK_SECONDS = 600         # never ask the server more often than this
TIMEOUT = 8

_lock = threading.Lock()


def dev_mode():
    """Developer bypass (UPDATEIP_DEV=1 in the service environment). Never set on a normal installation."""
    return os.environ.get('UPDATEIP_DEV') == '1'


def _load():
    try:
        with open(STATE_PATH, encoding='utf-8') as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _save(state):
    tmp = STATE_PATH + '.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        json.dump(state, f)
    os.replace(tmp, STATE_PATH)


def _post(base, path, body):
    resp = requests.post(base.rstrip('/') + path, json=body, timeout=TIMEOUT)
    try:
        data = resp.json()
    except ValueError:
        data = {}
    return resp.status_code, data


def start(base=None):
    """Begin device login. Returns {'user_code', 'verification_url'} or {'error'}."""
    base = base or DEFAULT_BASE
    try:
        code, data = _post(base, '/api/v1/public/device/start', {'app': SLUG, 'label': socket.gethostname()})
    except requests.RequestException as e:
        logger.warning('licence: device start failed: %s', type(e).__name__)
        return {'error': 'Could not reach auth.selaa.fi'}
    if code != 201 or not data.get('device_code'):
        return {'error': 'auth.selaa.fi refused the request (try again in a minute)'}
    with _lock:
        state = _load()
        state['pending'] = {'device_code': data['device_code'], 'expires': time.time() + int(data.get('expires_in', 600))}
        _save(state)
    return {'user_code': data.get('user_code', ''), 'verification_url': data.get('verification_url', ''),
            'interval': int(data.get('interval', 3))}


def poll(base=None):
    """Poll a pending device login. Returns 'none' | 'pending' | 'approved' | 'denied' | 'expired' | 'error'."""
    base = base or DEFAULT_BASE
    with _lock:
        pending = _load().get('pending')
    if not pending:
        return 'none'
    if time.time() > pending.get('expires', 0):
        return 'expired'
    try:
        code, data = _post(base, '/api/v1/public/device/token', {'device_code': pending['device_code']})
    except requests.RequestException:
        return 'error'
    if code == 202:
        return 'pending'
    if code == 200 and data.get('install_token'):
        with _lock:
            state = _load()
            state.pop('pending', None)
            state['install_token'] = data['install_token']
            state.pop('last', None)
            _save(state)
        check(base, force=True)
        return 'approved'
    if code == 403:
        return 'denied'
    return 'expired'


def check(base=None, force=False):
    """Ask the server about the licence (rate limited, cached). Returns the cached/new status dict."""
    base = base or DEFAULT_BASE
    with _lock:
        state = _load()
        token = state.get('install_token')
        last = state.get('last') or {}
        if not token:
            return {'status': 'none'}
        due = max(MIN_CHECK_SECONDS, min(int(last.get('check_again_after') or 3600), 3600))
        if not force and last and time.time() - last.get('checked_at', 0) < due:
            return last
    try:
        code, data = _post(base, '/api/v1/public/license/check', {'install_token': token})
    except requests.RequestException:
        return dict(last, offline=True) if last else {'status': 'unknown'}   # offline: is_valid() applies the grace limit
    with _lock:
        state = _load()
        if code == 200:
            new = {'status': data.get('status', 'none'), 'tier': data.get('tier'), 'expires_at': data.get('expires_at'),
                   'days_remaining': data.get('days_remaining'), 'checked_at': time.time(),
                   'check_again_after': data.get('check_again_after', 3600)}
            if new['status'] == 'licensed':
                new['ok_at'] = new['checked_at']
            else:
                new['ok_at'] = 0
            state['last'] = new
        elif code in (401, 422):                  # token unknown: this installation was unlinked
            state.pop('install_token', None)
            state['last'] = {'status': 'none', 'checked_at': time.time(), 'ok_at': 0}
        else:
            return dict(last, offline=True) if last else {'status': 'unknown'}
        _save(state)
        return state['last']


def status(base=None):
    """Current licence info for the UI."""
    if dev_mode():
        return {'status': 'licensed', 'dev': True}
    return check(base)


def is_valid(base=None):
    """True when the installation has a valid licence (or the last good answer is within the offline grace period)."""
    if dev_mode():
        return True
    last = check(base)
    if last.get('status') != 'licensed':
        return False
    return not last.get('offline') or time.time() - last.get('ok_at', 0) < GRACE_SECONDS


def unlink():
    with _lock:
        try:
            os.remove(STATE_PATH)
        except OSError:
            pass
