# UpdateIP - Copyright (c) 2026 BluexDEV Softwares. All rights reserved.
# https://github.com/JuhaFIN1/UpdateIP_Cloudflare
"""Tailscale running inside this container (optional), connected with a login link.

The user presses a button: UpdateIP installs Tailscale from Tailscale's official package repository, starts it in
userspace-networking mode (no TUN device or Proxmox change needed) and shows the login link. Nothing is stored by
UpdateIP: the login lives in Tailscale itself. UpdateIP only reads `tailscale status`.
"""
import json
import logging
import re
import shutil
import subprocess
import threading

logger = logging.getLogger(__name__)

# The package source is fixed here. No part of it comes from user input.
_INSTALL_SCRIPT = r'''
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl gnupg ca-certificates
. /etc/os-release
CODE="${VERSION_CODENAME:-bookworm}"
for C in "$CODE" bookworm; do
  if curl -fsSL "https://pkgs.tailscale.com/stable/debian/$C.noarmor.gpg" -o /usr/share/keyrings/tailscale-archive-keyring.gpg \
     && curl -fsSL "https://pkgs.tailscale.com/stable/debian/$C.tailscale-keyring.list" -o /etc/apt/sources.list.d/tailscale.list; then
    break
  fi
done
apt-get update -qq
apt-get install -y -qq tailscale
mkdir -p /etc/default
grep -q 'userspace-networking' /etc/default/tailscaled 2>/dev/null || echo 'FLAGS="--tun=userspace-networking"' >> /etc/default/tailscaled
systemctl enable --now tailscaled
systemctl restart tailscaled
'''

_lock = threading.Lock()
_install = {'state': 'idle', 'msg': ''}      # idle | running | done | error
_up_proc = None


def installed():
    return shutil.which('tailscale') is not None


def _run(args, timeout=15):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None


def status():
    """{'installed','state','auth_url','self','devices','installing'}  state: NeedsLogin | Running | Stopped | NoState | ''."""
    out = {'installed': installed(), 'state': '', 'auth_url': '', 'self': {}, 'devices': [], 'installing': dict(_install)}
    if not out['installed']:
        return out
    r = _run(['tailscale', 'status', '--json'])
    if r is None or not r.stdout.strip():
        out['state'] = 'NoState'
        return out
    try:
        j = json.loads(r.stdout)
    except ValueError:
        out['state'] = 'NoState'
        return out
    out['state'] = j.get('BackendState', '')
    url = j.get('AuthURL') if isinstance(j.get('AuthURL'), str) else ''
    out['auth_url'] = url if re.match(r'^https://[A-Za-z0-9.-]+\.tailscale\.com/', url) or url.startswith('https://login.') else ''
    me = j.get('Self') if isinstance(j.get('Self'), dict) else {}
    ips = [a for a in (me.get('TailscaleIPs') or []) if re.match(r'^\d+\.\d+\.\d+\.\d+$', a)]
    out['self'] = {'name': me.get('HostName', ''), 'ip': ips[0] if ips else ''}
    devices = []
    for p in (j.get('Peer') if isinstance(j.get('Peer'), dict) else {}).values():
        pips = [a for a in (p.get('TailscaleIPs') or []) if re.match(r'^\d+\.\d+\.\d+\.\d+$', a)]
        routes = [x for x in (p.get('PrimaryRoutes') or []) if x not in ('0.0.0.0/0', '::/0')]
        devices.append({'name': p.get('HostName', ''), 'ip': pips[0] if pips else '', 'online': bool(p.get('Online')),
                        'os': p.get('OS', ''), 'exit_node': bool(p.get('ExitNodeOption')), 'routes': routes,
                        'tags': p.get('Tags') or []})
    devices.sort(key=lambda d: (not d['online'], d['name'].lower()))
    out['devices'] = devices
    return out


def _do_install():
    with _lock:
        _install.update(state='running', msg='Installing Tailscale...')
    try:
        r = subprocess.run(['bash', '-c', _INSTALL_SCRIPT], capture_output=True, text=True, timeout=600)
        if r.returncode == 0 and installed():
            _install.update(state='done', msg='Installed.')
        else:
            _install.update(state='error', msg='The installation failed. Check that the container has internet access.')
            logger.warning('Tailscale install failed: %s', (r.stderr or '')[-300:])
    except (OSError, subprocess.SubprocessError) as e:
        _install.update(state='error', msg='The installation failed (%s).' % type(e).__name__)


def install():
    """Start the installation in the background. Returns False if it is already running."""
    with _lock:
        if _install['state'] == 'running':
            return False
    threading.Thread(target=_do_install, daemon=True).start()
    return True


def login():
    """Start `tailscale up` in the background; the login link then appears in status()['auth_url']."""
    global _up_proc
    if not installed():
        return False
    if _up_proc is not None and _up_proc.poll() is None:
        _up_proc.terminate()
    try:
        _up_proc = subprocess.Popen(['tailscale', 'up', '--accept-dns=false', '--accept-routes=false'],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except OSError:
        return False


def logout():
    r = _run(['tailscale', 'logout'])
    return bool(r and r.returncode == 0)
