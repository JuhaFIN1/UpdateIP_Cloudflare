# UpdateIP - Copyright (c) 2026 BluexDEV Softwares. All rights reserved.
# https://github.com/JuhaFIN1/UpdateIP_Cloudflare
"""Read-only Tailscale client (optional feature).

Uses the Tailscale API with an API access token to list the devices of a tailnet. Nothing is changed in Tailscale.
The token is a secret: it is never logged and never sent anywhere except api.tailscale.com.
"""
import logging
import re

import requests

logger = logging.getLogger(__name__)

API = 'https://api.tailscale.com/api/v2'
TIMEOUT = 10


def _valid_tailnet(value):
    value = (value or '-').strip() or '-'
    return value if re.match(r'^[A-Za-z0-9._@-]{1,100}$', value) else None


def list_devices(api_key, tailnet='-'):
    """Return (devices, error). devices: [{'name','ip','online','os','exit_node','routes','tags'}]."""
    tailnet = _valid_tailnet(tailnet)
    if not api_key or tailnet is None:
        return None, 'Enter the access token and the tailnet name (or leave the tailnet as "-").'
    try:
        r = requests.get('%s/tailnet/%s/devices' % (API, tailnet), params={'fields': 'all'},
                         auth=(api_key.strip(), ''), timeout=TIMEOUT)
    except requests.RequestException:
        return None, 'Could not reach api.tailscale.com.'
    if r.status_code in (401, 403):
        return None, 'Tailscale does not accept this token. It may be wrong or expired (access tokens last at most 90 days).'
    if r.status_code == 404:
        return None, 'That tailnet was not found. Leave the tailnet as "-" to use the token\'s own tailnet.'
    if r.status_code != 200:
        return None, 'Tailscale answered with an error (code %s).' % r.status_code
    try:
        raw = r.json().get('devices', [])
    except ValueError:
        return None, 'Tailscale gave an unexpected answer.'
    out = []
    for d in raw:
        ips = [a for a in d.get('addresses', []) if re.match(r'^\d+\.\d+\.\d+\.\d+$', a)]
        enabled = d.get('enabledRoutes') or []
        advertised = d.get('advertisedRoutes') or []
        out.append({
            'name': (d.get('name') or d.get('hostname') or '').split('.')[0],
            'ip': ips[0] if ips else '',
            'online': bool(d.get('connectedToControl', False)),
            'os': d.get('os', ''),
            'exit_node': '0.0.0.0/0' in enabled,
            'routes': [x for x in advertised if x not in ('0.0.0.0/0', '::/0')],
            'tags': d.get('tags') or [],
        })
    out.sort(key=lambda x: (not x['online'], x['name'].lower()))
    return out, None
