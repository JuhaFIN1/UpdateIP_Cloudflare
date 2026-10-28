# UpdateIP - Copyright (c) 2026 BluexDEV Softwares. All rights reserved.
# https://github.com/JuhaFIN1/UpdateIP_Cloudflare
"""Read-only overview of UniFi routing policies per WAN, in plain language.

Only GET requests are made. Nothing is created, changed or deleted here.
  outgoing: Policy-Based Routes  (which devices/destinations leave through which WAN)
  incoming: Port Forwarding      (which services arrive on which WAN)
"""
import logging

logger = logging.getLogger(__name__)

_ENDPOINTS = {
    'wans': '/proxy/network/v2/api/site/{site}/wan/enriched-configuration',
    'networks': '/proxy/network/api/s/{site}/rest/networkconf',
    'routes': '/proxy/network/v2/api/site/{site}/trafficroutes',
    'forwards': '/proxy/network/api/s/{site}/rest/portforward',
    'clients': '/proxy/network/api/s/{site}/rest/user',
}


def _rows(payload):
    """UniFi answers either a list or {'data': [...]}."""
    if isinstance(payload, dict):
        payload = payload.get('data', [])
    return payload if isinstance(payload, list) else []


def fetch_raw(client):
    """Fetch the raw data with GET requests only. Returns (raw, error). A missing optional part gives []."""
    raw = {}
    for key, path in _ENDPOINTS.items():
        try:
            r = client._request('get', path.format(site=client.site))
        except Exception as e:                      # network error: report, never raise into the page
            logger.warning('UniFi policy fetch %s failed: %s', key, type(e).__name__)
            r = None
        if r is None or r.status_code != 200:
            if key in ('wans', 'networks'):
                return None, 'Could not read the WAN list from UniFi.'
            raw[key] = []
            continue
        try:
            raw[key] = _rows(r.json())
        except ValueError:
            raw[key] = []
    return raw, None


def _who(route, names):
    out = []
    for d in route.get('target_devices') or []:
        mac = d.get('client_mac') or ''
        out.append(names.get(mac.lower()) or mac or d.get('type', 'device'))
    for n in route.get('target_networks') or []:
        out.append(str(n))
    return out or ['every device']


def _what(route):
    target = route.get('matching_target', 'INTERNET')
    if target == 'DOMAIN':
        items = [d.get('domain', d) if isinstance(d, dict) else d for d in route.get('domains') or []]
        return 'these websites: ' + ', '.join(map(str, items)) if items else 'selected websites'
    if target == 'IP':
        items = list(route.get('ip_addresses') or []) + list(route.get('ip_ranges') or [])
        items = [i.get('ip_or_subnet', i) if isinstance(i, dict) else i for i in items]
        return 'these addresses: ' + ', '.join(map(str, items)) if items else 'selected addresses'
    if target == 'REGION':
        return 'these regions: ' + ', '.join(map(str, route.get('regions') or []))
    return 'all internet traffic'


def build_overview(raw):
    """Turn the raw UniFi data into {'wans': [{name, outgoing:[...], incoming:[...]}]} for the page."""
    names = {}
    for c in raw.get('clients', []):
        mac = (c.get('mac') or '').lower()
        if mac:
            names[mac] = c.get('name') or c.get('hostname') or mac

    # WAN network id -> display name and the interface key that port forwards use ('wan', 'wan2', ...)
    group_of = {n.get('_id'): (n.get('wan_networkgroup') or '').lower()
                for n in raw.get('networks', []) if n.get('purpose') == 'wan'}
    wans = []
    for w in raw.get('wans', []):
        conf = w.get('configuration') or {}
        wid = conf.get('_id')
        wans.append({'id': wid, 'name': conf.get('name') or 'WAN', 'key': group_of.get(wid, ''),
                     'outgoing': [], 'incoming': []})
    by_id = {w['id']: w for w in wans}
    by_key = {w['key']: w for w in wans if w['key']}

    for r in raw.get('routes', []):
        w = by_id.get(r.get('network_id'))
        if not w:
            continue
        w['outgoing'].append({
            'title': r.get('description') or 'Route', 'enabled': bool(r.get('enabled')),
            'who': _who(r, names), 'what': _what(r), 'kill_switch': bool(r.get('kill_switch_enabled')),
        })

    for f in raw.get('forwards', []):
        w = by_key.get((f.get('pfwd_interface') or '').lower())
        if not w:
            continue
        port = f.get('dst_port') or '?'
        to_port = f.get('fwd_port') or port
        w['incoming'].append({
            'title': f.get('name') or 'Port forward', 'enabled': bool(f.get('enabled', True)),
            'proto': (f.get('proto') or 'tcp_udp').replace('_', '/').upper(),
            'port': port, 'to': '%s:%s' % (f.get('fwd') or '?', to_port),
        })
    return {'wans': wans}


def get_overview(client):
    """Return (overview, error)."""
    raw, err = fetch_raw(client)
    if err:
        return None, err
    return build_overview(raw), None
