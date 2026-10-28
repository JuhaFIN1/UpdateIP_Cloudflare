# UpdateIP - Copyright (c) 2026 BluexDEV Softwares. All rights reserved.
# https://github.com/JuhaFIN1/UpdateIP_Cloudflare
"""Create and remove UniFi routing rules from the DNS & WAN wizard.

Safety rules, enforced here and not only in the page:
  - every rule UpdateIP creates is named with OWN_PREFIX, and only rules with that prefix can be deleted here
  - a change is always built as a plain-language preview first; nothing is written without confirm=True
  - port forwards must point to a private address and must not clash with an existing forward on the same WAN
"""
import ipaddress
import logging
import re

logger = logging.getLogger(__name__)

OWN_PREFIX = 'UpdateIP: '
_ROUTES = '/proxy/network/v2/api/site/{site}/trafficroutes'
_FORWARDS = '/proxy/network/api/s/{site}/rest/portforward'
_ACTIVE = '/proxy/network/api/s/{site}/stat/sta'
_KNOWN = '/proxy/network/api/s/{site}/rest/user'


def _rows(payload):
    if isinstance(payload, dict):
        payload = payload.get('data', [])
    return payload if isinstance(payload, list) else []


def _get(client, tmpl):
    r = client._request('get', tmpl.format(site=client.site))
    if r is None or r.status_code != 200:
        return []
    try:
        return _rows(r.json())
    except ValueError:
        return []


def list_clients(client):
    """Devices on the network: [{'mac', 'name', 'ip'}], active ones first. Read only."""
    known = {}
    for c in _get(client, _KNOWN):
        mac = (c.get('mac') or '').lower()
        if mac:
            known[mac] = {'mac': mac, 'name': c.get('name') or c.get('hostname') or mac, 'ip': ''}
    for c in _get(client, _ACTIVE):
        mac = (c.get('mac') or '').lower()
        if not mac:
            continue
        e = known.setdefault(mac, {'mac': mac, 'name': c.get('name') or c.get('hostname') or mac, 'ip': ''})
        e['ip'] = c.get('ip') or e['ip']
    out = sorted(known.values(), key=lambda d: (not d['ip'], d['name'].lower()))
    return out


def own_rules(client):
    """The routes and port forwards that UpdateIP created: {'routes': [...], 'forwards': [...]}."""
    routes = [{'id': r.get('_id'), 'name': r.get('description', '')[len(OWN_PREFIX):]}
              for r in _get(client, _ROUTES) if (r.get('description') or '').startswith(OWN_PREFIX)]
    forwards = [{'id': f.get('_id'), 'name': f.get('name', '')[len(OWN_PREFIX):]}
                for f in _get(client, _FORWARDS) if (f.get('name') or '').startswith(OWN_PREFIX)]
    return {'routes': routes, 'forwards': forwards}


def _clean_name(name, fallback):
    name = re.sub(r'[^\w .()-]', '', str(name or '')).strip()[:60]
    return name or fallback


# ---- outgoing: route a device out through one WAN ----------------------------------------------------------------
def build_route(client, name, mac, wan_id, kill_switch):
    """Validate and return (payload, preview_text, error)."""
    mac = (mac or '').lower()
    if not re.match(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$', mac):
        return None, None, 'Choose a device.'
    devices = {d['mac']: d for d in list_clients(client)}
    wans = {w['id']: w for w in _wan_list(client)}
    if wan_id not in wans:
        return None, None, 'Choose an internet connection.'
    for r in _get(client, _ROUTES):
        if any((d.get('client_mac') or '').lower() == mac for d in r.get('target_devices') or []) and r.get('enabled'):
            return None, None, 'This device already has a routing rule ("%s"). Remove or change that rule first.' % r.get('description', '')
    dev = devices.get(mac, {'name': mac})
    title = _clean_name(name, 'Route %s' % dev['name'])
    payload = {'description': OWN_PREFIX + title, 'enabled': True, 'matching_target': 'INTERNET', 'network_id': wan_id,
               'next_hop': '', 'domains': [], 'ip_addresses': [], 'ip_ranges': [], 'regions': [],
               'target_devices': [{'client_mac': mac, 'type': 'CLIENT'}], 'kill_switch_enabled': bool(kill_switch)}
    preview = '%s will go out through %s for all internet traffic.%s' % (
        dev['name'], wans[wan_id]['name'],
        ' If that connection is down, its traffic is blocked.' if kill_switch else ' If that connection is down, it uses the other one.')
    return payload, preview, None


def create_route(client, payload):
    ok, data, status = client.write_json('post', _ROUTES.format(site=client.site), payload)
    return ok, (None if ok else 'UniFi did not accept the rule (code %s).' % status)


def delete_own(client, kind, item_id):
    """Delete a rule only if UpdateIP created it."""
    mine = own_rules(client)['routes' if kind == 'route' else 'forwards']
    if not any(m['id'] == item_id for m in mine):
        return False, 'This rule was not created by UpdateIP and is not touched.'
    tmpl = _ROUTES if kind == 'route' else _FORWARDS
    ok, _, status = client.write_json('delete', tmpl.format(site=client.site) + '/' + item_id)
    return ok, (None if ok else 'UniFi did not remove the rule (code %s).' % status)


# ---- incoming: open a port on one WAN and send it to a device ------------------------------------------------------
def build_forward(client, name, wan_key, proto, ext_port, ip, int_port):
    wans = {w['key']: w for w in _wan_list(client) if w['key']}
    if wan_key not in wans:
        return None, None, 'Choose an internet connection.'
    proto = (proto or '').lower()
    if proto not in ('tcp', 'udp', 'tcp_udp'):
        return None, None, 'Choose TCP, UDP or both.'
    try:
        ext, internal = int(ext_port), int(int_port or ext_port)
    except (TypeError, ValueError):
        return None, None, 'Ports must be numbers.'
    if not (1 <= ext <= 65535 and 1 <= internal <= 65535):
        return None, None, 'Ports must be between 1 and 65535.'
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return None, None, 'The device address is not valid.'
    if not addr.is_private or addr.is_loopback:
        return None, None, 'Traffic can only be sent to a device on your own network (a private address).'
    for f in _get(client, _FORWARDS):
        if (f.get('pfwd_interface') or '').lower() == wan_key and str(f.get('dst_port')) == str(ext) \
                and f.get('enabled', True) and (f.get('proto') in (proto, 'tcp_udp') or proto == 'tcp_udp'):
            return None, None, 'Port %d is already forwarded on %s ("%s").' % (ext, wans[wan_key]['name'], f.get('name', ''))
    title = _clean_name(name, 'Port %d' % ext)
    payload = {'name': OWN_PREFIX + title, 'enabled': True, 'pfwd_interface': wan_key, 'fwd': str(addr),
               'fwd_port': str(internal), 'dst_port': str(ext), 'proto': proto, 'src': 'any', 'log': False,
               'destination_ip': 'any', 'src_limiting_enabled': False}
    preview = 'Connections to port %d (%s) on %s will be sent to %s, port %d. This opens that port to the internet.' % (
        ext, proto.replace('_', '/').upper(), wans[wan_key]['name'], addr, internal)
    return payload, preview, None


def create_forward(client, payload):
    ok, data, status = client.write_json('post', _FORWARDS.format(site=client.site), payload)
    return ok, (None if ok else 'UniFi did not accept the port forward (code %s).' % status)


# ---- WAN list ------------------------------------------------------------------------------------------------------
def _wan_list(client):
    """[{'id', 'name', 'key'}] for the internet connections (key = 'wan', 'wan2', ...)."""
    nets = _get(client, '/proxy/network/api/s/{site}/rest/networkconf')
    groups = {n.get('_id'): (n.get('wan_networkgroup') or '').lower() for n in nets if n.get('purpose') == 'wan'}
    r = client._request('get', '/proxy/network/v2/api/site/%s/wan/enriched-configuration' % client.site)
    out = []
    if r is not None and r.status_code == 200:
        try:
            for w in _rows(r.json()):
                conf = w.get('configuration') or {}
                out.append({'id': conf.get('_id'), 'name': conf.get('name') or 'WAN', 'key': groups.get(conf.get('_id'), '')})
        except ValueError:
            pass
    return out


def wan_list(client):
    return _wan_list(client)
