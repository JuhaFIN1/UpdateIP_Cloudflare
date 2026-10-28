# UpdateIP - Copyright (c) 2026 BluexDEV Softwares. All rights reserved.
# https://github.com/JuhaFIN1/UpdateIP_Cloudflare
"""Review of DNS records across Cloudflare, Nginx Proxy Manager and UniFi, in plain language.

build_plan() only reads: it takes what the three services say and returns, for every DNS record, what was found,
which internet connection (WAN) it most likely belongs to and why, and the list of changes that would make everything
agree. Nothing is changed here. The changes are applied by the app only after the user has ticked and confirmed them.
"""
import ipaddress


def _lower_domains(host):
    return [str(d).lower() for d in (host.get('domain_names') or [])]


def _fwd(forwards, key, port):
    """An enabled UniFi port forward on this WAN for this destination port, or None."""
    for f in forwards:
        if not f.get('enabled', True) or (f.get('pfwd_interface') or '').lower() != key:
            continue
        if str(f.get('dst_port')) == str(port) and (f.get('proto') or 'tcp') in ('tcp', 'tcp_udp'):
            return f
    return None


def build_plan(records, wans, npm_hosts, npm_ip, forwards, choices=None):
    """records: [{id,name,content,proxied,auto_update,wan_id}]
    wans: [{id,label,key,ip}]  (id = UpdateIP's WAN id, key = UniFi interface 'wan'/'wan2', ip = current address)
    npm_hosts: Nginx Proxy Manager proxy hosts.  npm_ip: private address of the Nginx Proxy Manager server or ''.
    forwards: UniFi port forwards.  choices: {record id: WAN id chosen by the user}."""
    choices = choices or {}
    by_id = {w['id']: w for w in wans}
    items, actions = [], {}

    def add_action(a):
        actions.setdefault(a['id'], a)
        return a['id']

    for r in records:
        rid = str(r['id'])
        host = next((h for h in npm_hosts if r['name'].lower() in _lower_domains(h)), None)
        facts = ['Cloudflare: %s points to %s%s.' % (r['name'], r['content'] or 'nothing',
                                                     ' (hidden behind Cloudflare\'s proxy)' if r.get('proxied') else '')]
        if host:
            facts.append('Nginx Proxy Manager: it is a proxy host, sending visitors to %s:%s.' % (
                host.get('forward_host', '?'), host.get('forward_port', '?')))
        else:
            facts.append('Nginx Proxy Manager: no proxy host uses this name.')

        # which WAN? 1) the user's choice  2) the record's address is a WAN's address  3) ports 80/443 are forwarded on one WAN only
        chosen = by_id.get(choices.get(rid)) if choices.get(rid) else None
        suggestion, reason = None, ''
        if chosen is None:
            match = [w for w in wans if w['ip'] and w['ip'] == r['content']]
            if len(match) == 1:
                suggestion = match[0]
                reason = 'Its address %s is the current address of %s.' % (r['content'], match[0]['label'])
            elif host and npm_ip:
                on = [w for w in wans if w['key'] and _fwd(forwards, w['key'], 80) and _fwd(forwards, w['key'], 80).get('fwd') == npm_ip]
                if len(on) == 1:
                    suggestion = on[0]
                    reason = 'UniFi sends port 80 on %s to Nginx Proxy Manager, so visitors arrive on that connection.' % on[0]['label']
        wan = chosen or suggestion
        if wan is None and not r.get('wan_id'):
            reason = reason or 'It does not match any of your internet connections (its address %s is not one of them), so UpdateIP cannot tell which one it belongs to.' % (r['content'] or 'is empty')
        if wan is None and r.get('wan_id') in by_id:
            wan = by_id[r['wan_id']]
            reason = 'Already set to %s.' % wan['label']
        if chosen:
            reason = 'You chose %s.' % chosen['label']

        ids = []
        if wan:
            if not (r.get('auto_update') and r.get('wan_id') == wan['id']):
                ids.append(add_action({
                    'id': 'local:%s' % rid, 'kind': 'local', 'record': rid, 'wan_id': wan['id'], 'default': True,
                    'title': 'UpdateIP: keep %s up to date through %s' % (r['name'], wan['label']),
                    'why': 'When the address of %s changes, UpdateIP will update this record by itself.' % wan['label']}))
            if wan['ip'] and wan['ip'] != r['content']:
                ids.append(add_action({
                    'id': 'cf:%s' % rid, 'kind': 'cloudflare', 'record': rid, 'ip': wan['ip'], 'default': True,
                    'title': 'Cloudflare: change %s from %s to %s' % (r['name'], r['content'] or 'empty', wan['ip']),
                    'why': 'The record points to an address that is not %s any more, so visitors would not reach you.' % wan['label']}))
            if host and npm_ip and wan['key']:
                for port in (80, 443):
                    if not _fwd(forwards, wan['key'], port):
                        ids.append(add_action({
                            'id': 'fwd:%s:%d' % (wan['key'], port), 'kind': 'unifi', 'wan_key': wan['key'], 'port': port,
                            'ip': npm_ip, 'default': False,
                            'title': 'UniFi: open port %d on %s and send it to Nginx Proxy Manager (%s)' % (port, wan['label'], npm_ip),
                            'why': '%s is a proxy host, so visitors must be able to reach Nginx Proxy Manager through %s. This opens that port to the internet.' % (r['name'], wan['label'])}))
            elif host and not npm_ip:
                facts.append('UniFi: the address of Nginx Proxy Manager is not known, so port forwards cannot be checked.')
            if host and wan['key']:
                f80 = _fwd(forwards, wan['key'], 80)
                facts.append('UniFi: port 80 on %s %s.' % (wan['label'], ('goes to %s' % f80.get('fwd')) if f80 else 'is not forwarded'))
        items.append({'id': rid, 'name': r['name'], 'content': r['content'], 'facts': facts,
                      'wan_id': wan['id'] if wan else None, 'reason': reason, 'actions': ids,
                      'known': wan is not None})
    return {'items': items, 'actions': list(actions.values())}


def private_host(url):
    """The host of a URL if it is a private IP address, else ''."""
    try:
        host = (url or '').split('://', 1)[-1].split('/', 1)[0].rsplit(':', 1)[0]
        return host if ipaddress.ip_address(host).is_private else ''
    except ValueError:
        return ''
