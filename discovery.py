# UpdateIP - Copyright (c) 2026 BluexDEV Softwares. All rights reserved.
# https://github.com/JuhaFIN1/UpdateIP_Cloudflare
"""Home network discovery for the setup wizard.

Finds the subnets this machine can see, then looks for devices in the chosen (private) subnets by trying a few TCP
ports and reading the neighbour table. Recognises UniFi gateways and Nginx Proxy Manager. Only private address ranges
are ever scanned, only on the user's request, and nothing is changed on any device.
"""
import ipaddress
import json
import logging
import re
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)

MAX_HOSTS_PER_SUBNET = 1024            # /22; larger networks must be narrowed down by the user
PORTS = (443, 81, 80, 8443, 22, 445, 53)
CONNECT_TIMEOUT = 0.5
WORKERS = 128


def _private_net(text):
    """Parse text as an IPv4 network; return it only if it is private and small enough, else None."""
    try:
        net = ipaddress.ip_network(text.strip(), strict=False)
    except ValueError:
        return None
    if net.version != 4 or not net.is_private or net.is_loopback or net.is_link_local:
        return None
    if net.num_addresses > MAX_HOSTS_PER_SUBNET:
        return None
    return net


def parse_subnets(items):
    """Validate user input. Returns (list of ip_network, list of rejected strings)."""
    ok, bad = [], []
    for it in items:
        n = _private_net(str(it))
        if n is None:
            bad.append(str(it))
        elif n not in ok:
            ok.append(n)
    return ok, bad


def local_subnets():
    """Subnets this machine is connected to (and routes to). Returns a list of CIDR strings."""
    found = []
    try:
        out = subprocess.run(['ip', '-o', '-4', 'addr', 'show'], capture_output=True, text=True, timeout=5).stdout
        for m in re.finditer(r'inet (\d+\.\d+\.\d+\.\d+/\d+)', out):
            found.append(m.group(1))
        out = subprocess.run(['ip', '-4', 'route', 'show'], capture_output=True, text=True, timeout=5).stdout
        for m in re.finditer(r'^(\d+\.\d+\.\d+\.\d+/\d+)', out, re.M):
            found.append(m.group(1))
    except (OSError, subprocess.SubprocessError):
        pass
    if not found:                       # no `ip` command: fall back to the address used for outgoing traffic
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('10.255.255.255', 1))
            found.append(s.getsockname()[0] + '/24')
            s.close()
        except OSError:
            pass
    nets = []
    for c in found:
        n = _private_net(c)
        if n is not None and str(n) not in nets:
            nets.append(str(n))
    return nets


def _port_open(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT):
            return True
    except OSError:
        return False


def _get(url, **kw):
    try:
        return requests.get(url, timeout=2, verify=False, allow_redirects=False, **kw)
    except requests.RequestException:
        return None


def _identify(ip, open_ports):
    """Return (type, label) for a host: 'unifi', 'npm' or ''. Read-only GET requests."""
    if 81 in open_ports:
        r = _get('http://%s:81/api/' % ip)
        if r is not None and r.status_code == 200:
            try:
                d = r.json()
                if d.get('status') == 'OK' and 'version' in d:
                    return 'npm', 'Nginx Proxy Manager'
            except ValueError:
                pass
    if 443 in open_ports:
        r = _get('https://%s/' % ip)
        if r is not None:
            body = (r.text or '')[:6000].lower()
            if 'unifi' in body or 'ubnt' in body or 'x-csrf-token' in {k.lower() for k in r.headers}:
                return 'unifi', 'UniFi (OS console or gateway)'
    if 8443 in open_ports:
        r = _get('https://%s:8443/' % ip)
        if r is not None and 'unifi' in (r.text or '').lower()[:6000]:
            return 'unifi', 'UniFi Network application'
    return '', ''


def _neighbours():
    """IP -> MAC from the neighbour table (only hosts on directly connected subnets)."""
    out = {}
    try:
        txt = subprocess.run(['ip', '-4', 'neigh', 'show'], capture_output=True, text=True, timeout=5).stdout
        for m in re.finditer(r'^(\d+\.\d+\.\d+\.\d+) .*lladdr ([0-9a-f:]{17})', txt, re.M | re.I):
            out[m.group(1)] = m.group(2).lower()
    except (OSError, subprocess.SubprocessError):
        pass
    return out


def _probe(ip):
    ports = [p for p in PORTS if _port_open(ip, p)]
    return ip, ports


def _hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, socket.herror):
        return ''


class Scan:
    """One background scan with progress, shared by the wizard page."""

    def __init__(self):
        self.lock = threading.Lock()
        self.reset()

    def reset(self):
        self.state = 'idle'            # idle | running | done | error
        self.total = 0
        self.done = 0
        self.devices = []
        self.message = ''
        self.started = 0.0

    def start(self, nets):
        with self.lock:
            if self.state == 'running':
                return False
            self.reset()
            self.state = 'running'
            self.started = time.time()
            self.total = sum(max(n.num_addresses - 2, 1) for n in nets)
        threading.Thread(target=self._run, args=(nets,), daemon=True).start()
        return True

    def _run(self, nets):
        try:
            hosts = [str(h) for n in nets for h in (n.hosts() if n.num_addresses > 2 else [n.network_address])]
            found = {}
            with ThreadPoolExecutor(max_workers=WORKERS) as pool:
                for ip, ports in pool.map(_probe, hosts):
                    with self.lock:
                        self.done += 1
                    if ports:
                        found[ip] = ports
            neigh = _neighbours()
            for ip in neigh:                       # devices that answer ARP but have no open scanned port
                if any(ipaddress.ip_address(ip) in n for n in nets):
                    found.setdefault(ip, [])
            devices = []
            for ip, ports in sorted(found.items(), key=lambda kv: ipaddress.ip_address(kv[0])):
                kind, label = _identify(ip, ports)
                devices.append({'ip': ip, 'ports': ports, 'mac': neigh.get(ip, ''), 'hostname': _hostname(ip),
                                'type': kind, 'label': label})
            with self.lock:
                self.devices = devices
                self.state = 'done'
        except Exception as e:                    # never leave the page waiting
            logger.warning('network scan failed: %s', type(e).__name__)
            with self.lock:
                self.state = 'error'
                self.message = 'The scan failed. Try again, or narrow down the subnets.'

    def status(self):
        with self.lock:
            return {'state': self.state, 'done': self.done, 'total': self.total,
                    'devices': list(self.devices), 'message': self.message}


scan = Scan()
