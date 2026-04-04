# UpdateIP - Copyright (c) 2026 Juha Lempiäinen. All rights reserved.
# https://github.com/JuhaFIN1/Updateip

import requests
import logging
import time
import urllib3

# Suppress InsecureRequestWarning for self-signed UDM certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

# Cached singleton client — avoids repeated logins that trigger UDM rate limiting
_cached_client = None
_cached_config = None


class UnifiClient:
    """Client for UniFi OS controller API (UDM, UDM-Pro, UDM-SE, UCG)."""

    def __init__(self, base_url, username, password, site='default', verify_ssl=False):
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = password
        self.site = site
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.verify = self.verify_ssl
        self._logged_in = False
        self._login_time = 0
        self._login_backoff_until = 0  # timestamp: don't attempt login before this

    def login(self):
        """Authenticate with the UniFi controller."""
        self._logged_in = False
        now = time.time()
        # Respect backoff from previous 403 (rate-limit)
        if now < self._login_backoff_until:
            logger.debug('UniFi login skipped — backing off until %s',
                         time.strftime('%H:%M:%S', time.localtime(self._login_backoff_until)))
            return False
        try:
            # Clear stale cookies/CSRF tokens before re-login
            self.session.cookies.clear()
            r = self.session.post(
                f'{self.base_url}/api/auth/login',
                json={'username': self.username, 'password': self.password},
                timeout=15,
            )
            if r.status_code == 200:
                self._logged_in = True
                self._login_time = now
                self._login_backoff_until = 0
                logger.info('UniFi login successful')
                return True
            if r.status_code == 403:
                # UniFi OS rate-limited — back off for 5 minutes
                self._login_backoff_until = now + 300
                logger.warning('UniFi login rate-limited (403), backing off 5 min')
            else:
                logger.warning('UniFi login failed: HTTP %s — %s', r.status_code, r.text[:200])
            return False
        except Exception as e:
            logger.error('UniFi login error: %s', e)
            return False

    def _ensure_logged_in(self):
        """Login only if not already logged in or session is old (>30 min)."""
        if self._logged_in and (time.time() - self._login_time) < 1800:
            return True
        return self.login()

    def _request(self, method, path, **kwargs):
        """Make an authenticated request with auto-retry on 401/403."""
        if not self._ensure_logged_in():
            return None
        kwargs.setdefault('timeout', 15)
        url = f'{self.base_url}{path}'
        r = getattr(self.session, method)(url, **kwargs)
        if r.status_code in (401, 403):
            logger.info('UniFi session expired (%s), re-authenticating', r.status_code)
            self._logged_in = False
            if self.login():
                r = getattr(self.session, method)(url, **kwargs)
            else:
                return None
        return r

    def test_connection(self):
        """Test connectivity and credentials (forces fresh login)."""
        self._logged_in = False  # Force fresh login for explicit test
        if not self.login():
            return False
        r = self._request('get', f'/proxy/network/api/s/{self.site}/stat/health')
        if r and r.status_code == 200:
            return True
        logger.warning('UniFi connected but stat/health failed: %s',
                       r.status_code if r else 'no response')
        return False

    def _get_health(self):
        """Fetch site health data (subsystems including WAN info)."""
        try:
            r = self._request('get', f'/proxy/network/api/s/{self.site}/stat/health')
            if not r or r.status_code != 200:
                logger.warning('UniFi get_health: HTTP %s', r.status_code if r else 'None')
                return []
            data = r.json()
            if data.get('meta', {}).get('rc') == 'ok':
                return data.get('data', [])
            logger.warning('UniFi get_health: rc=%s', data.get('meta', {}).get('rc'))
            return []
        except Exception as e:
            logger.error('UniFi get_health error: %s', e)
            return []

    def _get_gateway_device(self):
        """Fetch gateway device data from stat/device (contains per-WAN port info)."""
        try:
            r = self._request('get', f'/proxy/network/api/s/{self.site}/stat/device')
            if not r or r.status_code != 200:
                logger.warning('UniFi stat/device: HTTP %s', r.status_code if r else 'None')
                return None
            data = r.json()
            if data.get('meta', {}).get('rc') != 'ok':
                return None
            for dev in data.get('data', []):
                # Gateway device has wan1/wan2 keys
                if 'wan1' in dev or dev.get('type') == 'ugw':
                    return dev
            return None
        except Exception as e:
            logger.error('UniFi stat/device error: %s', e)
            return None

    def get_wan_details(self):
        """Return detailed WAN info including IPs and ISP/operator names.

        Combines data from stat/health (ISP info) and stat/device (per-WAN IPs).

        Returns dict like:
        {
            'WAN':  {'ip': '1.2.3.4', 'isp_name': 'Fiber ISP', 'isp_org': 'ISP Ltd', 'status': 'ok'},
            'WAN2': {'ip': '5.6.7.8', 'isp_name': '', 'isp_org': '', 'status': 'ok'},
        }
        """
        # Get health data (has ISP info but only for primary WAN subsystem)
        health = self._get_health()
        health_wan = {}
        for item in health:
            if item.get('subsystem', '') == 'wan':
                health_wan = item
                break

        # Get device data (has per-WAN IPs for all WANs)
        gw = self._get_gateway_device()

        wans = {}

        if gw:
            # Build WAN list from device wan1/wan2/... port data
            for key in sorted(gw.keys()):
                if not key.startswith('wan') or not isinstance(gw[key], dict):
                    continue
                port_data = gw[key]
                ip = port_data.get('ip', '')
                if not ip and not port_data.get('up', False):
                    continue  # Skip WANs that are down with no IP
                name = key.upper()  # wan1 -> WAN, wan2 -> WAN2
                if name == 'WAN1':
                    name = 'WAN'
                # ISP info from health is only available for the primary WAN subsystem
                # For WAN2+, ISP info isn't in the health data
                uptime_stats = health_wan.get('uptime_stats', {})
                wan_uptime = uptime_stats.get(name, {})
                wans[name] = {
                    'ip': ip,
                    'isp_name': health_wan.get('isp_name', '') if name == 'WAN' else '',
                    'isp_org': health_wan.get('isp_organization', '') if name == 'WAN' else '',
                    'status': 'ok' if port_data.get('up', False) else 'down',
                    'latency': wan_uptime.get('latency_average', ''),
                    'availability': wan_uptime.get('availability', ''),
                    'speed': port_data.get('speed', ''),
                    'uplink_ifname': port_data.get('uplink_ifname', port_data.get('ifname', '')),
                }
        elif health_wan:
            # Fallback: no device data, use health only (single WAN)
            wans['WAN'] = {
                'ip': health_wan.get('wan_ip', ''),
                'isp_name': health_wan.get('isp_name', ''),
                'isp_org': health_wan.get('isp_organization', ''),
                'status': health_wan.get('status', 'unknown'),
                'latency': '',
                'availability': '',
                'speed': '',
                'uplink_ifname': '',
            }

        # Resolve ISP info for WANs that don't have it (WAN2+ not in health data)
        for name, info in wans.items():
            if info['ip'] and not info['isp_name']:
                try:
                    r = requests.get(
                        f"http://ip-api.com/json/{info['ip']}?fields=isp,org",
                        timeout=5,
                    )
                    if r.status_code == 200:
                        d = r.json()
                        info['isp_name'] = d.get('isp', '')
                        info['isp_org'] = d.get('org', '')
                except Exception:
                    pass

        return wans

    def get_wan_ips(self):
        """Return simple dict of WAN IPs {name: ip} for backward compat."""
        details = self.get_wan_details()
        return {name: d['ip'] for name, d in details.items() if d['ip']}

    def is_connected(self):
        """Quick check if the session is still valid without forced re-login."""
        if not self._logged_in:
            return self._ensure_logged_in()
        # Try a light request to verify session
        try:
            r = self.session.get(
                f'{self.base_url}/proxy/network/api/s/{self.site}/stat/health',
                timeout=10,
            )
            if r.status_code == 200:
                return True
            if r.status_code in (401, 403):
                # Session expired or invalidated, try one re-login
                self._logged_in = False
                return self.login()
            return False
        except Exception:
            return False

    def logout(self):
        """Log out from the controller."""
        try:
            self.session.post(f'{self.base_url}/api/auth/logout', timeout=10)
        except Exception:
            pass
        self._logged_in = False


def get_unifi_client(force_new=False):
    """Get a cached UnifiClient, creating one if needed.

    Reuses the same session to avoid hitting the UDM login rate limit.
    Pass force_new=True when credentials change (e.g. saving new settings).
    """
    global _cached_client, _cached_config
    from database import get_db
    db = get_db()
    try:
        row = db.execute('SELECT * FROM unifi_settings WHERE id = 1').fetchone()
        if not row or not row['url'] or not row['username'] or not row['password']:
            _cached_client = None
            _cached_config = None
            return None
        config_key = (row['url'], row['username'], row['password'],
                      row['site_name'] or 'default', bool(row['verify_ssl']))

        if not force_new and _cached_client and _cached_config == config_key:
            return _cached_client

        _cached_client = UnifiClient(
            base_url=row['url'],
            username=row['username'],
            password=row['password'],
            site=row['site_name'] or 'default',
            verify_ssl=bool(row['verify_ssl']),
        )
        _cached_config = config_key
        return _cached_client
    except Exception:
        return None
    finally:
        db.close()


def clear_cached_client():
    """Clear the cached client (call when credentials change)."""
    global _cached_client, _cached_config
    if _cached_client:
        _cached_client.logout()
    _cached_client = None
    _cached_config = None
