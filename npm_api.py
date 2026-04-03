import requests
import logging

logger = logging.getLogger(__name__)


class NpmClient:
    """Client for Nginx Proxy Manager API."""

    def __init__(self, url, email, password):
        self.base_url = url.rstrip('/')
        self.email = email
        self.password = password
        self.token = None

    def _authenticate(self):
        """Get JWT token from NPM."""
        try:
            r = requests.post(
                f'{self.base_url}/api/tokens',
                json={'identity': self.email, 'secret': self.password},
                timeout=15
            )
            if r.status_code == 200:
                data = r.json()
                self.token = data.get('token')
                return True
            logger.error(f'NPM auth failed: {r.status_code} {r.text}')
            return False
        except Exception as e:
            logger.error(f'NPM auth error: {e}')
            return False

    def _headers(self):
        return {'Authorization': f'Bearer {self.token}', 'Content-Type': 'application/json'}

    def _request(self, method, path, **kwargs):
        """Make authenticated request, auto-retry auth once."""
        if not self.token:
            if not self._authenticate():
                return None
        kwargs.setdefault('timeout', 15)
        kwargs['headers'] = self._headers()
        r = requests.request(method, f'{self.base_url}{path}', **kwargs)
        if r.status_code == 401:
            if self._authenticate():
                kwargs['headers'] = self._headers()
                r = requests.request(method, f'{self.base_url}{path}', **kwargs)
        return r

    def test_connection(self):
        """Test if we can connect and authenticate."""
        return self._authenticate()

    # ------------------------------------------------------------------
    # Proxy Hosts
    # ------------------------------------------------------------------

    def list_proxy_hosts(self):
        r = self._request('GET', '/api/nginx/proxy-hosts')
        if r and r.status_code == 200:
            return r.json()
        return []

    def get_proxy_host(self, host_id):
        r = self._request('GET', f'/api/nginx/proxy-hosts/{host_id}')
        if r and r.status_code == 200:
            return r.json()
        return None

    def create_proxy_host(self, data):
        r = self._request('POST', '/api/nginx/proxy-hosts', json=data)
        if r and r.status_code in (200, 201):
            return True, r.json()
        msg = r.json().get('error', {}).get('message', r.text) if r else 'Connection failed'
        return False, msg

    def update_proxy_host(self, host_id, data):
        r = self._request('PUT', f'/api/nginx/proxy-hosts/{host_id}', json=data)
        if r and r.status_code == 200:
            return True, r.json()
        msg = r.json().get('error', {}).get('message', r.text) if r else 'Connection failed'
        return False, msg

    def delete_proxy_host(self, host_id):
        r = self._request('DELETE', f'/api/nginx/proxy-hosts/{host_id}')
        if r and r.status_code == 200:
            return True, 'Deleted'
        msg = r.text if r else 'Connection failed'
        return False, msg

    # ------------------------------------------------------------------
    # SSL Certificates (for dropdown)
    # ------------------------------------------------------------------

    def list_certificates(self):
        r = self._request('GET', '/api/nginx/certificates')
        if r and r.status_code == 200:
            return r.json()
        return []

    # ------------------------------------------------------------------
    # Access Lists (for dropdown)
    # ------------------------------------------------------------------

    def list_access_lists(self):
        r = self._request('GET', '/api/nginx/access-lists')
        if r and r.status_code == 200:
            return r.json()
        return []


def get_npm_client():
    """Create NPM client from stored settings."""
    from database import get_db
    db = get_db()
    row = db.execute('SELECT * FROM npm_settings WHERE id = 1').fetchone()
    db.close()
    if not row or not row['url'] or not row['email']:
        return None
    return NpmClient(row['url'], row['email'], row['password'])
