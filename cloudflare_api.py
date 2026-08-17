# UpdateIP - Copyright (c) 2026 BluexDEV Softwares. All rights reserved.
# https://github.com/JuhaFIN1/Updateip

import requests
import logging
import time

logger = logging.getLogger(__name__)

CF_API_BASE = 'https://api.cloudflare.com/client/v4'


def _headers(api_token):
    return {
        'Authorization': f'Bearer {api_token}',
        'Content-Type': 'application/json',
    }


def _get_with_retry(url, headers, params=None, timeout=15, max_attempts=3):
    """GET against the Cloudflare API with retries on transient failures only
    (network errors, 429 rate-limit, 5xx). Non-transient failures (4xx auth/
    permission errors) return immediately since retrying them can't help."""
    last_exc = None
    for attempt in range(1, max_attempts + 1):
        try:
            r = requests.get(url, headers=headers, params=params, timeout=timeout)
        except requests.exceptions.RequestException as e:
            last_exc = e
            if attempt < max_attempts:
                time.sleep(2 ** (attempt - 1))
                continue
            raise
        if (r.status_code == 429 or r.status_code >= 500) and attempt < max_attempts:
            time.sleep(2 ** (attempt - 1))
            continue
        return r
    raise last_exc


def verify_token(api_token):
    """Verify that a Cloudflare API token is valid."""
    try:
        r = requests.get(f'{CF_API_BASE}/user/tokens/verify',
                         headers=_headers(api_token), timeout=15)
        data = r.json()
        return data.get('success', False)
    except Exception as e:
        logger.error(f'Token verification failed: {e}')
        return False


def list_zones(api_token):
    """Return list of zones accessible with this token, or None if the
    request could not be completed (network error / API failure). Callers
    must treat None as 'unknown state' and not as 'zero zones'."""
    zones = []
    page = 1
    while True:
        try:
            r = _get_with_retry(f'{CF_API_BASE}/zones',
                                headers=_headers(api_token),
                                params={'page': page, 'per_page': 50},
                                timeout=15)
            data = r.json()
        except Exception as e:
            logger.error(f'Failed to list zones: {e}')
            return None
        if not data.get('success'):
            logger.error(f'Failed to list zones: {data.get("errors")}')
            return None
        zones.extend(data.get('result', []))
        total_pages = data.get('result_info', {}).get('total_pages', 1)
        if page >= total_pages:
            break
        page += 1
    return zones


def list_dns_records(api_token, zone_id, record_type='A'):
    """Return list of DNS records for a zone, or None if the request could
    not be completed (network error / API failure). Pass record_type=None
    to get all types. Callers must treat None as 'unknown state' and not
    as 'zero records' — conflating the two causes local records to be
    deleted whenever Cloudflare is unreachable."""
    records = []
    page = 1
    while True:
        try:
            params = {'page': page, 'per_page': 100}
            if record_type:
                params['type'] = record_type
            r = _get_with_retry(f'{CF_API_BASE}/zones/{zone_id}/dns_records',
                                headers=_headers(api_token),
                                params=params,
                                timeout=15)
            data = r.json()
        except Exception as e:
            logger.error(f'Failed to list DNS records: {e}')
            return None
        if not data.get('success'):
            logger.error(f'Failed to list DNS records: {data.get("errors")}')
            return None
        records.extend(data.get('result', []))
        total_pages = data.get('result_info', {}).get('total_pages', 1)
        if page >= total_pages:
            break
        page += 1
    return records


def update_dns_record(api_token, zone_id, record_id, name, content, proxied=False, record_type='A', ttl=1, priority=None):
    """Update a DNS record."""
    try:
        payload = {
            'type': record_type,
            'name': name,
            'content': content,
            'proxied': proxied,
            'ttl': ttl,
        }
        if priority is not None and record_type == 'MX':
            payload['priority'] = priority
        r = requests.put(
            f'{CF_API_BASE}/zones/{zone_id}/dns_records/{record_id}',
            headers=_headers(api_token),
            json=payload,
            timeout=15
        )
        data = r.json()
        if data.get('success'):
            return True, 'Updated successfully'
        else:
            errors = data.get('errors', [])
            msg = errors[0].get('message', 'Unknown error') if errors else 'Unknown error'
            return False, msg
    except Exception as e:
        logger.error(f'Failed to update DNS record {record_id}: {e}')
        return False, str(e)


def create_dns_record(api_token, zone_id, record_type, name, content, proxied=False, ttl=1, priority=None):
    """Create a new DNS record in a zone."""
    try:
        payload = {
            'type': record_type,
            'name': name,
            'content': content,
            'proxied': proxied,
            'ttl': ttl,
        }
        if priority is not None and record_type == 'MX':
            payload['priority'] = priority
        r = requests.post(
            f'{CF_API_BASE}/zones/{zone_id}/dns_records',
            headers=_headers(api_token),
            json=payload,
            timeout=15
        )
        data = r.json()
        if data.get('success'):
            return True, data['result']
        else:
            errors = data.get('errors', [])
            msg = errors[0].get('message', 'Unknown error') if errors else 'Unknown error'
            return False, msg
    except Exception as e:
        logger.error(f'Failed to create DNS record: {e}')
        return False, str(e)


def delete_dns_record(api_token, zone_id, record_id):
    """Delete a DNS record from a zone."""
    try:
        r = requests.delete(
            f'{CF_API_BASE}/zones/{zone_id}/dns_records/{record_id}',
            headers=_headers(api_token),
            timeout=15
        )
        data = r.json()
        if data.get('success'):
            return True, 'Deleted successfully'
        else:
            errors = data.get('errors', [])
            msg = errors[0].get('message', 'Unknown error') if errors else 'Unknown error'
            return False, msg
    except Exception as e:
        logger.error(f'Failed to delete DNS record {record_id}: {e}')
        return False, str(e)


def get_public_ip():
    """Get the current public IP address."""
    services = [
        'https://api.ipify.org',
        'https://ifconfig.me/ip',
        'https://icanhazip.com',
        'https://checkip.amazonaws.com',
    ]
    for url in services:
        try:
            r = requests.get(url, timeout=10)
            if r.status_code == 200:
                ip = r.text.strip()
                if ip:
                    return ip
        except Exception:
            continue
    return None
