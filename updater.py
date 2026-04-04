# UpdateIP - Copyright (c) 2026 Juha Lempiäinen. All rights reserved.
# https://github.com/JuhaFIN1/Updateip

import logging
from datetime import datetime, timezone
from database import get_db
from cloudflare_api import get_public_ip, update_dns_record

logger = logging.getLogger(__name__)


def _resolve_wan_ips(wans):
    """Resolve IPs for all WAN interfaces.

    Returns dict {wan_id: ip_string}.
    """
    wan_ips = {}
    unifi_ips = None  # lazy-loaded

    for wan in wans:
        method = wan['detect_method']

        if method == 'unifi':
            if unifi_ips is None:
                unifi_ips = _fetch_unifi_wan_ips()
            ip = unifi_ips.get(wan['unifi_wan_name'] or '', '')
        elif method == 'static':
            ip = wan['static_ip'] or ''
        else:  # auto
            ip = get_public_ip() or ''

        if ip:
            wan_ips[wan['id']] = ip

    return wan_ips


def _fetch_unifi_wan_ips():
    """Get WAN IPs from UniFi controller."""
    try:
        from unifi_api import get_unifi_client
        client = get_unifi_client()
        if client:
            return client.get_wan_ips()
    except Exception as e:
        logger.error('Failed to fetch UniFi WAN IPs: %s', e)
    return {}


def check_and_update_ip(force=False):
    """Check public IP(s) and update Cloudflare records if changed or forced.

    Multi-WAN: each WAN interface resolves its own IP (auto/static/unifi).
    Each DNS record can be assigned to a specific WAN. Unassigned records
    use the auto-detected default IP.
    """
    db = get_db()
    try:
        wans = db.execute('SELECT * FROM wan_interfaces').fetchall()
        wan_ips = _resolve_wan_ips(wans) if wans else {}
        auto_ip = get_public_ip()

        ip_changed_any = False

        # Update per-WAN IPs
        for wan in wans:
            new_ip = wan_ips.get(wan['id'], '')
            if not new_ip:
                continue
            old_ip = wan['current_ip'] or ''
            if new_ip != old_ip:
                ip_changed_any = True
                db.execute('INSERT INTO ip_log (old_ip, new_ip, wan_id) VALUES (?, ?, ?)',
                           (old_ip, new_ip, wan['id']))
                db.execute('UPDATE wan_interfaces SET current_ip = ?, last_checked = CURRENT_TIMESTAMP WHERE id = ?',
                           (new_ip, wan['id']))
                logger.info('WAN "%s" IP changed: %s -> %s', wan['name'], old_ip, new_ip)
            else:
                db.execute('UPDATE wan_interfaces SET last_checked = CURRENT_TIMESTAMP WHERE id = ?',
                           (wan['id'],))

        # Legacy settings.current_ip
        settings = db.execute('SELECT current_ip FROM settings WHERE id = 1').fetchone()
        old_settings_ip = settings['current_ip'] if settings else ''
        if auto_ip and auto_ip != old_settings_ip:
            if not wans:
                db.execute('INSERT INTO ip_log (old_ip, new_ip) VALUES (?, ?)',
                           (old_settings_ip, auto_ip))
            db.execute('UPDATE settings SET current_ip = ? WHERE id = 1', (auto_ip,))
            ip_changed_any = True
            logger.info('Public IP changed: %s -> %s', old_settings_ip, auto_ip)

        if not auto_ip and not wan_ips:
            db.commit()
            return {'success': False, 'message': 'Could not determine public IP'}

        db.commit()

        # Update DNS records
        records = db.execute('''
            SELECT r.id, r.zone_id, r.name, r.content, r.proxied,
                   r.account_id, r.wan_id,
                   a.api_token, z.name as zone_name
            FROM cf_records r
            JOIN cf_accounts a ON r.account_id = a.id
            JOIN cf_zones z ON r.zone_id = z.id
            WHERE r.auto_update = 1
        ''').fetchall()

        updated = 0
        errors = 0
        now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        for rec in records:
            if rec['wan_id']:
                if rec['wan_id'] in wan_ips:
                    target_ip = wan_ips[rec['wan_id']]
                else:
                    # WAN-specific record but that WAN's IP is unavailable — skip
                    # to avoid overwriting with the wrong WAN's IP
                    logger.warning('Skipping %s: WAN id %s IP not available', rec['name'], rec['wan_id'])
                    db.execute('''
                        INSERT INTO update_log (record_id, record_name, zone_name, old_ip, new_ip, status, message)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (rec['id'], rec['name'], rec['zone_name'], rec['content'], rec['content'],
                          'skipped', f'WAN id {rec["wan_id"]} IP not available'))
                    continue
            elif auto_ip:
                target_ip = auto_ip
            else:
                continue

            if rec['content'] == target_ip and not force:
                # Already correct — mark as current
                db.execute('UPDATE cf_records SET last_updated = ?, last_status = ? WHERE id = ?',
                           (now, 'success', rec['id']))
                db.execute('''
                    INSERT INTO update_log (record_id, record_name, zone_name, old_ip, new_ip, status, message)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (rec['id'], rec['name'], rec['zone_name'], rec['content'], target_ip, 'no_change', 'IP unchanged'))
                continue

            success, msg = update_dns_record(
                rec['api_token'], rec['zone_id'], rec['id'],
                rec['name'], target_ip, bool(rec['proxied'])
            )
            status = 'changed' if success else 'error'
            db.execute('''
                INSERT INTO update_log (record_id, record_name, zone_name, old_ip, new_ip, status, message)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (rec['id'], rec['name'], rec['zone_name'], rec['content'], target_ip, status, msg))
            if success:
                db.execute('UPDATE cf_records SET content = ?, last_updated = ?, last_status = ? WHERE id = ?',
                           (target_ip, now, 'success', rec['id']))
                updated += 1
            else:
                db.execute('UPDATE cf_records SET last_status = ? WHERE id = ?', ('error: ' + msg, rec['id']))
                errors += 1

        db.commit()
        return {
            'success': True,
            'message': f'IP: {auto_ip or "N/A"}. Updated: {updated}, Errors: {errors}',
            'ip': auto_ip or '',
            'updated': updated,
            'errors': errors,
            'ip_changed': ip_changed_any
        }
    except Exception as e:
        logger.error(f'Update error: {e}')
        return {'success': False, 'message': str(e)}
    finally:
        db.close()
