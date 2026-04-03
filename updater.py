import logging
from datetime import datetime, timezone
from database import get_db
from cloudflare_api import get_public_ip, update_dns_record

logger = logging.getLogger(__name__)


def check_and_update_ip(force=False):
    """Check public IP and update Cloudflare records if changed or forced."""
    db = get_db()
    try:
        new_ip = get_public_ip()
        if not new_ip:
            logger.warning('Could not determine public IP')
            return {'success': False, 'message': 'Could not determine public IP'}

        settings = db.execute('SELECT current_ip FROM settings WHERE id = 1').fetchone()
        old_ip = settings['current_ip'] if settings else ''
        ip_changed = (new_ip != old_ip)

        if ip_changed:
            db.execute('INSERT INTO ip_log (old_ip, new_ip) VALUES (?, ?)', (old_ip, new_ip))
            db.execute('UPDATE settings SET current_ip = ? WHERE id = 1', (new_ip,))
            db.commit()
            logger.info(f'IP changed: {old_ip} -> {new_ip}')

        if not ip_changed and not force:
            return {'success': True, 'message': 'IP unchanged', 'ip': new_ip, 'updated': 0}

        # Get all records marked for auto-update
        records = db.execute('''
            SELECT r.id, r.zone_id, r.name, r.content, r.proxied, r.account_id,
                   a.api_token, z.name as zone_name
            FROM cf_records r
            JOIN cf_accounts a ON r.account_id = a.id
            JOIN cf_zones z ON r.zone_id = z.id
            WHERE r.auto_update = 1
        ''').fetchall()

        updated = 0
        errors = 0
        for rec in records:
            if rec['content'] == new_ip and not force:
                continue
            success, msg = update_dns_record(
                rec['api_token'], rec['zone_id'], rec['id'],
                rec['name'], new_ip, bool(rec['proxied'])
            )
            status = 'success' if success else 'error'
            db.execute('''
                INSERT INTO update_log (record_id, record_name, zone_name, old_ip, new_ip, status, message)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (rec['id'], rec['name'], rec['zone_name'], rec['content'], new_ip, status, msg))
            if success:
                now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
                db.execute('UPDATE cf_records SET content = ?, last_updated = ?, last_status = ? WHERE id = ?',
                           (new_ip, now, 'success', rec['id']))
                updated += 1
            else:
                db.execute('UPDATE cf_records SET last_status = ? WHERE id = ?', ('error: ' + msg, rec['id']))
                errors += 1

        db.commit()
        return {
            'success': True,
            'message': f'IP: {new_ip}. Updated: {updated}, Errors: {errors}',
            'ip': new_ip,
            'updated': updated,
            'errors': errors,
            'ip_changed': ip_changed
        }
    except Exception as e:
        logger.error(f'Update error: {e}')
        return {'success': False, 'message': str(e)}
    finally:
        db.close()
