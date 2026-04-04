# UpdateIP - Copyright (c) 2026 Juha Lempiäinen. All rights reserved.
# https://github.com/JuhaFIN1/Updateip

import sqlite3
import os

DB_PATH = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'updateip.db')


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    conn = get_db()
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            update_interval INTEGER NOT NULL DEFAULT 300,
            unifi_interval INTEGER NOT NULL DEFAULT 300,
            cloudflare_interval INTEGER NOT NULL DEFAULT 3600,
            npm_interval INTEGER NOT NULL DEFAULT 3600,
            current_ip TEXT DEFAULT '',
            timezone TEXT NOT NULL DEFAULT 'UTC'
        );

        CREATE TABLE IF NOT EXISTS cf_accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            api_token TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS cf_zones (
            id TEXT PRIMARY KEY,
            account_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            FOREIGN KEY (account_id) REFERENCES cf_accounts(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS cf_records (
            id TEXT PRIMARY KEY,
            zone_id TEXT NOT NULL,
            account_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            type TEXT NOT NULL,
            content TEXT DEFAULT '',
            proxied INTEGER DEFAULT 0,
            auto_update INTEGER DEFAULT 0,
            last_updated TIMESTAMP,
            last_status TEXT DEFAULT '',
            FOREIGN KEY (zone_id) REFERENCES cf_zones(id) ON DELETE CASCADE,
            FOREIGN KEY (account_id) REFERENCES cf_accounts(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS ip_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            old_ip TEXT,
            new_ip TEXT,
            changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS update_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            record_id TEXT,
            record_name TEXT,
            zone_name TEXT,
            old_ip TEXT,
            new_ip TEXT,
            status TEXT,
            message TEXT DEFAULT '',
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS npm_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            url TEXT NOT NULL DEFAULT '',
            email TEXT NOT NULL DEFAULT '',
            password TEXT NOT NULL DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS wan_interfaces (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            detect_method TEXT NOT NULL DEFAULT 'auto',
            static_ip TEXT DEFAULT '',
            current_ip TEXT DEFAULT '',
            unifi_wan_name TEXT DEFAULT '',
            isp_name TEXT DEFAULT '',
            last_checked TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS unifi_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            url TEXT NOT NULL DEFAULT '',
            username TEXT NOT NULL DEFAULT '',
            password TEXT NOT NULL DEFAULT '',
            site_name TEXT NOT NULL DEFAULT 'default',
            verify_ssl INTEGER NOT NULL DEFAULT 0
        );
    ''')
    # Migrate: add wan_id column to cf_records if missing
    cols = [r[1] for r in conn.execute("PRAGMA table_info(cf_records)").fetchall()]
    if 'wan_id' not in cols:
        conn.execute("ALTER TABLE cf_records ADD COLUMN wan_id INTEGER")
    # Migrate: add wan_id column to ip_log if missing
    cols = [r[1] for r in conn.execute("PRAGMA table_info(ip_log)").fetchall()]
    if 'wan_id' not in cols:
        conn.execute("ALTER TABLE ip_log ADD COLUMN wan_id INTEGER")
    # Ensure unifi_settings row exists
    if not conn.execute('SELECT id FROM unifi_settings WHERE id = 1').fetchone():
        conn.execute('INSERT INTO unifi_settings (id, url, username, password, site_name, verify_ssl) '
                     'VALUES (1, "", "", "", "default", 0)')
    # Migrate: add isp_name to wan_interfaces if missing
    cols = [r[1] for r in conn.execute("PRAGMA table_info(wan_interfaces)").fetchall()]
    if cols and 'isp_name' not in cols:
        conn.execute("ALTER TABLE wan_interfaces ADD COLUMN isp_name TEXT DEFAULT ''")
    # Ensure npm_settings row exists
    npm_row = conn.execute('SELECT id FROM npm_settings WHERE id = 1').fetchone()
    if not npm_row:
        conn.execute('INSERT INTO npm_settings (id, url, email, password) VALUES (1, "", "", "")')
    # Ensure settings row exists
    row = conn.execute('SELECT id FROM settings WHERE id = 1').fetchone()
    if not row:
        conn.execute('INSERT INTO settings (id, update_interval, unifi_interval, cloudflare_interval, npm_interval, current_ip, timezone) '
                     'VALUES (1, 300, 300, 3600, 3600, "", "UTC")')
    # Migrate: add sync interval columns to settings if missing
    cols = [r[1] for r in conn.execute("PRAGMA table_info(settings)").fetchall()]
    if 'unifi_interval' not in cols:
        conn.execute("ALTER TABLE settings ADD COLUMN unifi_interval INTEGER NOT NULL DEFAULT 300")
    if 'cloudflare_interval' not in cols:
        conn.execute("ALTER TABLE settings ADD COLUMN cloudflare_interval INTEGER NOT NULL DEFAULT 3600")
    if 'npm_interval' not in cols:
        conn.execute("ALTER TABLE settings ADD COLUMN npm_interval INTEGER NOT NULL DEFAULT 3600")
    # Migrate: add timezone to settings if missing
    cols = [r[1] for r in conn.execute("PRAGMA table_info(settings)").fetchall()]
    if 'timezone' not in cols:
        conn.execute("ALTER TABLE settings ADD COLUMN timezone TEXT NOT NULL DEFAULT 'UTC'")
    # Migrate: add mdns_hostname to settings if missing
    cols = [r[1] for r in conn.execute("PRAGMA table_info(settings)").fetchall()]
    if 'mdns_hostname' not in cols:
        conn.execute("ALTER TABLE settings ADD COLUMN mdns_hostname TEXT NOT NULL DEFAULT 'updateip'")
    conn.commit()
    conn.close()
