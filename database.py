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
            current_ip TEXT DEFAULT ''
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
    ''')
    # Ensure npm_settings row exists
    npm_row = conn.execute('SELECT id FROM npm_settings WHERE id = 1').fetchone()
    if not npm_row:
        conn.execute('INSERT INTO npm_settings (id, url, email, password) VALUES (1, "", "", "")')
    # Ensure settings row exists
    row = conn.execute('SELECT id FROM settings WHERE id = 1').fetchone()
    if not row:
        conn.execute('INSERT INTO settings (id, update_interval, current_ip) VALUES (1, 300, "")')
    conn.commit()
    conn.close()
