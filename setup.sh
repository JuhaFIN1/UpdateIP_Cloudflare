#!/usr/bin/env bash
set -e

APP_DIR="/root/Updateip"
VENV_DIR="$APP_DIR/venv"
SERVICE_FILE="/etc/systemd/system/updateip.service"
NGINX_CONF="/etc/nginx/sites-available/updateip"

echo "=== UpdateIP Setup ==="

# 1. Create virtual environment
echo "[1/5] Creating Python virtual environment..."
python3 -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"

# 2. Install dependencies
echo "[2/5] Installing Python dependencies..."
pip install --upgrade pip
pip install -r "$APP_DIR/requirements.txt"

# 3. Initialize database
echo "[3/5] Initializing database..."
cd "$APP_DIR"
python3 -c "from database import init_db; init_db()"

# 4. Create systemd service
echo "[4/5] Creating systemd service..."
cat > "$SERVICE_FILE" << 'EOF'
[Unit]
Description=UpdateIP - Cloudflare DNS Updater
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/Updateip
ExecStart=/root/Updateip/venv/bin/gunicorn --bind 127.0.0.1:5000 --workers 1 --threads 2 --timeout 120 wsgi:app
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable updateip.service
systemctl restart updateip.service

# 5. Configure Nginx reverse proxy (port 80 -> 5000)
echo "[5/5] Configuring Nginx reverse proxy..."
cat > "$NGINX_CONF" << 'EOF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 120s;
    }
}
EOF

# Enable site, remove default if exists
rm -f /etc/nginx/sites-enabled/default
ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/updateip
nginx -t
systemctl enable nginx
systemctl restart nginx

echo ""
echo "=== Setup Complete ==="
echo "  App running on port 5000 (gunicorn)"
echo "  Nginx proxying port 80 -> 5000"
echo "  Default login: admin / admin"
echo "  Service: systemctl status updateip"
echo ""
