"""Container console defaults: root auto-login on the Proxmox console, apt never asks questions.

Idempotent; runs at every start so installs updated from an older version get it too.
Only acts inside an LXC container (systemd-detect-virt) as root.
"""
import os
import subprocess

_GETTY = ('[Service]\n'
          'ExecStart=\n'
          'ExecStart=-/sbin/agetty --autologin root --noclear --keep-baud pts/%I 115200,38400,9600 $TERM\n')
_APT = ('Dpkg::Options { "--force-confdef"; "--force-confold"; };\n'
        'APT::Get::Assume-Yes "true";\n')
_PROFILE = 'export DEBIAN_FRONTEND=noninteractive\n'
_MOTD = r'''# UpdateIP console banner (managed by UpdateIP)
case $- in *i*) ;; *) return 2>/dev/null ;; esac
[ -n "$UPDATEIP_MOTD" ] && return 2>/dev/null
export UPDATEIP_MOTD=1
. /etc/os-release 2>/dev/null
IP=$(hostname -I 2>/dev/null | awk '{print $1}')
VER=$(sed -n "s/^APP_VERSION *= *['\"]\([^'\"]*\).*/\1/p" /opt/updateip/config.py 2>/dev/null)
printf '\n\033[1;36m  UpdateIP\033[0m %s\n' "${VER:+v$VER}"
printf '  \033[1;33mOS:\033[0m        %s\n' "${PRETTY_NAME:-Linux}"
printf '  \033[1;33mHostname:\033[0m  %s\n' "$(hostname)"
printf '  \033[1;33mIP:\033[0m        %s\n' "${IP:-unknown}"
printf '  \033[1;32mWeb UI:\033[0m    http://%s\n' "${IP:-localhost}"
printf '  \033[1;32mUpdate:\033[0m    Settings -> Check for Updates in the web UI\n'
printf '  \033[1;32mDebian:\033[0m    apt update && apt upgrade  (never asks questions)\n\n'
'''


def _write(path, content):
    try:
        with open(path) as f:
            if f.read() == content:
                return False
    except OSError:
        pass
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        f.write(content)
    return True


def ensure_console_defaults():
    try:
        if os.geteuid() != 0:
            return
        r = subprocess.run(['systemd-detect-virt', '--container'], capture_output=True, text=True, timeout=5)
        if r.returncode != 0:
            return
        changed = False
        for n in (0, 1):
            changed |= _write(f'/etc/systemd/system/container-getty@{n}.service.d/autologin.conf', _GETTY)
        _write('/etc/apt/apt.conf.d/90-noninteractive', _APT)
        _write('/etc/profile.d/noninteractive.sh', _PROFILE)
        _write('/etc/profile.d/updateip-motd.sh', _MOTD)
        _write('/etc/motd', '')
        if changed:
            subprocess.run(['systemctl', 'daemon-reload'], timeout=15)
            for n in (0, 1):
                subprocess.run(['systemctl', 'try-restart', f'container-getty@{n}.service'], timeout=15)
    except Exception:
        pass
