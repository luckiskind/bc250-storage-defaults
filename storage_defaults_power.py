#!/usr/bin/python3
"""Persistent BC-250 NVMe policy; boot service owns a reversible runtime snapshot."""
import json, os, stat, sys
from pathlib import Path
CTRL = Path('/sys/class/nvme/nvme0')
QOS = CTRL / 'power/pm_qos_latency_tolerance_us'
STATE = Path('/run/bc250-storage-power.json')
TARGET = '5000'
MODEL = 'PNY CS2241 1TB SSD'

def info():
    return {'model': (CTRL / 'model').read_text().strip(), 'link_speed': (CTRL / 'device/current_link_speed').read_text().strip(), 'link_width': (CTRL / 'device/current_link_width').read_text().strip(), 'latency_tolerance_us': QOS.read_text().strip()}

def main():
    action = sys.argv[1] if len(sys.argv) > 1 else 'status'
    if action not in ('status', 'apply', 'restore'):
        raise RuntimeError('Expected status, apply or restore')
    current = info()
    if action == 'status':
        print(json.dumps(current))
        return
    if os.geteuid() != 0:
        raise RuntimeError('Run apply/restore as root')
    if not (current['model'] == MODEL and current['link_width'] == '2' and current['link_speed'].startswith('5.0 GT/s')):
        raise RuntimeError(current)
    saved = None
    if STATE.exists() or STATE.is_symlink():
        s = STATE.lstat()
        if not (stat.S_ISREG(s.st_mode) and s.st_uid == 0 and (s.st_mode & 0o077 == 0)):
            raise RuntimeError('Safety check failed')
        saved = json.loads(STATE.read_text())
        if not (saved['model'] == MODEL and saved['target'] == TARGET):
            raise RuntimeError('Safety check failed')
        if not saved['original'].isdigit():
            raise RuntimeError('Safety check failed')
    if action == 'apply':
        if saved is None:
            if current['latency_tolerance_us'] == TARGET:
                raise RuntimeError('Cap already owned by another policy')
            if not current['latency_tolerance_us'].isdigit():
                raise RuntimeError('Unsupported original drive tolerance; no change made')
            saved = {'model': MODEL, 'target': TARGET, 'original': current['latency_tolerance_us']}
            fd = os.open(STATE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'w') as f:
                json.dump(saved, f)
                f.flush()
                os.fsync(f.fileno())
        if current['latency_tolerance_us'] not in (TARGET, saved['original']):
            raise RuntimeError('Another policy changed the cap')
        QOS.write_text(TARGET)
        if QOS.read_text().strip() != TARGET:
            raise RuntimeError('Safety check failed')
    elif saved is not None:
        if current['latency_tolerance_us'] not in (TARGET, saved['original']):
            raise RuntimeError('Another policy changed the cap; state retained')
        QOS.write_text(saved['original'])
        if QOS.read_text().strip() != saved['original']:
            raise RuntimeError('Safety check failed')
        STATE.unlink()
    print(json.dumps({'action': action, **info()}))
if __name__ == '__main__':
    main()
