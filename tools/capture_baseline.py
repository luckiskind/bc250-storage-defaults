#!/usr/bin/env python3
"""Read-only, privacy-limited BC-250 storage baseline capture; JSON goes to stdout."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import sqlite3
import subprocess
import sys
import time

UNITS = ('bc250-nvme-power.service', 'bc250-btrfs-repack.service', 'bc250-btrfs-repack.timer')
INSTALLED = (
    '/usr/local/libexec/bc250-storage-defaults/storage_defaults_power.py',
    '/usr/local/libexec/bc250-storage-defaults/storage_defaults_repack.py',
    '/etc/bc250-storage-defaults.json',
    '/etc/systemd/system/bc250-nvme-power.service',
    '/etc/systemd/system/bc250-btrfs-repack.service',
    '/etc/systemd/system/bc250-btrfs-repack.timer',
    '/usr/lib/systemd/system-sleep/90-bc250-nvme-power',
)
STATE = '/var/lib/bc250-storage-defaults'
CONFIG_FLAGS = ('CONFIG_BTRFS_FS', 'CONFIG_EROFS_FS', 'CONFIG_EROFS_FS_ZIP', 'CONFIG_BPF',
                'CONFIG_BPF_SYSCALL', 'CONFIG_BPF_EVENTS', 'CONFIG_FTRACE', 'CONFIG_BLK_DEV_LOOP',
                'CONFIG_USER_NS', 'CONFIG_MEMCG', 'CONFIG_KVM', 'CONFIG_KVM_AMD')


class Reader:
    def __init__(self, root=Path('/')):
        self.root = root

    def path(self, name):
        return self.root / name.lstrip('/')

    def text(self, name):
        try:
            return self.path(name).read_text().strip()
        except (OSError, UnicodeError):
            return None

    def json(self, name):
        value = self.text(name)
        try:
            return json.loads(value) if value is not None else None
        except ValueError:
            return None

    def exists(self, name):
        try:
            self.path(name).stat()
            return True
        except FileNotFoundError:
            return False
        except OSError:
            return None


def command(args):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=15)
        return result.stdout.strip() if result.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


def sanitize_mount(data):
    """Keep the selected device and policy, never arbitrary subvolume/user paths."""
    if not data or not data.get('filesystems'):
        return None
    mount = data['filesystems'][0]
    source = str(mount.get('source', '')).split('[', 1)[0]
    if not re.fullmatch(r'/dev/[a-zA-Z0-9_./+-]+', source):
        source = '<non-device-source>'
    allowed = ('rw', 'ro', 'noatime', 'relatime', 'atime', 'compress', 'compress-force',
               'ssd', 'nossd', 'discard', 'space_cache', 'autodefrag', 'nodatacow', 'nodatasum', 'commit')
    options = [v for v in str(mount.get('options', '')).split(',') if v.split('=', 1)[0] in allowed]
    return dict(source=source, fstype=mount.get('fstype'), options=options)


def audit_installation(reader):
    manifest = reader.json(STATE + '/installation.json')
    answer = dict(manifest_readable=manifest is not None,
                  stop_marker=reader.exists(STATE + '/STOP'), installed_files={})
    for name in INSTALLED:
        path = reader.path(name)
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            expected = manifest.get('installed_sha256', {}).get(name) if manifest else None
            answer['installed_files'][name] = dict(sha256=digest, matches_manifest=digest == expected if expected else None)
        except OSError:
            answer['installed_files'][name] = dict(readable=False)
    last = reader.json(STATE + '/last-run.json')
    if isinstance(last, dict):
        answer['last_run'] = {k: last[k] for k in ('started', 'finished', 'dry_run', 'counts', 'processed_bytes',
                              'charged_bytes', 'retry_bytes', 'verified_files') if k in last}
    config = reader.json('/etc/bc250-storage-defaults.json')
    if isinstance(config, dict):
        # No arbitrary roots/excluded paths: those may identify a user or application.
        answer['policy_limits'] = {k: config[k] for k in ('min_file_bytes', 'max_file_bytes', 'quiet_seconds',
                  'max_bytes_per_run', 'max_bytes_per_day', 'reserve_free_bytes', 'max_run_seconds',
                  'max_load', 'sample_max_stored_ratio') if k in config}
    try:
        uri = reader.path(STATE + '/state.sqlite3').resolve().as_uri() + '?mode=ro'
        with sqlite3.connect(uri, uri=True, timeout=2) as db:
            answer['ledger'] = dict(status_counts=dict(db.execute('SELECT status,COUNT(*) FROM files GROUP BY status')),
                                    daily_charged_bytes=dict(db.execute('SELECT day,bytes FROM budget ORDER BY day')))
            tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if 'attempts' in tables:
                answer['ledger']['attempt_status_counts'] = dict(db.execute('SELECT status,COUNT(*) FROM attempts GROUP BY status'))
    except (OSError, sqlite3.Error):
        answer['ledger'] = dict(readable=False)
    return answer


def collect(reader=None, runner=command):
    reader = reader or Reader()
    cpu = reader.text('/proc/cpuinfo') or ''
    model = re.search(r'^model name\s*:\s*(.*)$', cpu, re.M)
    memory = reader.text('/proc/meminfo') or ''
    memory_fields = {}
    for line in memory.splitlines():
        key, _, value = line.partition(':')
        if key in ('MemTotal', 'MemAvailable', 'SwapTotal', 'SwapFree', 'Cached', 'Dirty', 'Writeback'):
            memory_fields[key] = value.strip()
    result = dict(schema_version=1, collector_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  captured_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                  kernel=reader.text('/proc/sys/kernel/osrelease'), architecture=platform.machine(),
                  cpu_model=model.group(1) if model else None, logical_cpus=cpu.count('processor\t:'),
                  memory=memory_fields, load_average=(reader.text('/proc/loadavg') or '').split()[:3],
                  pressure={kind: reader.text('/proc/pressure/' + kind) for kind in ('cpu', 'io', 'memory')},
                  nvme={}, block_devices={}, graphics_memory={}, temperatures_millicelsius={},
                  mounts={}, units={}, installation=audit_installation(reader))
    nvme = reader.path('/sys/class/nvme')
    for controller in sorted(nvme.glob('nvme*')) if nvme.exists() else []:
        if not re.fullmatch(r'nvme\d+', controller.name):
            continue
        prefix = '/sys/class/nvme/' + controller.name
        result['nvme'][controller.name] = {key: reader.text(prefix + '/' + name) for key, name in (
            ('model', 'model'), ('firmware', 'firmware_rev'), ('link_speed', 'device/current_link_speed'),
            ('link_width', 'device/current_link_width'), ('latency_tolerance_us', 'power/pm_qos_latency_tolerance_us'))}
    sysblock = reader.path('/sys/class/block')
    for disk in sorted(sysblock.glob('*')) if sysblock.exists() else []:
        if not re.fullmatch(r'nvme\d+n\d+(p\d+)?', disk.name):
            continue
        prefix = '/sys/class/block/' + disk.name
        result['block_devices'][disk.name] = {key: reader.text(prefix + '/' + name) for key, name in (
            ('major_minor', 'dev'), ('sectors_512b', 'size'), ('partition', 'partition'),
            ('scheduler', 'queue/scheduler'), ('read_ahead_kb', 'queue/read_ahead_kb'),
            ('nr_requests', 'queue/nr_requests'), ('max_sectors_kb', 'queue/max_sectors_kb'))}
    for target in ('/', '/usr', '/home', '/var/lib'):
        raw = runner(['findmnt', '--json', '-o', 'SOURCE,FSTYPE,OPTIONS', '--target', target])
        try:
            result['mounts'][target] = sanitize_mount(json.loads(raw)) if raw else None
        except ValueError:
            result['mounts'][target] = None
    for unit in UNITS:
        raw = runner(['systemctl', 'show', unit, '-p', 'LoadState', '-p', 'UnitFileState', '-p', 'ActiveState',
                      '-p', 'SubState', '-p', 'Result', '-p', 'ExecMainCode', '-p', 'ExecMainStatus', '-p', 'MemoryPeak'])
        result['units'][unit] = dict(line.split('=', 1) for line in (raw or '').splitlines() if '=' in line)
    try:
        with gzip.open(reader.path('/proc/config.gz'), 'rt') as stream:
            lines = stream.read().splitlines()
        result['kernel_features'] = {key: next((line.split('=', 1)[1] for line in lines if line.startswith(key + '=')), None)
                                     for key in CONFIG_FLAGS}
    except OSError:
        result['kernel_features'] = dict(available=False)
    # Static event names only. Never capture task names, command lines, filenames or trace data.
    events = reader.text('/sys/kernel/tracing/available_events')
    result['trace_events'] = sorted(v for v in (events or '').splitlines()
                                     if v.startswith(('block:block_rq_', 'btrfs:btrfs_sync_file', 'filemap:mm_filemap_',
                                                      'sched:sched_switch', 'exceptions:page_fault_')))
    result['isolation'] = dict(user_namespace_enabled=reader.text('/proc/sys/user/max_user_namespaces'),
                              kvm_present=reader.path('/dev/kvm').exists())
    drm = reader.path('/sys/class/drm')
    for card in sorted(drm.glob('card*')) if drm.exists() else []:
        if re.fullmatch(r'card\d+', card.name):
            prefix = '/sys/class/drm/' + card.name + '/device/'
            result['graphics_memory'][card.name] = {k: reader.text(prefix + k) for k in
                ('mem_info_vram_total', 'mem_info_vis_vram_total', 'mem_info_gtt_total')}
    sensors = reader.path('/sys/class/hwmon')
    for sensor in sorted(sensors.glob('hwmon*')) if sensors.exists() else []:
        prefix = '/sys/class/hwmon/' + sensor.name
        name = reader.text(prefix + '/name')
        if name not in ('amdgpu', 'nvme', 'k10temp'):
            continue
        result['temperatures_millicelsius'][sensor.name + ':' + name] = {
            value.name: reader.text(prefix + '/' + value.name) for value in sensor.glob('temp*_input')
            if re.fullmatch(r'temp\d+_input', value.name)}
    return result


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    print(json.dumps(collect(), indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
