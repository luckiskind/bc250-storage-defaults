#!/usr/bin/env python3
"""Run the real installer in a disposable bubblewrap root with fake sysfs/systemctl.

Requires Linux, bwrap, writable Btrfs scratch space and unprivileged user namespaces.
Host /usr is mounted read-only; systemctl, sysfs, state, hooks and config are private.
This checks installer file operations and real Btrfs ioctls, not actual systemd boot.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]

SHIM = '''#!/usr/bin/python3
import json,os,subprocess,sys
from pathlib import Path
p=Path('/run/fake-systemctl.json')
s=json.loads(p.read_text()) if p.exists() else {'enabled':[], 'calls':[]}
a=sys.argv[1:];s['calls'].append(a)
p.write_text(json.dumps(s))
power='bc250-nvme-power.service';timer='bc250-btrfs-repack.timer';worker='bc250-btrfs-repack.service'
helper='/usr/local/libexec/bc250-storage-defaults/storage_defaults_power.py'
def invoke(action):subprocess.run(['/usr/bin/python3',helper,action],check=True)
if a==['daemon-reload']:pass
elif len(a)==3 and a[:2]==['enable','--now'] and a[2] in (power,timer):
    if a[2] not in s['enabled']:s['enabled'].append(a[2])
    p.write_text(json.dumps(s))
    if a[2]==timer and os.environ.get('TEST_FAIL_ENABLE_TIMER')=='1':raise SystemExit('injected enable failure after symlink')
    if a[2]==power:invoke('apply')
elif len(a)==3 and a[:2]==['disable','--now'] and a[2] in (power,timer):
    if a[2] in s['enabled']:s['enabled'].remove(a[2])
    if a[2]==power:invoke('restore')
elif a==['stop',worker]:pass
elif a==['stop',power]:invoke('restore')
elif a==['start',power]:invoke('apply')
elif a==['is-enabled','--quiet',power]:raise SystemExit(0 if power in s['enabled'] else 1)
else:raise SystemExit('unexpected isolated systemctl command: '+repr(a))
p.write_text(json.dumps(s))
'''

INSIDE = '''import hashlib,json,os,subprocess
from pathlib import Path
qos=Path('/sys/class/nvme/nvme0/power/pm_qos_latency_tolerance_us')
manifest=Path('/var/lib/bc250-storage-defaults/installation.json')
def run(*args,ok=True,env=None):
    p=subprocess.run(['/usr/bin/python3','/pkg/install.py',*args],capture_output=True,text=True,env=env)
    if (p.returncode==0)!=ok:raise RuntimeError(p.stdout+p.stderr)
    return p
run('--check')
run()
assert qos.read_text()=='5000'
assert json.loads(manifest.read_text())['disposable_validation']['layout_target_met']
first=manifest.read_bytes()
run()
assert manifest.read_bytes()==first
subprocess.run(['/usr/bin/systemctl','stop','bc250-nvme-power.service'],check=True)
assert qos.read_text()=='100000'
subprocess.run(['/usr/bin/systemctl','start','bc250-nvme-power.service'],check=True)
assert qos.read_text()=='5000'
# Simulated controller reset, then the actual installed resume hook.
qos.write_text('100000')
subprocess.run(['/bin/sh','/usr/lib/systemd/system-sleep/90-bc250-nvme-power','post'],check=True)
assert qos.read_text()=='5000'
# A private administrator edit must block removal before systemctl calls.
config=Path('/etc/bc250-storage-defaults.json');original=config.read_bytes()
config.write_bytes(original+b' ')
calls=Path('/run/fake-systemctl.json').read_bytes()
run('--uninstall',ok=False)
assert Path('/run/fake-systemctl.json').read_bytes()==calls
config.write_bytes(original)
run('--uninstall');assert qos.read_text()=='100000'
run('--uninstall')
assert not Path('/usr/local/libexec/bc250-storage-defaults/storage_defaults_power.py').exists()
assert json.loads(Path('/run/fake-systemctl.json').read_text())['enabled']==[]
# Fail enable after recording it; installer must remove both units and its files.
env=dict(os.environ,TEST_FAIL_ENABLE_TIMER='1')
run(ok=False,env=env)
assert qos.read_text()=='100000'
assert json.loads(Path('/run/fake-systemctl.json').read_text())['enabled']==[]
assert not json.loads(manifest.read_text())['active']
run();assert qos.read_text()=='5000'
run('--uninstall');assert qos.read_text()=='100000'
print(json.dumps({'passed':True,'real_btrfs_fixture':True,'real_installer_file_operations':True,
    'simulated_systemd':True,'simulated_nvme_sysfs':True,'host_reboot_tested':False,
    'checks':['fresh-install','repeat-apply','stop-start-restore','simulated-resume-hook',
              'administrator-edit-refusal','repeat-undo','failed-enable-cleanup','reinstall-after-failure']}))
'''


def run_isolated(program, scratch, timeout=240):
    if os.geteuid() == 0:
        raise SystemExit('Run as an ordinary user; this test intentionally needs no host root privileges')
    if not shutil.which('bwrap'):
        raise SystemExit('bwrap is required')
    scratch = scratch.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix='bc250-install-isolation-', dir=scratch) as temporary:
        base = Path(temporary)
        tree = base / 'root'
        for name in ('usr/bin', 'usr/lib', 'usr/local', 'usr/share', 'etc', 'var/lib', 'home', 'run/systemd/system',
                     'sys/class/nvme/nvme0/device', 'sys/class/nvme/nvme0/power', 'proc', 'dev', 'tmp', 'pkg', 'shims'):
            (tree / name).mkdir(parents=True, exist_ok=True)
        for name in ('bin', 'sbin'):
            (tree / name).symlink_to('usr/bin')
        for name in ('lib', 'lib64'):
            (tree / name).symlink_to('usr/lib')
        shutil.copyfile('/etc/ld.so.cache', tree / 'etc/ld.so.cache')
        fake = tree / 'sys/class/nvme/nvme0'
        for name, value in {'model':'PNY CS2241 1TB SSD','device/current_link_speed':'5.0 GT/s PCIe',
                            'device/current_link_width':'2','power/pm_qos_latency_tolerance_us':'100000'}.items():
            (fake / name).write_text(value)
        hooks = base / 'hooks';hooks.mkdir()
        shim = tree / 'shims/systemctl';shim.write_text(SHIM);shim.chmod(0o755)
        script = tree / 'inside.py';script.write_text(program)
        command = ['bwrap','--unshare-all','--die-with-parent','--new-session','--uid','0','--gid','0',
                   '--bind',str(tree),'/', '--ro-bind','/usr/bin','/usr/bin', '--ro-bind','/usr/lib','/usr/lib',
                   '--ro-bind','/usr/share','/usr/share', '--bind',str(hooks),'/usr/lib/systemd/system-sleep',
                   '--ro-bind',str(shim),'/usr/bin/systemctl', '--ro-bind',str(ROOT),'/pkg',
                   '--proc','/proc','--dev','/dev','--clearenv','--setenv','PATH','/usr/bin',
                   '--setenv','LC_ALL','C','--setenv','PYTHONDONTWRITEBYTECODE','1',
                   '--chdir','/pkg','/usr/bin/python3','/inside.py']
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        if result.returncode:
            raise SystemExit(result.stdout + result.stderr)
        return result.stdout.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scratch', type=Path, required=True)
    args = parser.parse_args()
    print(run_isolated(INSIDE, args.scratch))


if __name__ == '__main__':
    main()
