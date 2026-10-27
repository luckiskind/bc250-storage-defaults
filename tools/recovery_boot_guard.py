#!/usr/bin/env python3
"""Guard an explicitly selected private recovery root and return to normal boot.

Installed only inside a separately prepared candidate. No installation, drive
policy change, boot-file edit or firmware-variable write is performed here.
The caller must establish and verify normal-default/one-shot boot policy first.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

sys.path.insert(0,str(Path(__file__).resolve().parent))
sys.path.append(str(Path(__file__).resolve().parents[1]))
import install_transaction as ownership

EFI=Path('/sys/firmware/efi/efivars')
GUID='4a67b082-0a4c-41cf-b6c7-440b29bb8c4f'
FIXTURE=Path('/opt/bc250-recovery-fixture.bin')
RESULT=Path('/var/lib/bc250-recovery/result.json')


def require(value,message):
    if not value:raise RuntimeError(message)


def digest(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def read_private(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        s=os.fstat(stream.fileno())
        require(stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1
                and s.st_mode&0o077==0 and s.st_size<=65536,'Unsafe recovery configuration')
        data=stream.read(65537);require(len(data)<=65536,'Configuration too large')
    return json.loads(data)


def load_config(path):
    cfg=read_private(path)
    require(cfg.get('format')==1 and cfg.get('mode') in ('vm','physical'),'Unsupported recovery configuration')
    require(re.fullmatch('[0-9a-f]{32}',cfg.get('nonce','')) is not None,'Invalid recovery nonce')
    require(ownership.valid_identity(cfg.get('root_identity')) and ownership.valid_identity(cfg.get('working_identity'))
            and cfg['root_identity']!=cfg['working_identity'],'Invalid or shared recovery root identity')
    require(re.fullmatch('[A-F0-9]{4}-[A-F0-9]{4}',cfg.get('esp_uuid','')) is not None,'Invalid ESP identity')
    require(set(cfg.get('support_sha256',{}))=={'recovery_boot_guard.py','install_transaction.py'},'Unrecognized support files')
    for name,sha in cfg['support_sha256'].items():
        require(digest(Path(__file__).parent/name)==sha,'Recovery support file changed')
    return cfg


def root_identity():
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:return ownership.persistent_identity(fd)
    finally:os.close(fd)


def validate_identity(actual,cfg):
    require(actual==cfg['root_identity'] and actual!=cfg['working_identity'],
            'Selected root identity does not match the private candidate')


def validate_policy(text,cfg):
    for name,expected in (('default_entry',cfg['normal_menu_path']),('remember_last_entry','no')):
        values=re.findall(r'^\s*'+name+r'\s*:\s*(.*?)\s*$',text,re.M|re.I)
        require(values==[expected],'Normal-default boot policy is not established')
    require(len(re.findall(r'^/'+re.escape(cfg['trial_entry'])+r'\s*$',text,re.M))==1,
            'Missing or duplicate trial entry')
    require(text.count('bc250.recovery='+cfg['nonce'])==1,'Trial nonce is absent or ambiguous')
    # Resolve the actual menu hierarchy as well as the global default value.
    # The preparation tool uses simple ASCII titles without escaped separators.
    entries=[];parents=[];current=None
    for line in text.splitlines():
        match=re.fullmatch(r'\s*(/+)\+?([^\r\n]+)',line)
        if match:
            depth=len(match[1]);require(depth<=len(parents)+1,'Invalid boot menu hierarchy')
            parents=parents[:depth-1]+[match[2]]
            current=dict(path='/'.join(parents),lines=[]);entries.append(current)
        elif current is not None:current['lines'].append(line)
    normal=[e for e in entries if e['path']==cfg['normal_menu_path']]
    require(len(normal)==1 and re.findall(r'^\s*protocol\s*:\s*(.*?)\s*$',
            '\n'.join(normal[0]['lines']),re.M|re.I)==['linux'],'Normal default is not a unique Linux boot entry')


def efi_text(name,missing=False):
    path=EFI/(name+'-'+GUID)
    if missing and not path.exists():return None
    require(not path.is_symlink() and path.stat().st_size<=8192,'Unsafe EFI variable')
    data=path.read_bytes();require(len(data)>=4,'Invalid EFI variable')
    return data[4:].decode('utf-16-le').rstrip('\0')


def basic_context(cfg):
    require(sys.platform=='linux' and os.geteuid()==0,'Requires Linux root')
    require(Path('/proc/1/comm').read_text().strip()=='systemd','Expected real systemd PID 1')
    tokens=[s.split('=',1)[1] for s in Path('/proc/cmdline').read_text().split() if s.startswith('bc250.recovery=')]
    require(tokens==[cfg['nonce']],'Not entered through the selected trial command line')
    require(os.uname().release==cfg['kernel_release'],'Unexpected recovery kernel')
    detected=subprocess.run(['systemd-detect-virt','--vm'],capture_output=True,text=True,timeout=10)
    require((detected.returncode==0 and detected.stdout.strip()=='qemu') if cfg['mode']=='vm'
            else detected.returncode==1,'Recovery environment type mismatch')


def boot_context(cfg,selected_entry=None):
    require(efi_text('LoaderEntrySelected')==(selected_entry or cfg['trial_entry']),'Unexpected selected boot entry')
    require(efi_text('LoaderInfo').startswith('Limine '),'Unexpected boot loader')
    require(efi_text('LoaderEntryOneShot',missing=True) is None,'Trial one-shot was not consumed')
    point=Path('/run/bc250-recovery-esp')
    require(not point.exists() and not point.is_symlink(),'Existing recovery ESP mountpoint preserved')
    source=Path('/dev/disk/by-uuid')/cfg['esp_uuid']
    require(stat.S_ISBLK(source.stat().st_mode),'ESP device unavailable')
    point.mkdir(mode=0o700)
    mounted=False
    try:
        subprocess.run(['mount','-t','vfat','-o','ro,nosuid,nodev,noexec',str(source),str(point)],check=True,timeout=20)
        mounted=True
        options=subprocess.check_output(['findmnt','-n','-o','OPTIONS','--target',str(point)],text=True,timeout=10).strip().split(',')
        require('ro' in options,'ESP inspection must be read-only')
        config=point/'limine.conf'
        require(config.is_file() and not config.is_symlink() and config.stat().st_size<=262144,'Unsafe boot configuration')
        require(digest(config)==cfg['config_sha256'],'Boot configuration changed')
        validate_policy(config.read_text(),cfg)
    finally:
        if mounted:subprocess.run(['umount',str(point)],check=True,timeout=20)
        point.rmdir()


def request_reboot():
    subprocess.run(['systemctl','reboot','--no-block'],check=True,timeout=20)


def trial(cfg):
    basic_context(cfg)
    validate_identity(root_identity(),cfg)  # Before managed data writes or ESP mount setup.
    boot_context(cfg)
    require(not RESULT.parent.exists(),'Existing recovery result is preserved')
    require(FIXTURE.is_file() and not FIXTURE.is_symlink() and FIXTURE.stat().st_nlink==1
            and digest(FIXTURE)==cfg['fixture_sha256'],'Private fixture changed')
    require(subprocess.check_output(['systemctl','is-active','multi-user.target'],text=True,timeout=15).strip()=='active',
            'Usable target is not active')
    require(not subprocess.check_output(['systemctl','--failed','--plain','--no-legend','--no-pager'],text=True,timeout=15).strip(),
            'Unexpected failed guest units')
    RESULT.parent.mkdir(mode=0o700)
    record=dict(passed=True,mode=cfg['mode'],kernel=os.uname().release,nonce=cfg['nonce'],
        root_identity_verified=True,normal_default_verified=True,one_shot_consumed=True,
        selected_entry_verified=True,fixture_sha256=digest(FIXTURE),managed_fixture_unchanged=True,
        real_systemd_pid1=True,usable_target_active=True,failed_units=0,
        boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),completed_unix=time.time())
    ownership.atomic_json(RESULT,record)
    print('BC250_RECOVERY_TRIAL='+json.dumps(record),flush=True)
    request_reboot()


def safe_return(cfg):
    # A root-identity refusal must not prevent return through the independently
    # verified trial selection, consumed one-shot and normal-default policy.
    basic_context(cfg);boot_context(cfg)
    print('BC250_RECOVERY_RETURN='+json.dumps(dict(guarded_return=True,return_action_writes_no_managed_data=True)),flush=True)
    request_reboot()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('step',choices=('trial','return'))
    parser.add_argument('--config',type=Path,required=True)
    args=parser.parse_args();cfg=load_config(args.config)
    (trial if args.step=='trial' else safe_return)(cfg)


if __name__=='__main__':main()
