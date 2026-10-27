#!/usr/bin/env python3
"""Record the installed profile before/after separately initiated hardware transitions.

This tool never reboots, suspends, sets an alarm, changes services or repairs a
failed check. It writes only new records in an explicit root-private output.
Private records contain host boot identity and lab paths; publish result files
only after review. A successful reboot result does not qualify recovery boot.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time

import capture_baseline as capture
import prepare_test_os as builder

ROOT = Path(__file__).resolve().parents[1]
PHASES = ('before-reboot','after-reboot','before-suspend','after-suspend')


def require(value, message):
    if not value:raise RuntimeError(message)


def write_new(path, value):
    fd = os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as stream:
        json.dump(value,stream,indent=2);stream.write('\n');stream.flush();os.fsync(stream.fileno())
    builder.ownership.sync_directory(path.parent)


def read_private(path):
    fd = os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        s=os.fstat(stream.fileno())
        require(stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and
                s.st_mode&0o077==0 and s.st_size<=262144,'Unsafe private record')
        data=stream.read(262145);require(len(data)<=262144,'Private record too large')
    return json.loads(data)


def collect(test_os):
    baseline=capture.collect()
    workspace_checks=[]
    for path in test_os:
        builder.check_workspace(Path(path))
        workspace_checks.append(dict(passed=True,provenance_format=2))
        require(builder.read_construction(Path(path))[0].get('provenance_format')==2,
                'Migrate the original ownership record before a hardware transition')
    return dict(captured_unix=time.time(),boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        monotonic=time.monotonic(),boottime=time.clock_gettime(time.CLOCK_BOOTTIME),
        suspend_success=int(Path('/sys/power/suspend_stats/success').read_text()),
        mem_sleep=Path('/sys/power/mem_sleep').read_text().strip(),
        root_fsroot=capture.command(['findmnt','-n','-o','FSROOT','/']),
        boot_config_sha256=hashlib.sha256(Path('/boot/limine.conf').read_bytes()).hexdigest(),
        test_os=test_os,workspace_checks=workspace_checks,baseline=baseline,
        source_sha256={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in
            ('tools/physical_transition_probe.py','tools/capture_baseline.py','tools/prepare_test_os.py',
             'install_transaction.py')},
        pending_transaction=(Path(capture.STATE)/'transaction.json').exists(),
        power_runtime=read_private(Path('/run/bc250-storage-power.json')))


def healthy(record):
    baseline=record['baseline'];installed=baseline['installation']['installed_files']
    return (len(installed)==7 and all(v.get('matches_manifest') is True for v in installed.values())
        and baseline['installation']['stop_marker'] is False and not record['pending_transaction']
        and baseline['nvme']['nvme0']['latency_tolerance_us']=='5000'
        and all(baseline['units'][u].get('ActiveState')=='active'
            and baseline['units'][u].get('UnitFileState')=='enabled'
            for u in ('bc250-nvme-power.service','bc250-btrfs-repack.timer'))
        and all(c['passed'] for c in record['workspace_checks']))


def compare(before, after, action):
    a=before['baseline'];b=after['baseline']
    ledger=a['installation']['ledger']['daily_charged_bytes']
    next_ledger=b['installation']['ledger']['daily_charged_bytes']
    checks=dict(before_profile_healthy=healthy(before),after_profile_healthy=healthy(after),
        installed_hashes_unchanged=a['installation']['installed_files']==b['installation']['installed_files'],
        same_kernel=a['kernel']==b['kernel'],same_root_subvolume=bool(before['root_fsroot']) and
        before['root_fsroot']==after['root_fsroot'],boot_config_unchanged=before['boot_config_sha256']==after['boot_config_sha256'],
        source_unchanged=before['source_sha256']==after['source_sha256'],
        daily_reservations_not_rewound=all(next_ledger.get(day,-1)>=amount for day,amount in ledger.items()))
    suspended=(after['boottime']-after['monotonic'])-(before['boottime']-before['monotonic'])
    if action=='reboot':checks['kernel_boot_identity_changed']=before['boot_id']!=after['boot_id']
    else:
        checks.update(kernel_boot_identity_unchanged=before['boot_id']==after['boot_id'],
            kernel_suspend_counter_increased=after['suspend_success']>before['suspend_success'],
            measured_sleep_interval=suspended>=1)
    return dict(passed=all(checks.values()),action=action,checks=checks,
        physical_host_transition=True,physical_power_loss_tested=False,recovery_boot_tested=False,
        nvme_qos_us=int(b['nvme']['nvme0']['latency_tolerance_us']),
        power_original_us=int(after['power_runtime']['original']),
        workspace_records_verified=len(after['workspace_checks']),
        suspend_seconds_from_clock_difference=suspended if action=='suspend' else None,
        kernel_suspend_counter_delta=after['suspend_success']-before['suspend_success'] if action=='suspend' else None,
        source_sha256=after['source_sha256'],completed_unix=after['captured_unix'])


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase',choices=PHASES)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--test-os',type=Path,action='append',default=[])
    args=parser.parse_args()
    require(sys.platform=='linux' and os.geteuid()==0,'Requires root on Linux')
    area=args.output.absolute()
    require(len(area.parts)>=4 and area.parent.resolve(strict=True)==area.parent,'Use a dedicated canonical output path')
    if not area.exists():
        require(args.phase.startswith('before-'),'Capture the before phase first')
        area.mkdir(mode=0o700);write_new(area/'probe-format.json',dict(format=1))
    require(not area.is_symlink() and area.is_dir() and area.stat().st_uid==0 and
            area.stat().st_mode&0o077==0,'Output must be root-owned and private')
    require(read_private(area/'probe-format.json')==dict(format=1),'Unrecognized output')
    target=area/(args.phase+'-private.json')
    require(not target.exists() and not target.is_symlink(),'Existing phase is never overwritten')
    before=None
    if args.phase.startswith('after-'):
        require(not args.test_os,'After phase uses the exact recorded private OS paths')
        before=read_private(area/(args.phase.replace('after-','before-')+'-private.json'))
    test_os=before['test_os'] if before else [str(p.absolute()) for p in args.test_os]
    record=collect(test_os);write_new(target,record)
    if before is None:
        require(healthy(record),'Before profile is not healthy; record retained; do not initiate transition')
        print(json.dumps(dict(recorded=True,phase=args.phase,physical_transition_tested=False)),flush=True)
    else:
        result=compare(before,record,args.phase.removeprefix('after-'))
        write_new(area/(args.phase+'-result.json'),result)
        print(json.dumps(result),flush=True)
        require(result['passed'],'Hardware transition checks failed; preserve records and investigate')


if __name__=='__main__':main()
