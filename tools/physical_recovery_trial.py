#!/usr/bin/env python3
"""Stage, boot once into a prepared private root, verify return and restore.

preflight touches only private lab records and enables persistent journaling in
the candidate. boot temporarily publishes the checked Limine config and requests
one trial boot. verify/restore preserve unexpected administrator/firmware edits.
No kernel replacement, system suspend or hardware power cut is performed.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

import native_trial_lab as native_trial
import native_volume_lab as native
import physical_transition_probe as transition
import prepare_physical_recovery as prepare
import recovery_boot_guard as guard

BOOT=Path('/boot/limine.conf')
NORMAL='CachyOS.linux-cachyos-bore-bc250'
LAST=Path('/sys/firmware/efi/efivars/LimineLastBootedEntry-513ee0d0-6e43-cb05-b272-f146a2fcb88a')
ROOT=Path(__file__).resolve().parents[1]


def require(value,message):
    if not value:raise RuntimeError(message)


def boot_id():return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def read(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid==os.geteuid() and info.st_nlink==1
            and info.st_mode&0o022==0 and info.st_size<=262144,'Unsafe owned file')
        data=stream.read(262145);require(len(data)<=262144,'Owned file too large');return data


def replace_owned(path,expected,replacement,token):
    require(re.fullmatch('[0-9a-f]{32}',token) is not None,'Invalid replacement token')
    require(read(path)==expected,'Owned file changed; preserve administrator edits')
    pending=path.parent/('.bc250-recovery-'+token+'.pending')
    fd=os.open(pending,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(replacement);stream.flush();os.fsync(stream.fileno())
    require(read(path)==expected,'Owned file changed before replacement; preserve both files')
    os.replace(pending,path);guard.ownership.sync_directory(path.parent)
    require(read(path)==replacement,'Published file mismatch')


def healthy():
    record=transition.collect([])
    require(transition.healthy(record),'Working storage profile is unhealthy')
    return record


def candidate(area):
    native.private_area(area)
    report=native_trial.safe_json(area/'preparation-result.json')
    require(report['prepared'] and not report['physical_boot_tested'],'Unrecognized prepared candidate')
    root=area/'root';require(str(root)==report['candidate_root'] and root.resolve(strict=True)==root,'Candidate path changed')
    require(prepare.identity(Path('/'))==report['working_identity'],'Not on the known working root')
    require(prepare.identity(root)==report['root_identity'],'Prepared root was replaced')
    cfg=guard.read_private(root/'opt/bc250-recovery/config.json')
    require(cfg['mode']=='physical' and cfg['root_identity']==report['root_identity']
        and cfg['working_identity']==report['working_identity'],'Candidate configuration changed')
    for name,sha in cfg['support_sha256'].items():
        require(name in ('recovery_boot_guard.py','install_transaction.py'),'Unknown support file')
        require(guard.digest(root/'opt/bc250-recovery'/name)==sha,'Candidate support changed')
    require(os.uname().release==cfg['kernel_release']==report['kernel_release'],'Kernel changed')
    bootdir=Path('/boot')/Path('/etc/machine-id').read_text().strip()/'linux-cachyos-bore-bc250'
    require(all(guard.digest(bootdir/name)==sha for name,sha in report['boot_sha256'].items()),'Installed boot files changed')
    original=read(area/'original-limine.conf');proposed=read(area/'proposed-limine.conf')
    import hashlib
    require(hashlib.sha256(original).hexdigest()==report['original_config_sha256']
        and hashlib.sha256(proposed).hexdigest()==report['proposed_config_sha256']==cfg['config_sha256'],'Staged boot files changed')
    guard.validate_policy(proposed.decode(),cfg)
    for relative in ('EFI/limine/limine.conf','EFI/BOOT/limine.conf','boot/limine/limine.conf','boot/limine.conf','limine/limine.conf'):
        path=BOOT.parent/relative;require(not path.exists() and not path.is_symlink(),'Shadow boot configuration preserved')
    require(guard.efi_text('LoaderEntrySelected')==NORMAL,'Unexpected current boot entry')
    return report,root,cfg,original,proposed


def preflight(area,out):
    report,root,cfg,original,proposed=candidate(area)
    require(read(BOOT)==original,'Boot setup changed before trial')
    require(guard.efi_text('LoaderEntryOneShot',missing=True) is None,'Pending firmware request preserved')
    require(native.tree_manifest(root,0)['sha256']==report['candidate_tree_sha256'],'Candidate tree changed')
    require(not (root/'var/lib/bc250-recovery').exists(),'Candidate was already used')
    before=healthy();native.private_area(out,creating=True);out.mkdir(mode=0o700)
    # Keep failure diagnostics across the return reboot. Only the private
    # candidate changes; its preparation fingerprint is retained separately.
    journal=root/'var/log/journal';require(not journal.exists(),'Existing journal preserved')
    journal.mkdir(mode=0o755)
    staged=native.tree_manifest(root,0)
    guard.ownership.atomic_json(out/'before-private.json',before)
    guard.ownership.atomic_json(out/'trial-private.json',dict(format=1,candidate=str(area),
        root_identity=report['root_identity'],working_identity=report['working_identity'],
        staged_tree_sha256=staged['sha256'],original_tree_sha256=report['candidate_tree_sha256'],
        last_booted_hex=read(LAST).hex(),nonce=cfg['nonce'],prepared_unix=time.time(),
        source_sha256=guard.digest(Path(__file__))))
    subprocess.run(['sync','-f',str(root)],check=True,timeout=60)
    print(json.dumps(dict(preflight_passed=True,boot_setup_changed=False,persistent_candidate_journal=True)),flush=True)


def record(out):
    native.private_area(out)
    state=guard.read_private(out/'trial-private.json')
    require(state['format']==1 and state['source_sha256']==guard.digest(Path(__file__)),'Trial source changed')
    area=Path(state['candidate']);values=candidate(area)
    require(values[2]['nonce']==state['nonce'],'Trial selection changed')
    return state,values


def restore_owned(state,original,proposed):
    require(prepare.identity(Path('/'))==state['working_identity'],'Restore requires the original working root')
    require(read(LAST).hex()==state['last_booted_hex'],'Remembered boot selection changed; preserve firmware state')
    requested=guard.efi_text('LoaderEntryOneShot',missing=True)
    require(requested in (None,'BC250-STORAGE-TRIAL'),'Unexpected one-shot request preserved')
    current=read(BOOT);require(current in (original,proposed),'Unknown boot edits preserved')
    if requested:
        subprocess.run(['bootctl','set-oneshot',''],check=True,timeout=20)
        require(guard.efi_text('LoaderEntryOneShot',missing=True) is None,'Cannot clear owned one-shot')
    if current==proposed:replace_owned(BOOT,proposed,original,state['nonce'])
    subprocess.run(['sync','-f',str(BOOT.parent)],check=True,timeout=30)


def boot(out):
    state,(report,root,cfg,original,proposed)=record(out)
    require(not (out/'armed-private.json').exists(),'Trial was already armed')
    require(native.tree_manifest(root,0)['sha256']==state['staged_tree_sha256'],'Staged root changed')
    before=transition.read_private(out/'before-private.json')
    require(boot_id()==before['boot_id'],'Working host restarted since preflight')
    healthy();require(guard.efi_text('LoaderEntryOneShot',missing=True) is None,'Pending request preserved')
    require(read(BOOT)==original and read(LAST).hex()==state['last_booted_hex'],'Boot policy changed')
    guard.ownership.atomic_json(out/'armed-private.json',dict(armed=True,boot_id=boot_id(),nonce=state['nonce'],time=time.time()))
    try:
        replace_owned(BOOT,original,proposed,state['nonce'])
        subprocess.run(['sync','-f',str(BOOT.parent)],check=True,timeout=30)
        subprocess.run(['bootctl','set-oneshot',cfg['trial_entry']],check=True,timeout=20)
        require(guard.efi_text('LoaderEntryOneShot')==cfg['trial_entry'],'One-shot selection not observed')
        require(read(BOOT)==proposed,'Temporary boot configuration changed')
        print(json.dumps(dict(reboot_requested=True,trial_entry=cfg['trial_entry'],normal_default=cfg['normal_menu_path'])),flush=True)
        subprocess.run(['systemctl','reboot','--no-block'],check=True,timeout=20)
    except BaseException:
        restore_owned(state,original,proposed)
        raise


def verify(out):
    state,(report,root,cfg,original,proposed)=record(out)
    before=transition.read_private(out/'before-private.json');after=healthy()
    require(boot_id()!=before['boot_id'],'No physical restart observed')
    require(guard.efi_text('LoaderEntryOneShot',missing=True) is None,'One-shot was not consumed')
    require(read(BOOT)==proposed,'Temporary boot config changed before verification')
    error=None;trial=None
    try:
        trial=guard.read_private(root/'var/lib/bc250-recovery/result.json')
        require(trial['passed'] and trial['mode']=='physical' and trial['nonce']==state['nonce'],'Trial did not pass')
        require(trial['boot_id'] not in (before['boot_id'],after['boot_id']),'Distinct trial kernel boot missing')
        require(all(trial[k] is True for k in ('root_identity_verified','normal_default_verified','one_shot_consumed',
            'selected_entry_verified','managed_fixture_unchanged','real_systemd_pid1','usable_target_active'))
            and trial['failed_units']==0,'Trial guard checks incomplete')
        require(guard.digest(root/'opt/bc250-recovery-fixture.bin')==cfg['fixture_sha256']==trial['fixture_sha256'],'Fixture changed')
    except (OSError,KeyError,ValueError,RuntimeError) as exc:error=str(exc)
    restore_owned(state,original,proposed)
    after['boot_config_sha256']=guard.digest(BOOT)
    result=transition.compare(before,after,'reboot')
    result.update(passed=result['passed'] and error is None,recovery_boot_tested=error is None,
        recovery_error=error,normal_root_identity_verified=True,original_boot_configuration_restored=True,
        selected_normal_entry_verified=True,owned_one_shot_absent=True,remembered_normal_entry_unchanged=True,
        recovery_fixture_unchanged=error is None,physical_suspend_tested=False,system_suspend_wake_supported=False,
        trial_kernel=trial.get('kernel') if trial else None,trial_failed_units=trial.get('failed_units') if trial else None,
        physical_boots_observed=2 if error is None else None,source_sha256=dict(result['source_sha256'],
            **{'tools/physical_recovery_trial.py':guard.digest(Path(__file__)),
               'tools/recovery_boot_guard.py':cfg['support_sha256']['recovery_boot_guard.py']}))
    guard.ownership.atomic_json(out/'after-private.json',after)
    guard.ownership.atomic_json(out/'result.json',result)
    print(json.dumps(result),flush=True)
    require(result['passed'],'Physical recovery trial failed; diagnostics and original boot config retained')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('step',choices=('preflight','boot','verify','restore'))
    parser.add_argument('--candidate',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();require(sys.platform=='linux' and os.geteuid()==0,'Requires Linux root')
    out=args.output.absolute()
    if args.step=='preflight':
        require(args.candidate is not None,'Specify prepared candidate');preflight(args.candidate.absolute(),out);return
    if args.step=='boot':boot(out)
    elif args.step=='verify':verify(out)
    else:
        state,(_,_,_,original,proposed)=record(out);restore_owned(state,original,proposed)
        print(json.dumps(dict(original_boot_configuration_restored=True)),flush=True)


if __name__=='__main__':main()
