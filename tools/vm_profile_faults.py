"""Abruptly stop only disposable QEMU guests at acknowledged installer boundaries.

Host disk caches survive. This does NOT model loss of volatile drive write cache.
"""
import argparse
import json
import os
from pathlib import Path
import selectors
import re
import signal
import stat
import subprocess
import time
import uuid
import vm_boot_probe as probe

LAB=Path('/vmlab')
CASES={
    'partial-stage':('cut-install','partial-stage-1','removed'),
    'power-enabled':('cut-install','after-power-enable','removed'),
    'timer-enabled':('cut-install','after-timer-enable','removed'),
    'manifest-committed':('cut-install','committed-manifest','installed'),
    'legacy-missing-timer-link':('cut-install','committed-missing-timer-link','installed'),
    'removal-started':('cut-remove','deleted-1','removed'),
    'recovery-interrupted':('cut-install','after-timer-enable','removed'),
}


def acknowledged(line,prefix,token):
    # systemd can emit terminal queries immediately before the first probe line.
    # Remove control sequences, not arbitrary text preceding a marker.
    line=re.sub(r'\x1b(?:\][^\x1b\x07]*(?:\x07|\x1b\\)|P[^\x1b]*\x1b\\|\[[0-?]*[ -/]*[@-~]|[78])','',line).strip()
    if not line.startswith(prefix):return None
    data=json.loads(line[len(prefix):])
    probe.require(data.get('token')==token,'Unexpected guest acknowledgement token')
    return data


def nbd_drive(path):
    path=Path(path).absolute()
    probe.require(path.parent.resolve()==path.parent and path.parent.parent==LAB/'runs'
                  and re.fullmatch('[a-z0-9][a-z0-9_-]{0,63}',path.parent.name) is not None
                  and re.fullmatch('[a-z0-9_.-]+',path.name) is not None,
                  'NBD socket must be in the private lab runs directory')
    info=path.lstat()
    probe.require(stat.S_ISSOCK(info.st_mode) and info.st_uid==os.geteuid() and info.st_mode&0o077==0,
                  'Expected an owned private NBD socket')
    return 'file=nbd+unix:///?socket='+str(path)+',if=virtio,format=raw,cache=writeback'


def boot(overlay,log,mode,point='none',expected='removed',case='none',nbd_socket=None,before_guest_kill=None):
    token=uuid.uuid4().hex
    args=probe.qemu_command(overlay,
        f'bc250.mode={mode} bc250.point={point} bc250.expected={expected} bc250.token={token} bc250.case={case}')
    if nbd_socket is not None:args[args.index('-drive')+1]=nbd_drive(nbd_socket)
    started=time.monotonic();cut=None;result=None;pending=b'';total=0
    with log.open('xb') as output:
        proc=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(proc.stdout,selectors.EVENT_READ)
                while True:
                    probe.require(time.monotonic()-started<300,'Virtual boot deadline; disk and log preserved')
                    ready=selector.select(timeout=1)
                    if not ready:
                        if proc.poll() is not None:break
                        continue
                    chunk=os.read(proc.stdout.fileno(),16384)
                    if not chunk:break
                    output.write(chunk);output.flush();total+=len(chunk)
                    probe.require(total<=16*2**20,'Virtual console exceeded bound')
                    pending+=chunk
                    while b'\n' in pending:
                        raw,pending=pending.split(b'\n',1)
                        text=raw.decode(errors='replace')
                        value=acknowledged(text,'BC250_VM_CUT=',token)
                        if value is not None:
                            probe.require(mode.startswith('cut-') and value['mode']==mode and value['point']==point,
                                          'Unexpected interruption checkpoint')
                            cut=value
                            if before_guest_kill is not None:
                                cut['device_fault_before_guest_kill']=before_guest_kill()
                            # Only the Popen-owned VM PID; never a host reboot or broad process match.
                            proc.kill();break
                        value=acknowledged(text,'BC250_VM_RESULT=',token)
                        if value is not None:
                            probe.require(result is None,'Duplicate virtual result');result=value
                    probe.require(len(pending)<=65536,'Unbounded virtual console line')
                    if cut is not None:break
            code=proc.wait(timeout=20)
        finally:
            if proc.poll() is None:proc.kill();proc.wait(timeout=20)
            proc.stdout.close()
    if mode.startswith('cut-'):
        probe.require(cut is not None and code==-signal.SIGKILL,
                      f'Checkpoint not interrupted; inspect {log.name}; exit={code}; result={result}')
        return dict(**cut,qemu_exit=code,elapsed_s=time.monotonic()-started,whole_guest_terminated=True)
    probe.require(code==0 and result is not None and result.get('passed') is True,
                  f'Recovery failed; inspect {log.name}; exit={code}; result={result}')
    manifest=json.loads((LAB/'image-build.json').read_text())
    probe.require(result['kernel']==manifest['kernel_release'] and result['kernel']!=os.uname().release,
                  'Expected separate pinned guest kernel')
    uuid.UUID(result['root_uuid'])
    return dict(**result,qemu_exit=code,elapsed_s=time.monotonic()-started)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-label',required=True,type=probe.validate_label)
    parser.add_argument('--cases',nargs='+',choices=CASES,default=list(CASES))
    args=parser.parse_args()
    probe.require(Path('/run/host').exists(),'Run through virtual_test_lab.py')
    probe.require(len(set(args.cases))==len(args.cases),'Duplicate cases')
    manifest=json.loads((LAB/'image-build.json').read_text())
    probe.require(manifest.get('storage_profile_fixture') is True,'Build a NEW profile fixture first')
    base=LAB/'baseline.raw';probe.check_base(base);before=probe.sparse_fingerprint(base)
    runs=LAB/'runs';runs.mkdir(mode=0o700,exist_ok=True)
    probe.require(not runs.is_symlink(),'Unsafe runs directory')
    run=runs/args.run_label;run.mkdir(mode=0o700)
    results=[]
    for name in args.cases:
        mode,point,expected=CASES[name]
        overlay=run/(name+'.qcow2');probe.new_overlay(overlay)
        cuts=[boot(overlay,run/(name+'-cut.serial.log'),mode,point)]
        if name=='recovery-interrupted':
            cuts.append(boot(overlay,run/(name+'-recover-cut.serial.log'),'cut-recover','deleted-1'))
        recovery=boot(overlay,run/(name+'-recover.serial.log'),'recover',expected=expected,case=name)
        result=dict(case=name,interruptions=cuts,recovery=recovery)
        if name=='legacy-missing-timer-link':
            result['additional_fault']='explicit removal of the committed timer startup symlink, synchronized before cut'
        results.append(result)
        print(json.dumps(result),flush=True)
    probe.require(probe.sparse_fingerprint(base)==before,'Protected baseline changed')
    report=dict(passed=True,cases=results,case_count=len(results),
        whole_guest_interruption_tested=True,physical_power_loss_tested=False,
        volatile_drive_cache_loss_modeled=False,simulated_nvme_sysfs=True,
        separate_guest_kernel=True,real_systemd_pid1=True,base_fingerprint_unchanged=True,
        base_sparse_fingerprint=before,package_sha256=manifest['package_sha256'],
        run_label=args.run_label,
        fault_model='SIGKILL acknowledged QEMU PID; guest RAM/kernel lost; host write cache survives')
    (run/'vm-profile-fault-result.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(passed=True,case_count=len(results))),flush=True)


if __name__=='__main__':main()
