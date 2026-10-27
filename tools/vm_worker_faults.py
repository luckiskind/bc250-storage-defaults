"""Check the real repacker and conservative reservations across modeled cache loss."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import vm_boot_probe as probe
import vm_profile_faults as profile
from vm_cache_faults import logical_sparse_digest
from calibrate_volatile_disk import Backend

LAB=Path('/vmlab')
CASES=('baseline','reserved','range-sync-8','verified-before-finish')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-label',required=True,type=probe.validate_label)
    parser.add_argument('--cases',nargs='+',choices=CASES,default=list(CASES))
    args=parser.parse_args()
    probe.require(Path('/run/host').exists(),'Run through virtual_test_lab.py')
    probe.require(len(set(args.cases))==len(args.cases),'Duplicate worker cases')
    manifest=json.loads((LAB/'image-build.json').read_text())
    probe.require(manifest.get('worker_fixture') is True,'Build a fresh worker fixture first')
    calibration=json.loads((LAB/'matched-cache-calibration.json').read_text())
    probe.require(calibration.get('passed') and calibration.get('armed_cache_cut_tested'),
                  'A matching armed-cut calibration is required')
    for name,digest in calibration['source_sha256'].items():
        probe.require(hashlib.sha256((LAB/name).read_bytes()).hexdigest()==digest,'Disk model changed since calibration')
    base=LAB/'baseline.raw';probe.check_base(base);before=probe.sparse_fingerprint(base)
    logical=logical_sparse_digest(base)
    runs=LAB/'runs';runs.mkdir(mode=0o700,exist_ok=True)
    probe.require(not runs.is_symlink(),'Unsafe worker runs directory')
    run=runs/args.run_label;run.mkdir(mode=0o700)
    results=[]
    for name in args.cases:
        stable=run/(name+'.raw')
        probe.require(not stable.exists() and not stable.is_symlink(),'Existing worker image preserved')
        subprocess.run(['cp','--reflink=never','--sparse=always',str(base),str(stable)],check=True,timeout=120)
        stable.chmod(0o600)
        probe.require(logical_sparse_digest(stable)==logical,'Worker disk copy differs from baseline')
        backend=Backend(run,stable,name+'-start',cache_mib=64)
        try:
            if name=='baseline':
                result=profile.boot(None,run/(name+'.serial.log'),'worker-baseline',nbd_socket=backend.socket,timeout_s=600)
                stats=backend.stats()
                probe.require(stats['dirty_bytes']==0 and stats['cache_limit_errors']==0,'Clean worker left pending model data')
                backend.cut()
                record=dict(case=name,passed=True,baseline=result,device_stats=stats)
            else:
                witness={}
                def fault():
                    witness['before']=backend.stats();witness['armed']=backend.arm()
                    witness['cut']=backend.wait_armed_cut(timeout=60)
                    return dict(method='armed-next-ordinary-NBD-write',dropped_bytes=witness['cut']['dropped_bytes'],
                                trigger_bytes=witness['cut']['cut_trigger_bytes'])
                interruption=profile.boot(None,run/(name+'-cut.serial.log'),'cut-worker',point=name,
                    nbd_socket=backend.socket,before_guest_kill=fault,timeout_s=600)
                probe.require(witness['cut']['dropped_bytes']>0 and witness['cut']['cache_limit_errors']==0,
                              'No positive bounded device-cache loss')
                record=dict(case=name,passed=True,interruption=interruption,before_device_cut=witness['before'],
                            device_cut=witness['cut'])
        finally:backend.close()
        if name!='baseline':
            backend=Backend(run,stable,name+'-recover',cache_mib=64)
            try:
                recovery=profile.boot(None,run/(name+'-recover.serial.log'),'worker-recover',case=name,
                                      nbd_socket=backend.socket,timeout_s=600)
                stats=backend.stats()
                probe.require(stats['dirty_bytes']==0 and stats['cache_limit_errors']==0,'Worker recovery left pending model data')
                backend.cut()
            finally:backend.close()
            original=record['interruption']['worker_witness'];prior=recovery['prior_ledger']
            first=prior['attempts'][0]
            probe.require(first['id']==original['attempt'] and first['day']==original['day']
                          and first['reserved_bytes']==original['reserved_bytes']
                          and prior['budget'][original['day']]==original['budget_bytes'],
                          'Worker reservation did not survive the cut exactly')
            probe.require(recovery['fixture_metadata']==original['fixture_metadata'],
                          'Worker changed persistent fixture metadata')
            record.update(recovery=recovery,recovery_device_stats=stats)
        results.append(record)
        print(json.dumps({'case':name,'passed':True,
                          'dropped_device_bytes':record.get('device_cut',{}).get('dropped_bytes',0)}),flush=True)
    probe.require(probe.sparse_fingerprint(base)==before,'Protected worker baseline changed')
    report=dict(passed=True,case_count=len(results),cases=results,
        worker_fault_cases_passed=sum(c['case']!='baseline' for c in results),
        worker_source_sha256=manifest['worker_reference']['worker_sha256'],worker_reference=manifest['worker_reference'],
        source_sha256={name:hashlib.sha256((LAB/name).read_bytes()).hexdigest() for name in
            ('vm_worker_faults.py','vm_cache_faults.py','vm_profile_faults.py','vm_boot_probe.py',
             'volatile_disk.py','calibrate_volatile_disk.py')},
        calibration_source_sha256=calibration['source_sha256'],run_label=args.run_label,
        base_fingerprint_unchanged=True,base_sparse_fingerprint=before,initial_copy_logical_digest=logical,
        separate_guest_kernel=True,real_systemd_pid1=True,live_virtual_disk_stat_adapter=True,
        physical_power_loss_tested=False,torn_writes_modeled=False,performance_tested=False,
        fault_scope='Pause actual worker at selected boundaries; cut modeled cache after next ordinary write reply; kill guest and recover conservative reservations')
    (run/'vm-worker-fault-result.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'passed':True,'cases':len(results),'worker_fault_cases':report['worker_fault_cases_passed']}),flush=True)


if __name__=='__main__':main()
