#!/usr/bin/env python3
"""Opt-in v2 capture around the unchanged private native Konsole fixture.

This checks integration and device-wide stream quality, not attribution,
application overhead, a cold OS, or accelerator performance.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid
from unittest.mock import patch

import native_application_inputs as native
import qualify_trace_v2 as observer
from application_trace_v2 import review_capture

q = native.q
ROOT = Path(__file__).resolve().parents[1]
PHASES = ('cold-before', 'cold-after', 'warm-before', 'warm-after')


def view_command(command, adapter):
    """Route only the native builder's exact child invocation to this adapter."""
    prefix = ['unshare', '--mount', '--propagation', 'private', 'python3',
              str(Path(native.__file__).resolve()), '_view']
    if command[:len(prefix)] == prefix:
        return [*prefix[:5], str(adapter), '_view', *command[len(prefix):]]
    return command


def view(args):
    original = native.terminal.trial
    def bounded_trial(area, index, *values):
        started = time.monotonic_ns()
        try:
            return original(area, index, *values)
        finally:
            # The envelope includes controller validation and normal cleanup.
            # It does not redefine the endpoint or reconstruct an exact launch.
            native.terminal.save(area / ('envelope-%d-private.json' % index),
                dict(start_ns=started, finish_ns=time.monotonic_ns()))
    with patch.object(native.terminal, 'trial', bounded_trial):
        native.view(args)


class CaptureGate:
    """Four authenticated cache phases are still admitted by native.serve_cache.

    This hook runs only after that server's identity/nonce/order checks. The
    caller cannot supply paths, devices, binaries, durations or BPF options.
    """
    def __init__(self, area, desktop, device, cache):
        self.area, self.desktop, self.device, self.cache = area, desktop, device, cache
        self.index = 0
        self.active = None
        self.rows = []

    def __call__(self, *args, **kwargs):
        q.require(self.index < 4, 'Unexpected cache call after final phase')
        index = self.index
        self.index += 1
        if index % 2:
            self.close_capture(index // 2)
        state = self.cache(*args, **kwargs)
        if not index % 2:
            q.require(self.active is None, 'Previous capture still active')
            q.require(state['resident_bytes'] == (0 if index == 0 else state['page_rounded_bytes']),
                      'Selected input cache condition failed before attach')
            self.active = observer.start(self.area / 'observer', self.device, duration=8)
        return state

    def close_capture(self, index):
        q.require(self.active is not None, 'No active application capture')
        proc, ids, log = self.active
        prefix = self.area / ('capture-%d' % index)
        try:
            out, err = proc.communicate(timeout=12)
            prefix.with_name(prefix.name + '-raw-private.json').write_bytes(out)
            prefix.with_name(prefix.name + '-loader-private.log').write_bytes(log + err)
            q.require(proc.returncode == 0 and q.absent(ids), 'Capture failed or left programs')
            raw = json.loads(out)
            envelope = json.loads((self.desktop / ('envelope-%d-private.json' % index)).read_text())
            trial = json.loads((self.desktop / ('trial-%02d/result-private.json' % index)).read_text())
            row = review_capture(raw, envelope, trial)
            row.update(condition=('selected-data-cold', 'selected-data-warm')[index], owned_programs_gone=True)
            self.rows.append(row)
            native.terminal.save(prefix.with_name(prefix.name + '-review.json'), row)
        finally:
            q.finish(proc)
            q.require(q.absent(ids), 'Owned application programs remain after cleanup')
            self.active = None

    def cleanup(self):
        if self.active is not None:
            proc, ids, _ = self.active
            q.finish(proc)
            q.require(q.absent(ids), 'Owned programs remain after failed fixture')
            self.active = None


def host(args):
    q.native.confined()
    area = args.output.absolute()
    qualified = args.qualified.absolute()
    native_qualified = args.native_qualified.absolute()
    q.native.private_area(area, creating=True)
    q.native.private_area(qualified)
    q.native.private_area(native_qualified)
    q.native.host_space(area.parent)
    device = q.block_device(area.parent)
    q.require(device == q.block_device(Path('/')), 'Physical namespace differs')
    reference = json.loads((qualified / 'result.json').read_text())
    q.require(reference['passed'] and reference['case_count'] == 10 and reference['all_owned_programs_gone']
              and reference['kernel'] == os.uname().release, 'Qualified v2 reference differs')
    for name, sha in reference['source_sha256'].items():
        q.require(q.digest(ROOT / name) == sha, 'Qualified source differs: ' + name)
    native_reference = json.loads((native_qualified / 'result.json').read_text())
    q.require(native_reference['passed'] and native_reference['source_and_corpus_unchanged'],
              'Native fixture reference did not pass')
    for name, sha in native_reference['source_sha256'].items():
        q.require(q.digest(ROOT / 'bench' / name) == sha, 'Native reference source differs: ' + name)
    area.mkdir(mode=0o700)
    (area / 'observer').mkdir(mode=0o700)
    for name in ('request-trace-v2', 'request_trace_v2.bpf.o'):
        q.require(q.digest(qualified / name) == reference['compiled_sha256'][name], 'Qualified binary differs')
        shutil.copyfile(qualified / name, area / 'observer' / name)
        (area / 'observer' / name).chmod(0o700 if name == 'request-trace-v2' else 0o600)
    source_names = ('bench/qualify_application_trace_v2.py', 'analysis/application_trace_v2.py',
        'bench/native_application_inputs.py', 'bench/terminal_endpoint.py', 'bench/copied_input_probe.py')
    sources = {name: q.digest(ROOT / name) for name in source_names}
    contract = dict(schema_version=1, kernel=os.uname().release, source_sha256=sources,
        qualification_sha256=q.digest(qualified / 'result.json'), compiled_sha256=reference['compiled_sha256'],
        native_qualification_sha256=q.digest(native_qualified / 'result.json'),
        capture_seconds=8, conditions=['selected-data-cold', 'selected-data-warm'], trials=2,
        endpoint_unchanged=True, native_fixture_unchanged=True, endpoint='Original owned Konsole PTY ready',
        capture_scope='Whole NVMe namespace; no foreground attribution',
        interval_scope='Whole terminal.trial envelope including validation and cleanup',
        application_overhead_qualified=False, full_os_cold=False, stage1_gate_passed=False)
    native.terminal.save(area / 'contract.json', contract)
    with (area / 'contract.json').open('rb') as stream:
        os.fsync(stream.fileno())
    state, inventory = q.trace_state(), q.programs()
    qos = Path('/sys/class/nvme/nvme0/power/pm_qos_latency_tolerance_us')
    q.require(qos.read_text().strip() == '5000', 'Drive power policy differs')
    gate = CaptureGate(area, args.desktop_output.absolute(), device, native.cache_state)
    original_popen = subprocess.Popen
    def launch(command, *values, **options):
        return original_popen(view_command(command, Path(__file__).resolve()), *values, **options)
    native_args = argparse.Namespace(output=area / 'native', desktop_output=args.desktop_output,
                                    audit=args.audit, uid=args.uid)
    try:
        # Only the native view executable is adapted. Endpoints, mount setup,
        # privilege drop, cache protocol and namespace cleanup are unmodified.
        with patch.object(native, 'cache_state', gate), patch.object(subprocess, 'Popen', launch):
            native.build(native_args)
        q.require(gate.index == 4 and len(gate.rows) == 2, 'Incomplete application/cache sequence')
    finally:
        gate.cleanup()
        native.terminal.save(area / 'completed-captures.json', gate.rows)
        q.require(q.trace_state() == state and q.programs() == inventory, 'Trace/program inventory changed')
        q.require(qos.read_text().strip() == '5000', 'Drive policy changed')
    for name, sha in sources.items():
        q.require(q.digest(ROOT / name) == sha, 'Adapter/fixture source changed')
    for name in ('request-trace-v2', 'request_trace_v2.bpf.o'):
        q.require(q.digest(area / 'observer' / name) == reference['compiled_sha256'][name], 'Copied observer changed')
    fixture = json.loads((area / 'native/result.json').read_text())
    q.require(fixture['passed'] and fixture['source_and_corpus_unchanged'], 'Native fixture failed')
    q.require(json.loads((area / 'native/manifest-private.json').read_text()) ==
              json.loads((native_qualified / 'manifest-private.json').read_text()), 'Selected native inputs changed')
    passed = all(r['capture_integration_passed'] for r in gate.rows)
    result = dict(contract=contract, passed=passed, captures=gate.rows,
        native_fixture=fixture, all_owned_programs_gone=True, global_trace_state_unchanged=True,
        unrelated_program_inventory_unchanged=True, nvme_qos_us=5000,
        new_accelerator_comparison=False, foreground_attribution_qualified=False,
        application_overhead_qualified=False, stage1_gate_passed=False)
    native.terminal.save(area / 'result.json', result)
    print(json.dumps(dict(passed=passed, captures=len(gate.rows), stage1_gate_passed=False)), flush=True)
    q.require(passed, 'Application capture quality/coverage failed; retained result is not a pass')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('step', choices=('run', '_host', '_view'))
    for name in ('output', 'qualified', 'native-qualified', 'audit', 'desktop-output'):
        parser.add_argument('--' + name, type=Path, required=name == 'output')
    parser.add_argument('--uid', type=int, default=1000)
    args = parser.parse_args()
    q.require(sys.platform == 'linux' and os.geteuid() == 0, 'Linux root setup required')
    if args.step == '_view':
        view(args)
        return
    q.require(all((args.qualified, args.native_qualified, args.audit, args.desktop_output)), 'All input/output paths required')
    if args.step == '_host':
        host(args)
        return
    unit = 'bc250-application-trace2-' + uuid.uuid4().hex[:12]
    subprocess.run(['systemd-run', '--quiet', '--wait', '--pipe', '--collect', '--unit=' + unit,
        '--property=MemoryMax=2G', '--property=MemorySwapMax=0', '--property=CPUQuota=200%',
        '--property=TasksMax=128', '--property=RuntimeMaxSec=300', '--property=KillMode=control-group',
        '/usr/bin/unshare', '--mount', '--propagation', 'private', '/usr/bin/python3', '-B',
        str(Path(__file__).resolve()), '_host', '--output', str(args.output), '--qualified', str(args.qualified),
        '--native-qualified', str(args.native_qualified),
        '--audit', str(args.audit), '--desktop-output', str(args.desktop_output), '--uid', str(args.uid)],
        check=True, timeout=330)


if __name__ == '__main__':
    main()
