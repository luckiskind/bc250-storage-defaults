#!/usr/bin/env python3
"""One prespecified precision extension of the serial overhead control.

Uses the original observer/workload and analysis unchanged, with 24 paired
serial trials, the same 3%/5% screen and a fresh copy of the same fixture bytes.
Results are separate from the pilot; no repeat-until-pass or pooled estimate.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

import measure_trace_overhead as pilot


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('step',choices=('run','_host'))
    parser.add_argument('--qualified',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();pilot.require(sys.platform=='linux' and os.geteuid()==0,'Requires Linux root')
    if args.step=='_host':
        contract=copy.deepcopy(pilot.CONTRACT)
        contract.update(version=2,pairs_per_scenario=24,minimum_valid_pairs=20,
            scenarios={'serial-strided':contract['scenarios']['serial-strided']},
            precision_extension='One fixed extension; observer/workload and thresholds unchanged; analyzed separately',
            refinement_driver_sha256=pilot.q.digest(Path(__file__)))
        pilot.CONTRACT=contract;pilot.host(args);return
    unit='bc250-overhead-refinement-'+uuid.uuid4().hex[:12];print(json.dumps(dict(parent_unit=unit)),flush=True)
    subprocess.run(['systemd-run','--quiet','--wait','--pipe','--collect','--unit='+unit,
        '--property=MemoryMax=2G','--property=MemoryHigh=1536M','--property=MemorySwapMax=0','--property=CPUQuota=200%',
        '--property=RuntimeMaxSec=300','--property=KillMode=control-group','--property=TimeoutStopSec=15',
        '/usr/bin/unshare','--mount','--propagation','private','/usr/bin/python3',str(Path(__file__).resolve()),'_host',
        '--qualified',str(args.qualified),'--output',str(args.output)],check=True,timeout=330)


if __name__=='__main__':main()
