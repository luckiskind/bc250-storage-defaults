#!/usr/bin/env python3
"""Opt-in live Btrfs check. Only a fresh private fixture is repacked and then removed."""
import argparse
import importlib.util
import json
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('directory', type=Path, help='Writable Btrfs scratch directory')
args = parser.parse_args()
spec = importlib.util.spec_from_file_location('repacker', Path(__file__).resolve().parents[1] / 'storage_defaults_repack.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
print(json.dumps(module.self_test(args.directory), indent=2))
