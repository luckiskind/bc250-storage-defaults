#!/usr/bin/env python3
"""Export tracked project files as one add-only patch under bc250-storage-defaults/."""
from pathlib import Path
import argparse
import shutil
import subprocess
import tempfile

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    output = args.output.resolve()
    names = subprocess.check_output(['git', '-C', str(root), 'ls-files', '-z']).decode().split('\0')
    with tempfile.TemporaryDirectory(prefix='bc250-patch-') as temporary:
        stage = Path(temporary)
        subprocess.run(['git', 'init', '-q', str(stage)], check=True)
        for name in filter(None, names):
            source = root / name
            if source.is_symlink() or not source.is_file():
                raise RuntimeError(f'Expected a regular tracked file: {name}')
            target = stage / 'bc250-storage-defaults' / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        subprocess.run(['git', '-C', str(stage), 'add', '.'], check=True)
        patch = subprocess.check_output(['git', '-C', str(stage), 'diff', '--cached', '--binary', '--no-ext-diff'])
        output.write_bytes(patch)
    print(output)

if __name__ == '__main__':
    main()
