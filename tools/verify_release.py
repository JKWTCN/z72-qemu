# SPDX-License-Identifier: GPL-2.0-or-later
"""Verify the declared public source inventory; ignore local runtime output.

Checks that every published file is declared in publication-manifest.json
with a matching SHA-256, that no symlink or binary payload sneaks in, and
that the manifest keeps declaring firmware_included=false. This is an
inventory checker, not a substitute for reviewing what is committed.
"""
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
IGNORED = {'.local', '.build', '.venv', '.git', '.vscode', '__pycache__'}
MANIFEST = ROOT / 'publication-manifest.json'
# Rejected by suffix before any content inspection; other binaries are
# caught by the NUL-byte content check below regardless of suffix.
NON_SOURCE_SUFFIXES = {'.bin', '.bi', '.raw', '.raw12', '.wav', '.log', '.png', '.jpg'}


def inventory():
    result = {}
    for folder, directories, names in os.walk(ROOT):
        directories[:] = sorted(d for d in directories if d not in IGNORED)
        for name in directories + names:
            if (Path(folder) / name).is_symlink():
                raise ValueError('Public symlink: ' + str(Path(folder) / name))
        for name in sorted(names):
            path = Path(folder) / name
            relative = path.relative_to(ROOT)
            if path == MANIFEST:
                continue
            data = path.read_bytes()
            # Match the repository's LF text policy on Windows and Linux.
            text = data.decode('utf-8')
            if path.suffix.lower() in NON_SOURCE_SUFFIXES:
                raise ValueError('Non-source asset: ' + str(relative))
            if '\0' in text:
                raise ValueError('Binary content in declared file: ' + str(relative))
            data = text.replace('\r\n', '\n').encode('utf-8')
            result[relative.as_posix()] = hashlib.sha256(data).hexdigest()
    return result


if __name__ == '__main__':
    files = inventory()
    if sys.argv[1:] == ['--refresh']:
        MANIFEST.write_text(json.dumps(dict(format=1, model='Nikon Z7 II',
            firmware_included=False, files=files), indent=2) + '\n', encoding='utf-8', newline='\n')
    elif sys.argv[1:]:
        raise SystemExit('Usage: python tools/verify_release.py [--refresh]')
    declared = json.loads(MANIFEST.read_text(encoding='utf-8'))
    if declared.get('firmware_included') is not False:
        raise SystemExit('Manifest must declare firmware_included=false')
    expected = declared['files']
    if expected != files:
        raise SystemExit('Public source inventory differs; review before --refresh')
    print(f'PASS {len(files)} declared UTF-8 source files; hashes match; no firmware declared')
