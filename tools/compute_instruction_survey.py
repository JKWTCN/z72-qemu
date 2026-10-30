# SPDX-License-Identifier: GPL-2.0-or-later
"""Bound candidate instruction decodes of the observed compute-program payload."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.compute_program_layout import check


def survey(slave, objdump, wsl):
    image = slave.read_bytes()
    layout = check(image)
    offset = int(layout['source'], 0) - 0x10020000
    program = image[offset:offset + layout['length']]
    cases = []
    with tempfile.TemporaryDirectory(prefix='compute-instructions-') as folder:
        path = Path(folder).resolve() / 'program.bin'
        path.write_bytes(program)
        input_path = str(path)
        if wsl:
            input_path = '/mnt/' + path.drive[0].lower() + path.as_posix()[2:]
        prefix = ['wsl.exe', '--exec'] if wsl else []
        version = subprocess.run(prefix + [objdump, '--version'], check=True,
                                 capture_output=True, text=True).stdout.splitlines()[0]
        for processor in ('frv', 'd30v', 'mep'):
            for endian in ('little', 'big'):
                windows = []
                for start, length in ((0xc000, 0x60), (0x2420a, 0x60), (0x24e32, 0x60)):
                    result = subprocess.run(prefix + [objdump, '-D', '-z', '-b', 'binary',
                        '-m', processor, '-EL' if endian == 'little' else '-EB',
                        '--start-address=' + str(start), '--stop-address=' + str(start + length),
                        input_path], check=True, capture_output=True, text=True)
                    rows = [line for line in result.stdout.splitlines()
                            if re.match(r'^\s*[0-9a-f]+:', line)]
                    unsupported = [int(line.split(':', 1)[0], 16) for line in rows
                                   if re.search(r'\*unknown\*|--reserved--|\.(?:long|word|short|byte)\b', line)]
                    windows.append(dict(file_offset=hex(start), runtime_address=hex(0x80300000 + start),
                        requested_bytes=length, instruction_rows=len(rows),
                        unsupported_rows=len(unsupported),
                        unsupported_offsets=[hex(value) for value in unsupported]))
                cases.append(dict(processor=processor, endianness=endian, windows=windows,
                    all_windows_decoded=all(window['instruction_rows'] and
                                            not window['unsupported_rows'] for window in windows)))
    return dict(format=1, firmware_included=False, evidence_kind='static',
        program_sha256=layout['program_sha256'], decoder_version=version, cases=cases,
        limitations=['Only three candidate processor families and three short windows are covered',
                     'Table targets are candidates; their roles as code entries remain unproven',
                     'An unsupported row prevents complete decoding of this window with this configuration',
                     'A complete decode alone would not establish architecture, valid control flow or execution',
                     'No RAW computation or photograph is produced'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--slave', type=Path, required=True)
    parser.add_argument('--objdump', required=True)
    parser.add_argument('--wsl', action='store_true')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = survey(args.slave, args.objdump, args.wsl)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps(dict(configurations=len(result['cases']),
        all_windows_decoded=[case['processor'] + '/' + case['endianness']
                             for case in result['cases'] if case['all_windows_decoded']])))
