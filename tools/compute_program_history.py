# SPDX-License-Identifier: GPL-2.0-or-later
"""Compare the complete observed compute-program payload across local updates."""
import argparse
import binascii
import hashlib
import json
from pathlib import Path
import struct
import sys

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import BASE, require
from tools.bootloader_survey import read_xor_tables
from tools.compute_program_layout import check


def survey(path, tables, program):
    raw = path.read_bytes()
    body = np.frombuffer(raw[0x20:], dtype=np.uint8).copy()
    for table, repeat in zip(tables, (1, 256, 65536)):
        body ^= np.resize(np.repeat(np.frombuffer(table, dtype=np.uint8), repeat), len(body))
    count, header_size = struct.unpack_from('>2I', body, 0x20)
    require(0 < count <= 64 and header_size == 0x30 + count * 32,
            'Invalid update member header')
    members = []
    for index in range(count):
        name, offset, size = struct.unpack_from('>16sII', body, 0x30 + index * 32)
        if name.startswith(b'eg1840_sla_'):
            require(size >= 2 and offset >= header_size and offset + size <= len(body),
                    'Invalid slave member bounds')
            members.append((name.rstrip(b'\0').decode('ascii'), body[offset:offset + size].tobytes()))
    require(len(members) == 1, 'Expected one slave member')
    name, image = members[0]
    require(binascii.crc_hqx(image, 0) == 0, 'Slave member CRC mismatch')
    offset = image.find(program)
    require(offset >= 0 and image.find(program, offset + 1) == -1,
            'Complete baseline program is absent or not unique: ' + path.name)
    return dict(package=path.name, package_sha256=hashlib.sha256(raw).hexdigest(),
        member=name, slave_sha256=hashlib.sha256(image).hexdigest(), slave_crc_valid=True,
        program_file_offset=hex(offset), program_source_address=hex(BASE + offset),
        program_bytes=len(program), complete_payload_equal=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--packages', type=Path, required=True)
    parser.add_argument('--slave', type=Path, required=True)
    parser.add_argument('--tables-source', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    baseline = args.slave.read_bytes()
    layout = check(baseline)
    offset = int(layout['source'], 0) - BASE
    program = baseline[offset:offset + layout['length']]
    tables = read_xor_tables(args.tables_source)
    rows = [survey(path, tables, program) for path in sorted(args.packages.glob('Z7_2_*.bin'))]
    require(rows, 'No historical update packages found')
    report = dict(format=1, result='passed', firmware_included=False,
        program_sha256=layout['program_sha256'], program_bytes=len(program), versions=rows,
        limitations=['Complete byte equality establishes payload presence, not historical loader execution',
                     'Host-side request preparation, configuration and memory placement may differ',
                     'No processor instruction set, calculation or photograph is established'])
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(f'PASS identical complete compute payload in {len(rows)} CRC-checked historical slave members')


if __name__ == '__main__':
    main()
