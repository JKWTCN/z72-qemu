# SPDX-License-Identifier: GPL-2.0-or-later
"""Compare operation 13 references in locally supplied historical updates.

Only decoded metadata is written. Direct branches are limited to the first
0x780000 member bytes; absent references do not exclude computed calls.
"""
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
from tools.boot_region_probe import direct_thumb_calls
from tools.bootloader_survey import read_xor_tables


def survey(path, tables):
    raw = path.read_bytes()
    body = np.frombuffer(raw[0x20:], dtype=np.uint8).copy()
    for table, repeat in zip(tables, (1, 256, 65536)):
        mask = np.repeat(np.frombuffer(table, dtype=np.uint8), repeat)
        body ^= np.resize(mask, len(body))
    count = struct.unpack_from('>I', body, 0x20)[0]
    require(0 < count <= 64, 'Invalid update member count')
    masters = []
    for index in range(count):
        name, offset, size = struct.unpack_from('>16sII', body, 0x30 + index * 32)
        if name.startswith(b'eg1840_mas_'):
            require(size >= 2 and offset + size <= len(body), 'Invalid master bounds')
            masters.append((name.rstrip(b'\0').decode('ascii'),
                            body[offset:offset + size].tobytes()))
    require(len(masters) == 1, 'Expected one master member')
    name, image = masters[0]
    require(binascii.crc_hqx(image, 0) == 0, 'Master CRC mismatch')
    # The prologue and mov r1,r0 / movs r0,#13 precede callback admission.
    # The CBZ displacement and following calls vary between versions.
    candidates = []
    start = 0
    while True:
        anchor = image.find(bytes.fromhex('01460d20'), start, 0x780000)
        if anchor < 0:
            break
        if anchor >= 8 and image[anchor - 8:anchor - 2] == bytes.fromhex('38b54ff00004'):
            candidates.append(anchor - 8)
        start = anchor + 1
    require(len(candidates) == 1, 'Operation 13 signature is not unique')
    target = candidates[0]
    sites = direct_thumb_calls(image, target)
    return dict(package=path.name, package_sha256=hashlib.sha256(raw).hexdigest(),
                member=name, master_sha256=hashlib.sha256(image).hexdigest(),
                master_crc_valid=True, api_file_offset=hex(target),
                api_runtime_address=hex(BASE + target),
                direct_edges=[dict(file_offset=site,
                                   runtime_address=hex(BASE + int(site, 16)),
                                   preceding_movs_r0_zero=image[int(site, 16) - 2:
                                                                int(site, 16)] == b'\x00\x20')
                              for site in sites],
                absolute_pointer_counts={hex(BASE + target + thumb):
                    image.count(struct.pack('<I', BASE + target + thumb))
                    for thumb in (0, 1)})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--packages', required=True, type=Path)
    parser.add_argument('--tables-source', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    tables = read_xor_tables(args.tables_source)
    rows = [survey(path, tables) for path in sorted(args.packages.glob('Z7_2_*.bin'))]
    require(rows, 'No historical update packages found')
    report = dict(format=1, firmware_included=False, evidence_kind='static',
                  direct_branch_window_bytes=0x780000, versions=rows,
                  limitations=['Computed calls and other branch encodings are not covered.',
                               'Reference absence does not prove unreachable code.',
                               'No native request or pixel production is established.'])
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(versions=len(rows), output=str(args.out))))


if __name__ == '__main__':
    main()
