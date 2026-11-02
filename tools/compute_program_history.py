# SPDX-License-Identifier: GPL-2.0-or-later
"""Compare compute payloads, request tables and selector layouts across updates."""
import argparse
import binascii
import hashlib
import json
from pathlib import Path
import struct
import sys

import numpy as np
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import BASE, require
from analyze.firmware_structure import scatter_records
from tools.bootloader_survey import read_xor_tables
from tools.compute_program_layout import check


SELECTOR_FIELDS = (
    (0x1e, 'special', ARM_OP_IMM),
    (0x2c, 'dimension', ARM_OP_MEM),
    (0x4c, 'subtype', ARM_OP_MEM),
    (0x56, 'group', ARM_OP_MEM),
    (0x5a, 'kind', ARM_OP_MEM),
)


def copied_source(image, address, length):
    records = [record for record in scatter_records(image) if record['kind'] == 'copy' and
               record['destination'] <= address and
               address + length <= record['destination'] + record['size']]
    require(len(records) == 1, 'Expected one complete native table copy source')
    record = records[0]
    return record['source'] + address - record['destination']


def selector_layout(image, baseline, descriptors):
    # The unchanged prefix locates candidates. The full function is then
    # checked, permitting only the five observed metadata operand changes.
    offset = image.find(baseline[:20])
    require(offset >= 0 and image.find(baseline[:20], offset + 1) == -1,
            'Native selector prefix is absent or not unique')
    code = image[offset:offset + len(baseline)]
    normalized = bytearray(code)
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    decoder.detail = True
    fields = {}
    for site, name, operand_type in SELECTOR_FIELDS:
        expected = list(decoder.disasm(baseline[site:site + 4], 0))
        actual = list(decoder.disasm(code[site:site + 4], 0))
        require(len(expected) == len(actual) == 1 and
                expected[0].size == actual[0].size == 4, 'Invalid selector field instruction')
        expected, actual = expected[0], actual[0]
        require(expected.id == actual.id and expected.cc == actual.cc and
                expected.writeback == actual.writeback and
                len(expected.operands) == len(actual.operands) == 2 and
                expected.operands[0].type == actual.operands[0].type and
                expected.operands[0].reg == actual.operands[0].reg and
                expected.operands[1].type == actual.operands[1].type == operand_type,
                'Selector field operation changed: ' + name)
        left, right = expected.operands[1], actual.operands[1]
        if operand_type == ARM_OP_MEM:
            require((left.mem.base, left.mem.index, left.mem.scale) ==
                    (right.mem.base, right.mem.index, right.mem.scale),
                    'Selector field addressing changed: ' + name)
            fields[name] = right.mem.disp
        else:
            fields[name] = right.imm
        normalized[site:site + 4] = baseline[site:site + 4]
    require(bytes(normalized) == baseline, 'Other native selector instructions changed')
    require(tuple(fields.values()) in ((0x1681, 0x846, 0x4ca, 0x4c9, 0x4c8),
                                       (0x1689, 0x84e, 0x4d6, 0x4d5, 0x4d4)),
            'Unrecognized selector metadata layout')
    require(offset + 0xc0 <= len(image) - 2, 'Selector literal pool outside member')
    second, first = struct.unpack_from('<2I', image, offset + 0xb8)
    span = len(descriptors) // 2
    require(second == first + span, 'Historical selector banks are not adjacent')
    source = copied_source(image, first, len(descriptors))
    require(image[source - BASE:source - BASE + len(descriptors)] == descriptors,
            'Historical selector literals do not refer to the identical descriptor tables')
    return dict(file_offset=hex(offset), source_address=hex(BASE + offset),
        bytes=len(code), sha256=hashlib.sha256(code).hexdigest(),
        metadata_offsets={name: hex(value) for name, value in fields.items()},
        other_instructions_equal=True, bank_bases=[hex(first), hex(second)],
        descriptor_source_address=hex(source), descriptor_file_offset=hex(source - BASE),
        complete_descriptor_tables_equal=True)


def survey(path, tables, program, descriptors, selector):
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
        program_bytes=len(program), complete_payload_equal=True,
        request_selector=selector_layout(image, selector, descriptors))


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
    descriptor_length = 2 * 12 * 1144
    descriptor_source = copied_source(baseline, 0xc19218f4, descriptor_length)
    descriptors = baseline[descriptor_source - BASE:descriptor_source - BASE + descriptor_length]
    selector = baseline[0x1011eff0 - BASE:0x1011f096 - BASE]
    tables = read_xor_tables(args.tables_source)
    rows = [survey(path, tables, program, descriptors, selector)
            for path in sorted(args.packages.glob('Z7_2_*.bin'))]
    require(rows, 'No historical update packages found')
    report = dict(format=1, result='passed', firmware_included=False,
        program_sha256=layout['program_sha256'], program_bytes=len(program),
        descriptor_tables=dict(bytes=len(descriptors), banks=2, rows_per_bank=12, stride=1144,
            sha256=hashlib.sha256(descriptors).hexdigest()),
        selector_baseline=dict(entry='0x1011eff0', bytes=len(selector),
            sha256=hashlib.sha256(selector).hexdigest()), versions=rows,
        limitations=['Complete byte equality establishes payload presence, not historical loader execution',
                     'Selector equality permits five verified metadata operand changes; other preparation may differ',
                     'Native copy records and selector literals establish static references, not historical execution',
                     'Descriptor field meanings and compute receiver behavior remain unproven',
                     'No processor instruction set, calculation or photograph is established'])
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(f'PASS complete compute payload, descriptor tables and selector layouts in {len(rows)} CRC-checked members')


if __name__ == '__main__':
    main()
