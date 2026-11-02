# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute the native compute descriptor selector and trace its copied tables."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                              UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import BASE, require
from analyze.firmware_structure import analyze_eg, scatter_records


def check(image):
    structure = analyze_eg(image, 'slave')
    cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    cpu.mem_map(BASE, (len(image) + 4095) & ~4095)
    cpu.mem_write(BASE, image)
    cpu.mem_map(0xc1000000, 0xa00000)
    cpu.mem_map(0x50000000, 0x10000)
    records = scatter_records(image)
    for record in records:
        if (record['kind'] == 'copy' and 0xc1000000 <= record['destination'] and
                record['destination'] + record['size'] <= 0xc1a00000):
            offset = record['source'] - BASE
            cpu.mem_write(record['destination'], image[offset:offset + record['size']])

    bases = (0xc19218f4, 0xc1924e94)
    stride, rows = 1144, 12
    require(struct.unpack_from('<2I', image, 0x1011f0a8 - BASE) == bases[::-1],
            'Native descriptor bank literals differ')
    require(bases[1] - bases[0] == stride * rows, 'Descriptor banks are not adjacent')
    tables = []
    for bank, base in enumerate(bases):
        for row in range(rows):
            address = base + row * stride
            copies = [record for record in records if record['kind'] == 'copy' and
                      record['destination'] <= address and
                      address + stride <= record['destination'] + record['size']]
            require(len(copies) == 1, 'Descriptor does not have one complete native copy source')
            record = copies[0]
            source = record['source'] + address - record['destination']
            data = image[source - BASE:source - BASE + stride]
            require(bytes(cpu.mem_read(address, stride)) == data, 'Copied descriptor differs')
            tables.append(dict(bank=bank, row=row, address=hex(address), source=hex(source),
                               length=stride, sha256=hashlib.sha256(data).hexdigest()))

    context, descriptor, parent, metadata, stop = (
        0x50001000, 0x50002000, 0x50003000, 0x50004000, 0x5000f000)

    def put(address, *values):
        cpu.mem_write(address, struct.pack('<' + 'I' * len(values), *values))

    # Expected rows come from the selector's branch conditions, independently
    # of the address returned by executing it. Include both threshold edges.
    fixtures = [
        ('still-other-format', 1, 3, 0, 0, 0, 0, 0, 0, 0),
        ('still-format-2', 1, 2, 0, 0, 0, 0, 0, 0, 1),
        ('still-format-4', 1, 4, 0, 0, 0, 0, 0, 0, 0),
        ('preview-subtype-0', 0, 2, 0, 0, 0, 0, 2, 0, 7),
        ('preview-subtype-1', 0, 2, 0, 0, 0, 1, 2, 0, 7),
        ('preview-group-2-other', 0, 2, 0, 0, 0, 4, 2, 0, 2),
        ('preview-group-2-kind-1', 0, 2, 0, 0, 0, 4, 2, 1, 3),
        ('preview-group-2-kind-5', 0, 2, 0, 0, 0, 4, 2, 5, 3),
        ('preview-group-2-subtype-2', 0, 2, 0, 0, 0, 2, 2, 0, 4),
        ('preview-group-2-subtype-3', 0, 2, 0, 0, 0, 3, 2, 0, 4),
        ('preview-other-group', 0, 2, 0, 0, 0, 4, 0, 0, 5),
        ('preview-other-kind-1', 0, 2, 0, 0, 0, 4, 0, 1, 6),
        ('preview-other-kind-5', 0, 2, 0, 0, 0, 4, 0, 5, 6),
        ('preview-small', 0, 2, 1, 1, 0x205, 0, 0, 0, 8),
        ('preview-middle-low', 0, 2, 1, 1, 0x206, 0, 0, 0, 9),
        ('preview-middle-high', 0, 2, 1, 1, 0x40b, 0, 0, 0, 9),
        ('preview-large', 0, 2, 1, 1, 0x40c, 0, 0, 0, 10),
        ('preview-special-0', 0, 2, 1, 0, 0, 0, 0, 0, 11),
        ('preview-special-2', 0, 2, 1, 2, 0, 0, 0, 0, 11),
    ]
    cases = []
    for name, still, fmt, flag, special, dimension, subtype, group, kind, row in fixtures:
        cpu.mem_write(0x50000000, bytes(0x10000))
        put(context, descriptor, 0, parent, still)
        put(parent + 0x144, metadata)
        cpu.mem_write(descriptor + 0x24, bytes([fmt]))
        for offset, value in ((1, flag), (0x1689, special), (0x4d6, subtype),
                              (0x4d5, group), (0x4d4, kind)):
            cpu.mem_write(metadata + offset, bytes([value]))
        cpu.mem_write(metadata + 0x84e, struct.pack('<H', dimension))
        inputs = bytes(cpu.mem_read(context, 0x5000))
        for pass_value in (0, 1, 2):
            cpu.reg_write(UC_ARM_REG_R0, context)
            cpu.reg_write(UC_ARM_REG_R1, 0)
            cpu.reg_write(UC_ARM_REG_R2, pass_value)
            cpu.reg_write(UC_ARM_REG_SP, 0x5000e000)
            cpu.reg_write(UC_ARM_REG_LR, stop | 1)
            cpu.emu_start(0x1011eff1, stop, count=1000)
            require(cpu.reg_read(UC_ARM_REG_PC) == stop, 'Native selector did not return')
            bank = int(pass_value != 0)
            address = cpu.reg_read(UC_ARM_REG_R0)
            require(address == bases[bank] + row * stride, 'Native descriptor selection differs: ' + name)
            require(bytes(cpu.mem_read(context, 0x5000)) == inputs, 'Selector changed its inputs')
            cases.append(dict(name=name, supplied_still=still, supplied_format=fmt,
                metadata_fields={'0x1': flag, '0x1689': special, '0x84e': dimension,
                                 '0x4d6': subtype, '0x4d5': group, '0x4d4': kind},
                supplied_pass=pass_value, bank=bank, row=row, selected=hex(address)))
    require({case['row'] for case in cases} == set(range(rows)), 'Not all descriptor rows exercised')
    for table in tables:
        data = bytes(cpu.mem_read(int(table['address'], 0), stride))
        require(hashlib.sha256(data).hexdigest() == table['sha256'], 'Selector changed a descriptor')
    return dict(format=1, result='passed', firmware_included=False,
        slave_sha256=structure['sha256'], entry='0x1011eff0', stride=stride,
        bank_bases=[hex(base) for base in bases], rows_per_bank=rows, tables=tables, cases=cases,
        host_boundaries=['Synthetic context, RAW format and metadata; native startup copies reproduced in RAM'],
        limitations=['Branch fixtures do not establish product meanings for metadata fields',
                     'Stride-sized spans are selected table records, not decoded instructions',
                     'No compute receiver, descriptor interpretation, RAW algorithm or photograph is executed'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--slave', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = check(args.slave.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8', newline='\n')
    print('PASS native descriptor selection: 12 rows, two banks and threshold edges')
