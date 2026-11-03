# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute C1.70 system input classification and status-operation arguments."""
import argparse
import json
from pathlib import Path
import struct
import sys

from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_PC, UC_ARM_REG_LR

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import BASE, MASTER_SHA, require
from tools.boot_region_probe import RegionProbe


class InputClassProbe(RegionProbe):
    def __init__(self, image):
        super().__init__(image)
        self.status_count = 0
        self.status_tail = 0
        self.properties = {}
        self.queries = []
        self.operations = []

    def boundary(self, u, address, size, unused):
        a, b, c = (u.reg_read(reg) for reg in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2))
        if address == 0x10360a02:
            require(a == 0x1921 and c == 0x118, 'Unexpected status-list read')
            status = bytearray(0x118)
            struct.pack_into('<II', status, 0x110, self.status_count, self.status_tail)
            u.mem_write(b, bytes(status))
            result = 0
        elif address == 0x10360bce:
            require(a in self.properties, 'Unexpected property read')
            self.queries.append(hex(a))
            result = self.properties[a]
        elif address == 0x103f350a:
            self.operations.append(dict(value=hex(self.word(a)), callback=hex(b)))
            result = 0
        else:
            return super().boundary(u, address, size, unused)
        u.reg_write(UC_ARM_REG_R0, result)
        u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))


def probe(image):
    native = InputClassProbe(image)
    context = native.DATA + 0x1000
    cases = []
    for count, properties, expected in (
            (0, {0x1b25: 0, 0x1186: 0, 0x168c: 0}, 1),
            (0, {0x1b25: 0, 0x1186: 1, 0x168c: 1}, 2),
            (0, {0x1b25: 1, 0x1186: 1, 3: 1}, 2),
            (0, {0x1b25: 1, 0x1186: 1, 3: 0}, 1),
            (1, {}, 4), (2, {}, 4), (68, {}, 4)):
        native.status_count, native.properties = count, properties
        native.queries.clear()
        native.u.mem_write(context + 0x340, b'\xa5' * 4 + b'\xcc' * 4 + b'\x5a' * 4)
        native.call(0x1020d3b4 - BASE, context)
        result = native.u.mem_read(context + 0x344, 1)[0]
        require(result == expected, 'Native system input classification differs')
        require(bytes(native.u.mem_read(context + 0x340, 4)) == b'\xa5' * 4 and
                bytes(native.u.mem_read(context + 0x345, 7)) == b'\xcc' * 3 + b'\x5a' * 4,
                'Classification touched surrounding fields')
        require(len(native.queries) == (0 if count else 3), 'Property query count differs')
        cases.append(dict(status_count=count, properties={hex(k): v for k, v in properties.items()},
                          property_queries=list(native.queries), input_class=result))
    native.status_count, native.status_tail = 2, 0x12345678
    native.call(0x10360a06 - BASE, 0x10204d47)
    require(native.operations == [dict(value='0x12345678', callback='0x10204d47')],
            'Status operation did not forward the list tail and callback')
    return dict(format=1, firmware_included=False, master_sha256=MASTER_SHA,
        classifier='0x1020d3b4', input_class_offset='0x344', cases=cases,
        status_operation_wrapper='0x10360a06', status_operation_arguments=native.operations,
        host_boundaries=['Supply isolated status-list contents at the parameter read boundary',
                         'Supply only the queried scalar properties',
                         'Record status-operation submission without executing it'],
        limitations=['Does not establish status production or clearing in a running machine',
                     'Does not execute capture preparation or prove repeated photographs'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = probe(args.master.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8', newline='\n')
    print('PASS native system input classes, field guards and status-operation arguments')


if __name__ == '__main__':
    main()
