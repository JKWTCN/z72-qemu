# SPDX-License-Identifier: GPL-2.0-or-later
"""Trace the original scalar-to-silent-format path with synthetic parameters."""
import argparse
import json
from pathlib import Path
import struct
import sys

from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
    UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_LR, UC_ARM_REG_PC)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import BASE, MASTER_SHA, require
from tools.boot_region_probe import RegionProbe


class SilentParameterProbe(RegionProbe):
    def __init__(self, image):
        super().__init__(image)
        self.updates = []

    def boundary(self, cpu, address, size, unused):
        if address != 0x1032b854:
            return super().boundary(cpu, address, size, unused)
        count, keys, values = (cpu.reg_read(register) for register in
                              (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2))
        require(count == 1, 'Unexpected silent parameter batch length')
        self.updates.append([self.word(keys), self.word(values)])
        cpu.reg_write(UC_ARM_REG_R0, 1)
        cpu.reg_write(UC_ARM_REG_PC, cpu.reg_read(UC_ARM_REG_LR))


def check(image):
    native = SilentParameterProbe(image)
    registration = 0x118f65a8
    require(native.word(registration) == 0x057a and
            native.word(registration + 16) == 0x10336a69,
            'Silent request parameter registration differs')
    source, context = native.DATA + 0x8000, native.DATA + 0x8100
    normalized = []
    for requested in (0, 1):
        for flags in (0, 1, 0x20, 0x200):
            native.u.mem_write(source, struct.pack('<9I', 0, requested, 0, flags, 0, 0, 0, 0, 0))
            native.u.mem_write(context, bytes(0x144))
            native.updates.clear()
            native.u.reg_write(UC_ARM_REG_R3, context)
            result = native.call(0x10336a68 - BASE, 0, source, 0)
            expected = [] if flags & 0x220 else [[0x161d, requested if not flags else 0]]
            require(result == 1 and native.updates == expected,
                    'Original silent request normalization differs')
            require(native.word(context + 0x140) == int(bool(expected)),
                    'Silent normalization change marker differs')
            normalized.append(dict(requested=requested, flags=hex(flags), updates=native.updates[:]))
    property_id, property_array = 0x161d, 0x118e60b4
    require(native.word(property_array + 0x138) == property_id,
            'Silent scalar array entry differs')
    group = 0x11906924 + (property_id >> 8) * 28
    index = struct.unpack('<H', native.u.mem_read(group + 12, 2))[0] + (property_id & 255)
    descriptor = 0x118fb024 + index * 16
    require(struct.unpack('<3I', native.u.mem_read(descriptor, 12)) ==
            (7, 4, 0xb25517dc), 'Silent scalar descriptor differs')
    parameters, scalars, request = (native.DATA + offset for offset in (0x1000, 0x6000, 0x7000))
    cases = []
    tables = {1: (0x119cebcc, 'Still'), 2: (0x119cf04c, 'StillSilent'),
              0x100: (0x119cf4cc, 'LvStill'), 0x200: (0x119cf94c, 'LvStillSilent')}
    for runtime_state in (0, 2):
        for value in (0, 1, 2, 255):
            native.u.mem_write(parameters, bytes(0x3000))
            native.u.mem_write(0xb25517dc, struct.pack('<I', value))
            require(native.call(0x1063c7d4 - BASE, property_id) == value,
                    'Original camera parameter getter differs')
            native.call(0x101004a0 - BASE, property_array, scalars, 0xde)
            require(native.word(scalars + 0x138) == value, 'Silent bulk read differs')
            guard = b'\xa5' * 9
            native.u.mem_write(parameters + 0x2e63, guard)
            native.u.reg_write(UC_ARM_REG_R4, parameters + 0x2c90)
            native.u.reg_write(UC_ARM_REG_R5, scalars)
            native.u.emu_start(0x10358670 | 1, 0x10358678, count=4)
            require(native.u.reg_read(UC_ARM_REG_PC) == 0x10358678 and
                    bytes(native.u.mem_read(parameters + 0x2e63, 9)) ==
                    guard[:4] + bytes([value]) + guard[5:], 'Silent field copy or guards differ')
            native.u.mem_write(0xb1887d7d, bytes([runtime_state]))
            native.u.mem_write(request, bytes(8))
            native.u.reg_write(UC_ARM_REG_R3, request)
            native.call(0x102324cc - BASE, parameters, 0, 0)
            mask = struct.unpack('<H', native.u.mem_read(request, 2))[0]
            expected = (2 if value == 1 else 1) * (1 if runtime_state == 2 else 0x100)
            require(mask == expected, 'Original capture format mask differs')
            table = native.call(0x1034f918 - BASE, mask)
            label = bytes(native.u.mem_read(native.word(0xb2951148), 20)).split(b'\0')[0].decode()
            require((table, label) == tables[expected], 'Original format table selection differs')
            cases.append(dict(runtime_state=runtime_state, scalar=value,
                parameter_byte=value, format_mask=hex(mask), table=hex(table), label=label))
    return dict(format=1, result='passed', firmware_included=False, master_sha256=MASTER_SHA,
        request_property='0x057a', request_registration=hex(registration),
        request_processor='0x10336a68', normalized_cases=normalized,
        property='0x161d', descriptor=hex(descriptor), scalar_address='0xb25517dc',
        property_array=hex(property_array), scalar_offset='0x138', bulk_getter='0x101004a0',
        camera_parameter_getter='0x1063c7d4',
        copy_block=['0x10358670', '0x10358678'], parameter_offset='0x2e67',
        format_builder='0x102324cc', table_selector='0x1034f918', cases=cases,
        limitations=['Synthetic request descriptors; record and acknowledge the derived batch at 0x1032b854',
                     'Synthetic scalar and runtime state; full parameter construction is outside this check',
                     'Does not exercise native setting validation, propagation, capture or mechanical sampling',
                     'Only scalar value 1 selects the recovered silent tables; other values are negative cases'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    report = check(args.master.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('PASS: original silent scalar, guarded field copy and normal/silent table selection')


if __name__ == '__main__':
    main()
