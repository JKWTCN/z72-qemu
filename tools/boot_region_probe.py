# SPDX-License-Identifier: GPL-2.0-or-later
"""Recover original storage regions and bound the boot-region API.

Requires Unicorn, NumPy and Capstone. Original lookup, request construction
and retry code run against synthetic RAM. Host queue callbacks reject program
requests and acknowledge erase requests without modifying storage. A separate
read checks synthetic boot data only. No real device is opened or key exported.
"""
import argparse
import json
from pathlib import Path
import struct
import sys

import numpy as np
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import (UC_CPU_ARM_CORTEX_A15, UC_ARM_REG_R0,
                               UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_SP,
                               UC_ARM_REG_LR, UC_ARM_REG_PC)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import BASE, MASTER_SHA, require, validate_master
from analyze.firmware_structure import scatter_records


def direct_thumb_calls(image, target):
    """Find BL and unconditional B.W edges in the bounded main code window."""
    half = np.frombuffer(image[:0x780000], dtype='<u2').astype(np.int64)
    low = half[1:] & 0xD000
    indices = np.flatnonzero(((half[:-1] & 0xF800) == 0xF000) &
                             ((low == 0xD000) | (low == 0x9000)))
    first, second = half[indices], half[indices + 1]
    sign = (first >> 10) & 1
    displacement = ((sign << 24) | ((1 ^ ((second >> 13) & 1) ^ sign) << 23) |
                    ((1 ^ ((second >> 11) & 1) ^ sign) << 22) |
                    ((first & 1023) << 12) | ((second & 2047) << 1))
    displacement = np.where(sign, displacement - (1 << 25), displacement)
    destinations = indices * 2 + 4 + displacement
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    sites = []
    for offset in (indices[destinations == target] * 2).tolist():
        instruction = next(decoder.disasm(image[offset:offset + 4], offset))
        require(instruction.mnemonic in ('b.w', 'bl') and
                int(instruction.op_str.lstrip('#'), 16) == target, 'Branch decode mismatch')
        sites.append(hex(offset))
    return sites


class RegionProbe:
    DATA = 0x50000000
    STOP = DATA + 0x20000

    def __init__(self, image):
        validate_master(image)
        self.u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        self.u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15)
        self.u.mem_map(0x10000000, 0x20000)
        self.u.mem_map(BASE, (len(image) + 4095) & ~4095)
        self.u.mem_map(0xB1800000, 0x4800000)
        self.u.mem_map(self.DATA, 0x30000)
        self.u.mem_write(BASE, image)
        for record in scatter_records(image):
            if record['kind'] == 'copy':
                offset = record['source'] - BASE
                self.u.mem_write(record['destination'], image[offset:offset + record['size']])
        self.programs, self.erases, self.copies = [], [], []
        self.u.hook_add(UC_HOOK_CODE, self.boundary)

    def word(self, address):
        return struct.unpack('<I', self.u.mem_read(address, 4))[0]

    def boundary(self, u, address, size, unused):
        offset = address - BASE
        if offset not in (0x3482E0, 0x348302, 0x3513B8, 0x3513F8, 0x340FAC):
            return
        a, b, c = [u.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2)]
        result = 0
        if offset == 0x3513B8:
            self.programs.append((a, b, c))
            result = 2  # Reject before handing any bytes to a storage device.
        elif offset == 0x3513F8:
            self.erases.append((a, b))
        elif offset == 0x340FAC:
            require(c <= 0x20000, 'Unexpected copy size')
            self.copies.append((a, b, c))
            u.mem_write(a, bytes(u.mem_read(b, c)))
            result = a
        u.reg_write(UC_ARM_REG_R0, result)
        u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))

    def call(self, offset, a=0, b=0, c=0):
        for reg, value in zip((UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2), (a, b, c)):
            self.u.reg_write(reg, value)
        self.u.reg_write(UC_ARM_REG_SP, self.DATA + 0x18000)
        self.u.reg_write(UC_ARM_REG_LR, self.STOP | 1)
        self.u.emu_start(BASE + offset | 1, self.STOP, count=100000)
        require(self.u.reg_read(UC_ARM_REG_PC) == self.STOP, 'Native call did not return')
        return self.u.reg_read(UC_ARM_REG_R0)

    def run(self, image):
        objects = []
        for index in range(81):
            pointer = self.call(0x2286F6, index)
            require(pointer == 0xB185EB70 + index * 28, 'Object lookup mismatch')
            objects.append(dict(id=index, region=self.word(pointer + 20),
                                offset=hex(self.word(pointer + 4)),
                                initial_length=self.word(pointer + 12)))
        require(self.call(0x2286F6, 81) == 0, 'Object upper bound mismatch')
        require(max(item['region'] for item in objects) == 32, 'Unexpected region extent')
        regions = []
        for index in range(33):
            pointer = self.call(0x2286E4, index)
            require(pointer == 0xB185E5C4 + index * 44, 'Region lookup mismatch')
            first, alternate, span, capacity = struct.unpack('<4I', self.u.mem_read(pointer, 16))
            regions.append(dict(id=index, address=hex(pointer), primary=hex(first),
                                alternate=hex(alternate), span=span, capacity=capacity,
                                contains_material=first <= 0x10000088 < first + span))
        require([r['id'] for r in regions if r['contains_material']] == [0, 1],
                'Boot region set mismatch')
        cases = []
        self.u.mem_write(self.DATA, bytes([0xA5]) * 256)
        for object_id, length in ((0, 256), (1, 256), (2, 256), (0, 0x20002)):
            self.programs.clear()
            self.erases.clear()
            result = self.call(0x39F6CC, object_id, self.DATA, length)
            require(result == 0, 'Rejected program request unexpectedly succeeded')
            expected = [(0x10000000, self.DATA, 128)] * 9 if object_id == 0 and length == 256 else []
            require(self.programs == expected, 'Program forwarding mismatch: ' +
                    repr((object_id, length, self.programs, self.erases)))
            require(self.erases == ([(0, 1)] * 3 if expected else []), 'Erase forwarding mismatch')
            cases.append(dict(object_id=object_id, input_length=length, result=result,
                              program_attempts=len(self.programs),
                              erase_attempts=len(self.erases),
                              destinations=[hex(a) for a, _, _ in self.programs],
                              program_lengths=[c * 2 for _, _, c in self.programs],
                              source_is_supplied_buffer=bool(expected),
                              request_overlaps_material=bool(expected)))
        sample = bytes((17 * index + 3) & 255 for index in range(256))
        self.u.mem_write(0x10000000, sample)
        self.copies.clear()
        result = self.call(0x39F7D4, 0, self.DATA + 0x1000, 256)
        require(result == 1 and bytes(self.u.mem_read(self.DATA + 0x1000, 256)) == sample,
                'Boot-region read mismatch')
        require(self.copies == [(self.DATA + 0x1000, 0x10000000, 256)],
                'Unexpected read copy path')
        return dict(format=1, firmware_included=False, master_sha256=MASTER_SHA,
                    regions=regions, objects=objects, write_cases=cases,
                    synthetic_read=dict(object_id=0, bytes=256, source='0x10000000',
                                        result=result, includes_material=True),
                    staged_transfer_object_ids=list(image[0x119E5B48 - BASE:0x119E5B48 - BASE + 6]),
                    startup_descriptor_78_object_id=image[0x118FAB04 - BASE + 78 * 16],
                    main_code_scan_end='0x780000',
                    direct_thumb_write_callers=direct_thumb_calls(image, 0x39F6CC),
                    host_boundaries=['locks', 'rejected program queue',
                                     'synthetic erase queue acknowledgement', 'bulk copy'],
                    real_storage_written=False, actual_material_read=False,
                    initializer_found=False, k8_recovered=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    image = args.master.read_bytes()
    report = RegionProbe(image).run(image)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
    print('PASS 33 regions, 81 objects, boot write forwarding/rejection and synthetic read')
