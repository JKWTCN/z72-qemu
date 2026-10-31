# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute native signed coefficient expansion for compute request tables."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_SP,
                              UC_ARM_REG_LR, UC_ARM_REG_PC)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import BASE, require
from analyze.firmware_structure import analyze_eg


def check(image):
    structure = analyze_eg(image, 'slave')
    cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    cpu.mem_map(BASE, (len(image) + 4095) & ~4095)
    cpu.mem_write(BASE, image)
    for address, size in ((0xc1012000, 0x1000), (0x50000000, 0x10000),
                          (0x60000000, 0x200000)):
        cpu.mem_map(address, size)
    source_base, metadata, output, stop = 0x60000000, 0x50001000, 0x50004000, 0x5000f000
    cpu.mem_write(0xc1012f28, struct.pack('<I', source_base))
    translations, maintenance = [], []

    def boundary(uc, address, size, unused):
        if address == 0x10065a7a:
            # Identity translation is supplied only for synthetic source RAM.
            translations.append(uc.reg_read(UC_ARM_REG_R0))
        elif address == 0x10069ca4:
            maintenance.append([uc.reg_read(UC_ARM_REG_R0), uc.reg_read(UC_ARM_REG_R1)])
        else:
            return
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

    cpu.hook_add(UC_HOOK_CODE, boundary)
    cases = []
    for name, prefix, offset, columns, length in (
            ('full', bytes((0, 2, 6, 0, 0, 1, 2, 0)), 899024, 10, 1808),
            ('six-columns', bytes((5, 0, 2, 0, 0, 1, 0, 0)), 930208, 6, 1088),
            ('two-columns', bytes((5, 0, 0, 0, 0, 1, 0, 0)), 941232, 2, 368)):
        parameters = bytearray(36)
        parameters[:8] = prefix
        struct.pack_into('<h', parameters, 20, -1)
        cpu.mem_write(metadata, bytes(parameters))
        packed = bytearray(length)
        expected = bytearray(b'\xa5' * (6 * 896))
        for row in range(21):
            for bank in range(6):
                for column in range(columns):
                    if row < 12:
                        value = ((row * 67 + bank * 23 + column * 7) & 255) - 128
                        position = row * 6 * columns + bank * columns + column
                        struct.pack_into('<b', packed, position, value)
                    else:
                        value = ((row * 1237 + bank * 14753 + column * 1111) & 65535) - 32768
                        position = 12 * 6 * columns + ((row - 12) * 6 * columns +
                                                       bank * columns + column) * 2
                        struct.pack_into('<h', packed, position, value)
                    struct.pack_into('<i', expected, bank * 896 + row * 40 + column * 4, value)
        cpu.mem_write(source_base + offset, bytes(packed))
        cpu.mem_write(output - 8, b'HEADMARK' + b'\xa5' * len(expected) + b'TAILMARK')
        translations.clear()
        maintenance.clear()
        cpu.reg_write(UC_ARM_REG_R0, metadata)
        cpu.reg_write(UC_ARM_REG_R1, output)
        cpu.reg_write(UC_ARM_REG_SP, 0x5000e000)
        cpu.reg_write(UC_ARM_REG_LR, stop | 1)
        cpu.emu_start(0x101623c3, stop, count=100000)
        require(cpu.reg_read(UC_ARM_REG_PC) == stop, 'Native coefficient expansion did not return')
        actual = bytes(cpu.mem_read(output, len(expected)))
        require(actual == expected, 'Native signed expansion or untouched fields differ: ' + name)
        require(cpu.mem_read(output - 8, 8) == b'HEADMARK' and
                cpu.mem_read(output + len(expected), 8) == b'TAILMARK',
                'Native coefficient expansion changed a guard')
        require(translations == [source_base + offset] and
                maintenance == [[source_base + offset, length]],
                'Native coefficient source selection differs: ' + name)
        require(cpu.mem_read(source_base + offset, length) == packed,
                'Native coefficient expansion changed its source')
        cases.append(dict(name=name, metadata_hex=bytes(parameters).hex(), source_offset=hex(offset),
            source_bytes=length, banks=6, rows=21, columns=columns, bank_stride=896,
            row_stride=40, bytes_written=6 * 21 * columns * 4,
            output_sha256=hashlib.sha256(actual).hexdigest(),
            signed_byte_rows=12, signed_halfword_rows=9,
            guards_preserved=True, unwritten_fields_preserved=True))
    return dict(format=1, result='passed', firmware_included=False,
        slave_sha256=structure['sha256'], entry='0x101623c2', selector='0x1016223a', cases=cases,
        host_boundaries=['Synthetic metadata, signed source tables, output storage and stack',
                         'Address translation is identity for synthetic RAM; cache maintenance is recorded'],
        limitations=['Only three default-source branches with signed halfword at metadata +20 equal to -1',
                     'Interpolation, other metadata branches and real calibration contents remain unverified',
                     'No compute program, RAW pixel algorithm, result reply or photograph is produced'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--slave', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    report = check(args.slave.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
    print('PASS native signed coefficient expansion, source selection, strides and guards')
