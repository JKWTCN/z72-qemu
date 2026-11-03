# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute native still-output plane offsets and processing IRQ callbacks."""
import argparse
import json
from pathlib import Path
import struct
import sys

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R4, UC_ARM_REG_SP,
                              UC_ARM_REG_LR, UC_ARM_REG_PC)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import BASE, require
from analyze.firmware_structure import analyze_eg, scatter_records


def check(image):
    identity = analyze_eg(image, 'slave')
    cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    for start, size in ((BASE, (len(image) + 4095) & ~4095),
                        (0xc1000000, 0xa00000), (0x20380000, 0x80000),
                        (0x50000000, 0x10000)):
        cpu.mem_map(start, size)
    cpu.mem_write(BASE, image)
    for row in scatter_records(image):
        if row['kind'] == 'copy' and 0xc1000000 <= row['destination'] and row['destination'] + row['size'] <= 0xc1a00000:
            begin = row['source'] - BASE
            cpu.mem_write(row['destination'], image[begin:begin + row['size']])
    events, writes = [], []

    def boundary(uc, address, size, unused):
        if address == 0x1006a954:
            events.append(dict(object=hex(uc.reg_read(UC_ARM_REG_R0)),
                               mask=hex(uc.reg_read(UC_ARM_REG_R1))))
            uc.reg_write(UC_ARM_REG_R0, 1)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

    def write(uc, access, address, size, value, unused):
        if address in (0x20380024, 0x203c0024):
            writes.append(dict(address=hex(address), value=hex(value)))

    cpu.hook_add(UC_HOOK_CODE, boundary)
    cpu.hook_add(UC_HOOK_MEM_WRITE, write)
    cpu.mem_write(0xc1001420, bytes(16))
    cpu.mem_write(0xc1001428, struct.pack('<2I', 0x100b26eb, 0x100b2699))
    irq_cases = []
    for bank, handler, task in ((0, 0x10096418, 0xc1486708), (1, 0x100963dc, 0xc148685c)):
        for cause, mask in ((0, None), (2, 1), (0x80, 0x100)):
            cpu.mem_write(0x20380024 + bank * 0x40000, struct.pack('<I', cause))
            events.clear()
            writes.clear()
            cpu.reg_write(UC_ARM_REG_SP, 0x5000e000)
            cpu.reg_write(UC_ARM_REG_LR, 0x5000f001)
            cpu.emu_start(handler | 1, 0x5000f000, count=1000)
            require(cpu.reg_read(UC_ARM_REG_PC) == 0x5000f000, 'Native processing IRQ did not return')
            expected = [] if mask is None else [dict(object=hex(task), mask=hex(mask))]
            require(events == expected and writes == [dict(address=hex(0x20380024 + bank * 0x40000), value=hex(cause))],
                    f'Native processing IRQ differs: bank={bank}, cause={cause:#x}, events={events}, writes={writes}')
            irq_cases.append(dict(bank=bank, handler=hex(handler), cause=hex(cause), events=list(events), acknowledgements=list(writes)))
    planes = []
    for width, height, secondary in ((8256, 5504, False), (8256, 5504, True), (128, 32, False)):
        header, base = 0x50001000, 0xea3b6800
        cpu.mem_write(header, bytes(0x68))
        cpu.mem_write(header + 0x1a, struct.pack('<4H', width, width, width, height))
        if secondary:
            cpu.mem_write(header + 0x48, struct.pack('<I', 1))
            cpu.mem_write(header + 0x4e, struct.pack('<4H', width, width, width, height))
        cpu.mem_write(0x5000e004, struct.pack('<I', base))
        cpu.reg_write(UC_ARM_REG_R4, header)
        cpu.reg_write(UC_ARM_REG_SP, 0x5000e000)
        cpu.emu_start(0x100cb9b1, 0x100cb9f2, count=100)
        first, second = struct.unpack('<2I', cpu.mem_read(header + 0x2c, 8))
        require(cpu.reg_read(UC_ARM_REG_PC) == 0x100cb9f2 and first == base and second == base + width * height,
                'Native processing output plane spacing differs')
        planes.append(dict(width=width, height=height, secondary_view=secondary, first=hex(first), second=hex(second), spacing=second - first))
    return dict(format=1, result='passed', firmware_included=False, slave_sha256=identity['sha256'],
        irq_cases=irq_cases, plane_cases=planes,
        host_boundaries=['Synthetic handler mode bytes and native service callback addresses',
                         'Record native task-event publication instead of executing the kernel',
                         'Output constructor fragment starts after earlier allocation and geometry setup'],
        limitations=['Synthetic MMIO causes; no hardware interrupt delivery or pixel operation',
                     'Plane spacing does not establish chroma packing or the camera color algorithm'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--slave', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    report = check(args.slave.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
    print('PASS native still-output plane offsets and processing IRQ callbacks')
