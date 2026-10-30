# SPDX-License-Identifier: GPL-2.0-or-later
"""Recover the original slave runtime arena without allocating image storage."""
import argparse
import json
from pathlib import Path
import struct
import sys

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import BASE, require
from analyze.firmware_structure import analyze_eg, scatter_records


def check(image):
    structure = analyze_eg(image, 'slave')
    cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    cpu.mem_map(BASE, (len(image) + 4095) & ~4095)
    cpu.mem_write(BASE, image)
    cpu.mem_map(0xc1000000, 0xa00000)
    for record in scatter_records(image):
        if (record['kind'] == 'copy' and 0xc1000000 <= record['destination'] and
                record['destination'] + record['size'] <= 0xc1a00000):
            offset = record['source'] - BASE
            cpu.mem_write(record['destination'], image[offset:offset + record['size']])
    stack, stop = 0x50000000, 0x50001000
    cpu.mem_map(stack, 0x2000)
    locks = []

    def boundary(uc, address, size, unused):
        if address in (0x100f96b8, 0x100f9714, 0x100f970e):
            locks.append(dict(entry=hex(address), object=hex(uc.reg_read(UC_ARM_REG_R0))))
            uc.reg_write(UC_ARM_REG_R0, 0)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

    cpu.hook_add(UC_HOOK_CODE, boundary)

    def call(address, argument=0):
        cpu.reg_write(UC_ARM_REG_R0, argument)
        cpu.reg_write(UC_ARM_REG_SP, stack + 0x800)
        cpu.reg_write(UC_ARM_REG_LR, stop | 1)
        cpu.emu_start(address | 1, stop, count=10000)
        require(cpu.reg_read(UC_ARM_REG_PC) == stop, 'Slave arena call did not return')
        return cpu.reg_read(UC_ARM_REG_R0)

    call(0x10065a38)
    current_address = 0xc1015b98
    current = lambda: int.from_bytes(cpu.mem_read(current_address, 4), 'little')
    require(current() == 0xc6100000, 'Original slave runtime arena base differs')
    cases, expected = [], current()
    for length in (0, 1, 63, 64, 65, 0xa5cc2):
        pointer = call(0x10065a4e, length)
        require(pointer == expected, 'Original slave allocation pointer differs')
        expected += (length + 63) & ~63
        require(current() == expected, 'Original slave arena alignment differs')
        cases.append(dict(requested=length, address=hex(pointer), next=hex(expected)))
    row = call(0x10065ad8, 0xc6313cc0)
    start, kind, peer, end = struct.unpack('<4I', cpu.mem_read(row, 16))
    require((start, kind, peer, end) == (0xc6100000, 1, 0x15100000, 0xc8200000),
            'Slave runtime address classification differs')
    conversions = []
    for address in (start, 0xc6313cc0, end - 1):
        converted = call(0x10065a7a, address)
        require(converted == peer + address - start, 'Slave arena bus conversion differs')
        conversions.append(dict(address=hex(address), converted=hex(converted)))
    remaining = call(0x10065a6e)
    require(remaining == end - expected + 1, 'Original remaining-size expression differs')
    return dict(format=1, result='passed', firmware_included=False,
        slave_sha256=structure['sha256'], initialize='0x10065a38', allocate='0x10065a4e',
        remaining='0x10065a6e', current_pointer=hex(current_address),
        base=hex(start), classification_end=hex(end), classification_kind=hex(kind),
        bus_base=hex(peer), conversions=conversions,
        bytes=end - start, alignment=64, cases=cases, reported_remaining=remaining,
        lock_calls=locks,
        host_boundaries=['Supply synthetic initialized state and stack; accept uncontended lock operations'],
        limitations=['The original allocator has no observed bounds check and reports end minus current plus one',
                     'Classification end is treated as the next interval boundary, not a valid last byte',
                     'No memory is mapped or written at the returned allocation addresses',
                     'No processing completion, encoded photo or file is produced'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--slave', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = check(args.slave.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8', newline='\n')
    print('PASS original slave runtime arena: base, allocation alignment and classification boundary')
