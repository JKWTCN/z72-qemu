# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute the native still-transform start order and shared IRQ dispatch."""
import argparse
import json
from pathlib import Path
import struct
import sys

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_SP,
                              UC_ARM_REG_LR, UC_ARM_REG_PC)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import BASE, require
from analyze.firmware_structure import analyze_eg, scatter_records


def check(image, capture, mode):
    identity = analyze_eg(image, 'slave')
    trace = capture['trace']
    record = next(row for row in trace['records']
                  if row['entry'] == 'capture-slave-transform-program-start' and
                  row['transform']['slot']['mode'] == mode)
    program = record['transform']['program']
    operations = program['operations']
    require(program['count'] == len(operations) == (18 if mode == 0 else 5), 'Unexpected transform recipe')
    cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    for start, size in ((BASE, (len(image) + 4095) & ~4095),
                        (0xc1000000, 0xa00000), (0x20100000, 0x1000),
                        (0x50000000, 0x10000)):
        cpu.mem_map(start, size)
    cpu.mem_write(BASE, image)
    for row in scatter_records(image):
        if row['kind'] == 'copy' and 0xc1000000 <= row['destination'] and row['destination'] + row['size'] <= 0xc1a00000:
            begin = row['source'] - BASE
            cpu.mem_write(row['destination'], image[begin:begin + row['size']])
    starts, events, acknowledgements = [], [], []

    def boundary(uc, address, size, unused):
        if address == 0x1009457c:
            starts.append(uc.reg_read(UC_ARM_REG_R1))
            uc.reg_write(UC_ARM_REG_R0, 0)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
        elif address == 0x100f9786:
            events.append(dict(object=hex(uc.reg_read(UC_ARM_REG_R0)),
                               mask=hex(uc.reg_read(UC_ARM_REG_R1))))
            uc.reg_write(UC_ARM_REG_R0, 1)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

    def write(uc, access, address, size, value, unused):
        if address in (0x20100018, 0x2010001c, 0x20100020):
            acknowledgements.append(dict(address=hex(address), value=hex(value)))

    def run(address, first=0, second=0):
        cpu.reg_write(UC_ARM_REG_SP, 0x5000e000)
        cpu.reg_write(UC_ARM_REG_LR, 0x5000f001)
        cpu.reg_write(UC_ARM_REG_R0, first)
        cpu.reg_write(UC_ARM_REG_R1, second)
        cpu.emu_start(address | 1, 0x5000f000, count=10000)
        require(cpu.reg_read(UC_ARM_REG_PC) == 0x5000f000, 'Native transform fragment did not return')

    cpu.hook_add(UC_HOOK_CODE, boundary)
    cpu.hook_add(UC_HOOK_MEM_WRITE, write)
    rows = b''.join(struct.pack('<4I', *(int(word, 16) for word in operation['words']))
                    for operation in operations)
    # The native loop first reads the count-th (sentinel) record, then walks backwards.
    cpu.mem_write(0x50002000, rows + bytes(16))
    cpu.mem_write(0x50001000, struct.pack('<IB', 0x50002000, len(operations)))
    run(0x100b146a, 0x50001000, 0x50003000)
    wait_mask = struct.unpack('<I', cpu.mem_read(0x50003000, 4))[0]
    expected_starts = [55, 41, 62, 61, 54, 53, 46, 45] if mode == 0 else [53, 41]
    require(starts == expected_starts and wait_mask == (0xe0 if mode == 0 else 0x20),
            f'Unexpected native unit starts/mask: {starts}, {wait_mask:#x}')
    # The captured operators install resource-0 callbacks in the selected slots.
    cpu.mem_write(0xc144da0c, bytes(32))
    for slot in ((4, 5, 6) if mode == 0 else (4,)):
        cpu.mem_write(0xc144da0c + slot * 4, struct.pack('<I', 0x100b13d5))
    cpu.mem_write(0xc10012b4, bytes(4))
    cpu.mem_write(0xc10012c4, bytes(4))
    cases = []
    for status, masks in ((0, []), (0x10, [0x20]), (0x20, [0x40] if mode == 0 else []),
                          (0x40, [0x80] if mode == 0 else []),
                          (0x70, [0x20, 0x40, 0x80] if mode == 0 else [0x20])):
        cpu.mem_write(0x20100018, struct.pack('<3I', 0, status, 0))
        events.clear()
        acknowledgements.clear()
        run(0x10094338)
        require(events == [dict(object='0xc14861bc', mask=hex(mask)) for mask in masks],
                f'Native transform events differ for {status:#x}: {events}')
        require(acknowledgements == [dict(address=hex(0x20100018 + index * 4), value=hex(value))
                for index, value in enumerate((0, status, 0))], 'Native IRQ acknowledgement differs')
        cases.append(dict(status_1c=hex(status), events=list(events),
                          acknowledgements=list(acknowledgements)))
    return dict(format=1, result='passed', firmware_included=False,
        slave_sha256=identity['sha256'], mode=mode, start_units=starts, wait_mask=hex(wait_mask), cases=cases,
        host_boundaries=['Use the observed recipe selectors and a zero sentinel',
            'Record unit-start calls instead of programming the hardware',
            'Install the captured resource-0 callbacks in synthetic runtime state',
            'Record kernel event publication instead of running the kernel'],
        limitations=['Synthetic MMIO status; no pixel writes or real IRQ delivery',
                     'No proof of completion of the enclosing transform request'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--slave', type=Path, required=True)
    parser.add_argument('--capture-report', type=Path, required=True)
    parser.add_argument('--mode', type=int, choices=(0, 2, 3), default=0)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    report = check(args.slave.read_bytes(), json.loads(args.capture_report.read_text(encoding='utf-8')), args.mode)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
    print('PASS native still-transform unit starts, wait mask and shared IRQ callbacks')
