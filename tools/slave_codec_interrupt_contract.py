# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute the slave codec IRQ with synthetic status and result registers."""
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


def check(image):
    identity = analyze_eg(image, 'slave')
    cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    for start, size in ((BASE, (len(image) + 4095) & ~4095),
                        (0xc1000000, 0xa00000), (0x24072000, 0x1000),
                        (0x50000000, 0x10000)):
        cpu.mem_map(start, size)
    cpu.mem_write(BASE, image)
    for row in scatter_records(image):
        if row['kind'] == 'copy' and 0xc1000000 <= row['destination'] and row['destination'] + row['size'] <= 0xc1a00000:
            begin = row['source'] - BASE
            cpu.mem_write(row['destination'], image[begin:begin + row['size']])
    events, acknowledgements, service_events = [], [], []

    def word(address):
        return struct.unpack('<I', cpu.mem_read(address, 4))[0]

    def boundary(uc, address, size, unused):
        if address == 0x5000d000:
            descriptor = uc.reg_read(UC_ARM_REG_R1)
            events.append(dict(notification=hex(uc.reg_read(UC_ARM_REG_R0)),
                descriptor=hex(descriptor), flags=hex(word(descriptor + 0x98)),
                result_90=hex(word(descriptor + 0x90)), result_94=hex(word(descriptor + 0x94))))
            uc.reg_write(UC_ARM_REG_R0, 0)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
        elif address == 0x1006a954:
            service_events.append(dict(object=hex(uc.reg_read(UC_ARM_REG_R0)),
                                       mask=hex(uc.reg_read(UC_ARM_REG_R1))))
            uc.reg_write(UC_ARM_REG_R0, 1)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

    def write(uc, access, address, size, value, unused):
        if address in (0x24072480, 0x2407202c):
            acknowledgements.append(dict(address=hex(address), value=hex(value)))

    cpu.hook_add(UC_HOOK_CODE, boundary)
    cpu.hook_add(UC_HOOK_MEM_WRITE, write)
    cases = []
    for name, status, mask, mode, expected_flags, expected_accumulated, notified in (
            ('empty', 0, 0xffffffff, 1, 0, 0, False),
            ('result-only', 0x08000000, 0, 1, 1, 1, False),
            ('mode-done-only', 0x1000, 0x1000, 1, 2, 2, False),
            ('masked-mode-done', 0x08001000, 0, 1, 1, 1, False),
            ('combined-mode-one', 0x08001000, 0x1000, 1, 3, 3, True),
            ('mode-zero', 0x08001000, 0x1000, 0, 3, 1, False),
            ('combined-bounds', 0x0800c000, 0xc000, 0, 0x60001, 0x60001, True),
            ('summary-error', 0x20040000, 0x40000, 1, 0x20, 0, True)):
        cpu.mem_write(0x24072000, bytes(0x1000))
        cpu.mem_write(0xc1001410, struct.pack('<4I', 0, 0, 0x50001000, 0x50002000))
        cpu.mem_write(0x50001000, bytes(0xb8))
        cpu.mem_write(0x50001014, struct.pack('<I', mode))
        cpu.mem_write(0x500010b0, struct.pack('<I', 0x5000d001))
        cpu.mem_write(0x24072020, struct.pack('<I', 0x12345678))
        cpu.mem_write(0x24072474, struct.pack('<I', 0x23456789))
        cpu.mem_write(0x2407202c, struct.pack('<I', 0x80000000))
        cpu.mem_write(0x24072480, struct.pack('<2I', status, mask))
        events.clear()
        acknowledgements.clear()
        cpu.reg_write(UC_ARM_REG_SP, 0x5000e000)
        cpu.reg_write(UC_ARM_REG_LR, 0x5000f001)
        cpu.emu_start(0x10095adf, 0x5000f000, count=10000)
        require(cpu.reg_read(UC_ARM_REG_PC) == 0x5000f000, 'Native codec IRQ did not return')
        require(word(0x50001098) == expected_flags and word(0xc1001410) == expected_accumulated,
                f'Native codec flags differ: {name}: {word(0x50001098):#x}, {word(0xc1001410):#x}')
        result_90 = 0x12345678 if status & 0x08000000 else 0
        result_94 = 0x23456789 if name == 'combined-mode-one' else 0
        require(word(0x50001090) == result_90 and word(0x50001094) == result_94,
                f'Native codec result words differ: {name}')
        expected_events = [dict(notification='0x41051401', descriptor='0x50001000',
            flags=hex(expected_flags), result_90=hex(result_90), result_94=hex(result_94))] if notified else []
        require(events == expected_events, f'Native codec notification differs: {name}: {events}')
        expected_acknowledgements = [dict(address='0x24072480', value=hex(status))]
        if status & 0x08000000:
            expected_acknowledgements.append(dict(address='0x2407202c', value='0x7fffffff'))
        require(acknowledgements == expected_acknowledgements, 'Native codec acknowledgement differs')
        require(word(0x500010ac) == status, 'Native codec raw status differs')
        cases.append(dict(name=name, status=hex(status), mask=hex(mask), mode=mode,
            flags=hex(word(0x50001098)), accumulated=hex(word(0xc1001410)),
            result_90=hex(word(0x50001090)), result_94=hex(word(0x50001094)),
            acknowledgements=list(acknowledgements), events=list(events)))
    callback_cases = []
    for flags, result, expected_status in ((3, 0x12345678, 0), (0x20, 0, 1)):
        cpu.mem_write(0xc10079b0, struct.pack('<I', 0x50004000))
        cpu.mem_write(0x50004000, bytes(0x60))
        cpu.mem_write(0x50001090, struct.pack('<3I', result, 0, flags))
        cpu.reg_write(UC_ARM_REG_SP, 0x5000e000)
        cpu.reg_write(UC_ARM_REG_LR, 0x5000f001)
        cpu.reg_write(UC_ARM_REG_R0, 0x41051401)
        cpu.reg_write(UC_ARM_REG_R1, 0x50001000)
        service_events.clear()
        cpu.emu_start(0x100b1be7, 0x5000f000, count=1000)
        require(cpu.reg_read(UC_ARM_REG_PC) == 0x5000f000 and
                cpu.mem_read(0x50004040, 1) == bytes([expected_status]) and
                word(0x50004048) == result and
                service_events == [dict(object='0xc1486460', mask='0x1')],
                'Native codec service callback result/event differs')
        callback_cases.append(dict(flags=hex(flags), result_90=hex(result),
            request_status=expected_status, request_field_48=hex(word(0x50004048)),
            events=list(service_events)))
    return dict(format=1, result='passed', firmware_included=False,
        slave_sha256=identity['sha256'], handler='0x10095ade', interrupt_id=105,
        status='0x24072480', mask='0x24072484', substatus='0x2407202c', cases=cases,
        callback_cases=callback_cases,
        host_boundaries=['Synthetic descriptor, mode, MMIO status and result words',
                         'Record the device callback and execute the separate native service callback',
                         'Record task-event publication instead of executing the kernel'],
        limitations=['No pixel reads, compressed data, hardware IRQ delivery or saved photograph',
                     'Result-word meaning is not established by this synthetic IRQ check'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--slave', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    report = check(args.slave.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
    print('PASS native slave codec IRQ flags, result words and callbacks')
