# SPDX-License-Identifier: GPL-2.0-or-later
"""Verify original notification and work-submission gates for capture contexts."""
import argparse
import json
from pathlib import Path
import struct
import sys

from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                               UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_LR, UC_ARM_REG_PC)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import MASTER_SHA, require
from tools.boot_region_probe import RegionProbe


class ContextGateProbe(RegionProbe):
    def __init__(self, image):
        super().__init__(image)
        self.jobs = []
        self.reached_allocation = False

    def boundary(self, cpu, address, size, unused):
        if address == 0x103d0eae:
            self.reached_allocation = True
            cpu.reg_write(UC_ARM_REG_PC, self.STOP)
            return
        if address in (0x10360f18, 0x10360f12, 0x103610d2):
            cpu.reg_write(UC_ARM_REG_R0, 1)
            cpu.reg_write(UC_ARM_REG_PC, cpu.reg_read(UC_ARM_REG_LR))
            return
        if address != 0x10319d56:
            return super().boundary(cpu, address, size, unused)
        self.jobs.append([cpu.reg_read(register) for register in
                          (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2)])
        cpu.reg_write(UC_ARM_REG_R0, 1)
        cpu.reg_write(UC_ARM_REG_PC, cpu.reg_read(UC_ARM_REG_LR))


def check(image):
    native = ContextGateProbe(image)
    cases = []
    for state in range(32):
        for qualifier in (0, 1, 2, 255):
            native.u.mem_write(0xb1868af1, bytes([state]))
            native.u.mem_write(0xb1868b02, bytes([qualifier]))
            native.jobs.clear()
            native.call(0x10327976 - 0x10020000, 0x041a0010)
            expected = [[0x10326675, 0, 0]] if state == 16 and qualifier == 0 else []
            require(native.jobs == expected, 'Original context construction gate differs')
            cases.append(dict(driver_state=state, qualifier=qualifier,
                              jobs=[dict(entry=hex(job[0]), bytes=job[2]) for job in native.jobs]))
    modes = []
    context = native.DATA + 0x1000
    native.u.mem_write(context, bytes(0x2d0))
    for context_kind in (1, 2):
        native.u.mem_write(context + 0xd, bytes([context_kind]))
        for manager_kind in range(4):
            for phase in range(7):
                native.u.mem_write(0xb1864d48, bytes([0, phase, manager_kind, 0]))
                native.reached_allocation = False
                result = native.call(0x103d0db0 - 0x10020000, context)
                admitted = manager_kind == context_kind and phase in (1, 2)
                require(native.reached_allocation == admitted and (admitted or result == 0),
                        'Original work submission mode gate differs')
                modes.append(dict(context_kind=context_kind, manager_kind=manager_kind,
                                  phase=phase, reached_allocation=admitted))
    # Follow the original scalar array and copy block into the kind selector.
    # The full parameter builder is deliberately outside this bounded check.
    property_id = 0x1676
    property_array = 0x118e60b4
    property_index = 0x214 // 4
    require(native.word(property_array + property_index * 4) == property_id,
            'Context property array index differs')
    group = 0x11906924 + (property_id >> 8) * 28
    index = struct.unpack('<H', native.u.mem_read(group + 12, 2))[0] + (property_id & 255)
    descriptor = 0x118fb024 + index * 16
    kind, size, pointer, _ = struct.unpack('<4I', native.u.mem_read(descriptor, 16))
    require((kind, size, pointer) == (7, 4, 0xb2551954),
            'Context property scalar descriptor differs')
    parameters, scalars = native.DATA + 0x4000, native.DATA + 0x8000
    kind_cases = []
    native.u.mem_write(0xb1868af7, b'\0')
    for parameter_mode in (0, 2):
        for value in (0, 1, 2, 255):
            native.u.mem_write(parameters, bytes(0x3000))
            native.u.mem_write(parameters, bytes([parameter_mode]))
            native.u.mem_write(pointer, struct.pack('<I', value))
            native.call(0x101004a0 - 0x10020000, property_array, scalars, 0xde)
            require(native.word(scalars + 0x214) == value, 'Original bulk scalar read differs')
            native.u.reg_write(UC_ARM_REG_R4, parameters + 0x2c90)
            native.u.reg_write(UC_ARM_REG_R5, scalars)
            native.u.emu_start(0x103585be | 1, 0x103585c6, count=4)
            require(native.u.reg_read(UC_ARM_REG_PC) == 0x103585c6 and
                    bytes(native.u.mem_read(parameters + 0x2dcd, 1)) == bytes([value]),
                    'Original scalar-to-parameter copy differs')
            result = native.call(0x10319560 - 0x10020000, parameters)
            require(result == (2 if value == 1 else 1), 'Original context kind selection differs')
            kind_cases.append(dict(parameter_mode=parameter_mode, property_value=value,
                                   parameter_2dcd=value, context_kind=result))
    return dict(format=1, result='passed', firmware_included=False, master_sha256=MASTER_SHA,
        notification='0x041a0010', callback='0x10327976', condition='0x10328190',
        driver_state='0xb1868af1', qualifier='0xb1868b02',
        deferred_entry='0x10326675', construction='0x1032642e', cases=cases,
        work_submission=dict(entry='0x103d0db0', manager='0xb1864d48',
                             allocation_boundary='0x103d0eae', cases=modes),
        kind_selection=dict(entry='0x10319560', property_id=hex(property_id),
            descriptor=hex(descriptor), scalar_address=hex(pointer),
            bulk_getter='0x101004a0', property_array=hex(property_array),
            property_index=property_index, scalar_offset='0x214',
            parameter_builder='0x103581fa', copy_block=['0x103585be', '0x103585c6'],
            output_base_offset='0x2c90', output_field_offset='0x13d',
            parameter_offset='0x2dcd', cases=kind_cases),
        host_boundaries=['Seed synthetic state and qualifier; record deferred submission without executing it',
                         'Supply uncontended locks and event clear for the submission mode check',
                         'Stop an admitted submission before allocation; no image job is created',
                         'Seed a synthetic scalar, run the original bulk getter, copy block and kind selector'],
        limitations=['Notification and initial submission gates only; no native event delivery or image processing is supplied',
                     'The kind check excludes the full parameter builder and other selector branches',
                     'Property meaning and whether a context represents a photo remain unverified',
                     'No conclusion about other producers or the required hardware timing'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    report = check(args.master.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
    print('PASS original context gates: 128 notification, 56 submission and 8 kind selection cases')
