# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute the original capture readiness calculation and notification gate."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import require
from tools.boot_region_probe import RegionProbe
from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_LR, UC_ARM_REG_R0, UC_ARM_REG_R1


class ReadinessProbe(RegionProbe):
    def __init__(self, image):
        super().__init__(image)
        self.notifications = []

    def boundary(self, cpu, address, size, unused):
        if address == self.DATA + 0x2000:
            self.notifications.append([cpu.reg_read(UC_ARM_REG_R0), cpu.reg_read(UC_ARM_REG_R1)])
            cpu.reg_write(UC_ARM_REG_PC, cpu.reg_read(UC_ARM_REG_LR))
        else:
            super().boundary(cpu, address, size, unused)


def probe(image):
    native = ReadinessProbe(image)
    state = 0xb18697e0
    for index in range(2):
        native.u.mem_write(0xb1869818 + index * 8,
                           struct.pack('<II', 40, native.DATA + 0x1000 + index * 0x100))
    cases = []
    for first, second, expected in ((0, 0, 2), (1, 0, 1), (0, 1, 0), (1, 1, 1)):
        for index, value in enumerate((first, second)):
            native.u.mem_write(native.DATA + 0x1000 + index * 0x100, struct.pack('<II', value, 0))
        native.u.mem_write(state, b'\xff')
        changed = native.call(0x209080)
        actual = native.u.mem_read(state, 1)[0]
        require(changed == 1 and actual == expected, 'Original readiness bitmap precedence differs')
        require(native.call(0x209080) == 0, 'Unchanged readiness reported a change')
        cases.append(dict(first_bitmap=hex(first), second_bitmap=hex(second),
                          result=actual, changed=changed, repeat_changed=0))
    native.u.mem_write(state + 4, struct.pack('<I', (native.DATA + 0x2000) | 1))
    notification_cases = []
    for changed, enabled in ((0, 0x20), (1, 0), (1, 0x20)):
        native.notifications.clear()
        native.u.mem_write(state + 8, struct.pack('<I', enabled))
        native.call(0x2095f6, changed, 5, 0)
        expected = [[0x04100005, 0]] if changed and enabled else []
        require(native.notifications == expected, 'Original readiness notification gate differs')
        notification_cases.append(dict(changed=changed, enabled=hex(enabled),
            notifications=[dict(code=hex(code), payload=hex(payload))
                           for code, payload in native.notifications]))
    validation = []
    for value in (0, 1, 20, 39):
        result = native.call(0x20962a, value)
        require(result == int(value == 0), 'Original input predicate differs')
        validation.append(dict(input=value, result=result))
    return dict(firmware_included=False, master_sha256=hashlib.sha256(image).hexdigest(),
        calculation='0x10229080', state='0xb18697e0',
        descriptors=['0xb1869818', '0xb1869820'], cases=cases,
        notification_entry='0x102295f6', notification_cases=notification_cases,
        input_predicate='0x1022962a', input_predicate_cases=validation,
        host_boundaries=['recording notification subscriber'],
        limitation='Synthetic bitmap contract only; native pending bits, application event 1 and capture completion require separate runtime evidence.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    report = probe(args.master.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('PASS original capture readiness bitmap and notification contracts')
