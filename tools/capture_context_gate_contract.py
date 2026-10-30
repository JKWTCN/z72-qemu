# SPDX-License-Identifier: GPL-2.0-or-later
"""Verify the original input notification gate for deferred context construction."""
import argparse
import json
from pathlib import Path
import sys

from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_LR, UC_ARM_REG_PC

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import MASTER_SHA, require
from tools.boot_region_probe import RegionProbe


class ContextGateProbe(RegionProbe):
    def __init__(self, image):
        super().__init__(image)
        self.jobs = []

    def boundary(self, cpu, address, size, unused):
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
    return dict(format=1, result='passed', firmware_included=False, master_sha256=MASTER_SHA,
        notification='0x041a0010', callback='0x10327976', condition='0x10328190',
        driver_state='0xb1868af1', qualifier='0xb1868b02',
        deferred_entry='0x10326675', construction='0x1032642e', cases=cases,
        host_boundaries=['Seed synthetic state and qualifier; record deferred submission without executing it'],
        limitations=['Only this notification branch; no native event delivery or image processing is supplied',
                     'No conclusion about other producers or the required hardware timing'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    report = check(args.master.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
    print('PASS original context notification gate: 128 state/qualifier cases')
