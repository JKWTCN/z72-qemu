# SPDX-License-Identifier: GPL-2.0-or-later
"""Distinguish native processing task posts from synchronization flag updates."""
import argparse
import json
from pathlib import Path
import sys

from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_PC, UC_ARM_REG_LR

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import MASTER_SHA, require
from tools.boot_region_probe import RegionProbe


class EventProbe(RegionProbe):
    def __init__(self, image):
        super().__init__(image)
        self.effects = []

    def boundary(self, u, address, size, unused):
        a, b, c = (u.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2))
        if address in (0x103606e4, 0x103610cc, 0x103610d2):
            kind = {0x103606e4: 'task-post', 0x103610cc: 'flag-set',
                    0x103610d2: 'flag-clear'}[address]
            self.effects.append(dict(kind=kind, object=hex(a), mask=hex(b)))
            if kind != 'flag-clear':
                u.reg_write(UC_ARM_REG_PC, self.STOP)
                u.emu_stop()
                return
        elif address == 0x10360f44:
            require(c == 0x30, 'Unexpected notification copy size')
            u.mem_write(a, bytes(u.mem_read(b, c)))
        elif address not in (0x103a30f0, 0x1026d762):
            return super().boundary(u, address, size, unused)
        u.reg_write(UC_ARM_REG_R0, 0)
        u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))


def check(image):
    cases = []
    for notification, kind, target, mask in (
            (0x0420010a, 'task-post', 0xb23ecc80, 0x10),
            (0x0420010b, 'task-post', 0xb23ecc80, 0x20),
            (0x03030005, 'flag-set', 0xb186832c, 0x10)):
        probe = EventProbe(image)
        probe.u.mem_write(0xb1868310, bytes([5]))
        packet = probe.DATA + 0x1000
        probe.u.mem_write(packet, bytes(range(0x30)))
        probe.call(0x374762, notification, packet)
        expected = dict(kind=kind, object=hex(target), mask=hex(mask))
        require(probe.effects and probe.effects[-1] == expected,
                'Notification reached a different event destination')
        cases.append(dict(notification=hex(notification), effects=probe.effects))
    return dict(result='passed', master_sha256=MASTER_SHA, firmware_included=False,
        cases=cases, boundaries=[
            'Synthetic packet RAM and processing command 5',
            'Timestamp query and sampling command return zero at explicit boundaries',
            'Bounded notification copy is performed by the harness',
            'Flag clear is recorded; execution stops before task post or flag set'],
        limitations=['No task consumer, device completion or whole-machine event is supplied.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = check(args.master.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8', newline='\n')
    print('PASS processing notification destinations: two task posts and one flag update')
