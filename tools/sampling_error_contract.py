# SPDX-License-Identifier: GPL-2.0-or-later
"""Verify original sampling error priority and notification payloads."""
import argparse
import json
from pathlib import Path
import struct
import sys

from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_PC

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import MASTER_SHA, require
from tools.boot_region_probe import RegionProbe


class ErrorProbe(RegionProbe):
    CALLBACK = RegionProbe.DATA + 0x4000

    def __init__(self, image):
        super().__init__(image)
        self.notifications = []

    def boundary(self, u, address, size, unused):
        if address != self.CALLBACK:
            return super().boundary(u, address, size, unused)
        packet = bytes(u.mem_read(u.reg_read(UC_ARM_REG_R1), 12))
        self.notifications.append(dict(notification=hex(u.reg_read(UC_ARM_REG_R0)),
            index=packet[0], state=struct.unpack_from('<I', packet, 4)[0],
            mask=hex(struct.unpack_from('<I', packet, 8)[0])))
        u.reg_write(UC_ARM_REG_PC, self.STOP)
        u.emu_stop()


def check(image):
    native = ErrorProbe(image)
    native.u.mem_write(0xb1868534, struct.pack('<I', native.CALLBACK | 1))
    cases = []
    for state in (7, 17):
        native.u.mem_write(0xb1868510, bytes([state]))
        for mask, index in ((0x10000, 2), (0x20000, 3), (0x80000, 5),
                            (0x30000, 2), (0x90000, 2), (0xa0000, 3),
                            (0xb0000, 2)):
            native.notifications.clear()
            native.call(0x24c2ac, mask)
            expected = dict(notification='0x4200181', index=index,
                            state=state, mask=hex(mask))
            require(native.notifications == [expected], 'Error priority or payload differs')
            cases.append(expected)
    return dict(result='passed', master_sha256=MASTER_SHA, cases=cases,
        limitations=['Synthetic delegate state and callback registration.',
                     'Stops before notification consumer; no device error or status is injected.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = check(args.master.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print('PASS 14 original sampling error priority cases')
