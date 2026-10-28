# SPDX-License-Identifier: GPL-2.0-or-later
"""Verify original input cause routing and task-event translations."""
import argparse
import json
from pathlib import Path
import struct
import sys

from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_LR, UC_ARM_REG_PC

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import MASTER_SHA, require
from tools.boot_region_probe import RegionProbe


class FrameProbe(RegionProbe):
    def __init__(self, image):
        super().__init__(image)
        self.events = []

    def boundary(self, u, address, size, unused):
        if address in (0x103606e4, 0x103610cc):
            self.events.append((u.reg_read(UC_ARM_REG_R0), u.reg_read(UC_ARM_REG_R1)))
            u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))
        else:
            super().boundary(u, address, size, unused)


def probe(image):
    engine = FrameProbe(image)
    cases = []
    for bank, bits, logical, callback, group, events in (
            (0, 1, 0x10000000, 0x102391b2, 0, [(0xb26b3888, 1)]),
            (0, 0x40, 0x10000000, 0x102391b2, 0, [(0xb26b3888, 4)]),
            (0, 0x41, 0x10000000, 0x102391b2, 0, [(0xb26b3888, 1), (0xb26b3888, 4)]),
            (4, 0x80, 0x200, 0x1023931c, 2, [(0xb188814c, 0x4000000)]),
            (4, 0x100, 0x200, 0x1023931c, 2, [(0xb26b3888, 0x4000)])):
        status = [0] * 8
        status[bank] = bits
        engine.u.mem_write(engine.DATA, struct.pack('<8I', *status))
        result = engine.call(0x1ead46, engine.DATA)
        require(result == logical, 'Original logical cause routing differs')
        engine.events.clear()
        engine.call(callback - 0x10020000, 0x41072800 + group, engine.DATA)
        require(engine.events == events, 'Original input callback events differ')
        cases.append(dict(bank=bank, bits=hex(bits), logical=hex(result),
                          callback=hex(callback), group=group,
                          events=[dict(object=hex(target), bits=hex(value))
                                  for target, value in engine.events]))
    return dict(format=1, firmware_included=False, master_sha256=MASTER_SHA,
                cause_decoder='0x1020ad46', cases=cases,
                limitations=['Synthetic event storage and host task/event API boundaries.',
                             'Task delivery does not prove frame-buffer ownership or pixel processing.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    result = probe(args.master.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(routes=len(result['cases']))))


if __name__ == '__main__':
    main()
