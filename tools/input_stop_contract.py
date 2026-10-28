# SPDX-License-Identifier: GPL-2.0-or-later
"""Recover input stop requests and their original interrupt translations."""
import argparse
import json
from pathlib import Path
import struct
import sys

from unicorn import UC_HOOK_MEM_WRITE
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_LR, UC_ARM_REG_PC

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import MASTER_SHA, require
from tools.boot_region_probe import RegionProbe


class StopProbe(RegionProbe):
    def __init__(self, image):
        super().__init__(image)
        self.u.mem_map(0x20068000, 0x1000)
        self.writes, self.events = [], []
        self.u.hook_add(UC_HOOK_MEM_WRITE, self.write, begin=0x20068000, end=0x20068fff)

    def write(self, u, access, address, size, value, unused):
        require(size == 4, 'Unexpected input access width')
        self.writes.append((address, value))

    def boundary(self, u, address, size, unused):
        if address == 0x10361034:
            target, length = u.reg_read(UC_ARM_REG_R0), u.reg_read(UC_ARM_REG_R1)
            require(length == 32, 'Unexpected temporary clear size')
            u.mem_write(target, bytes(length))
        elif address == 0x103610cc:
            self.events.append(u.reg_read(UC_ARM_REG_R1))
        else:
            return super().boundary(u, address, size, unused)
        u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))


def probe(image):
    engine = StopProbe(image)
    cases = []
    for entry, command, logical, status, events in (
            (0x10209020, 3, 0x600, [0, 0x110, 0, 0, 0, 0, 0, 0], [4, 4]),
            (0x1020ae7c, 4, 0x10, [0, 1, 0, 0, 0, 0, 0, 0], [2]),
            (0x10208c84, 8, 0x20, [0x10000000, 0, 0, 0, 0, 0, 0, 0], [1]),
            (0x1020a05c, 0x10, 0x800, [0, 0x1000, 0, 0, 0, 0, 0, 0], [8]),
            (0x1020a17e, 0x60, 2, [0, 0, 0, 0, 0, 0, 0, 0x30], [0x10])):
        engine.u.mem_write(0x20068000, bytes(0x1000))
        engine.writes.clear()
        engine.call(entry - 0x10020000)
        require(engine.writes[-1] == (0x20068060, command), 'Input request differs')
        require((0x2006800c, logical) in engine.writes, 'Logical status clear differs')
        masks = [engine.word(0x20068200 + index * 32) for index in range(8)]
        require(masks == status, 'Stop interrupt enables differ')
        engine.u.mem_write(engine.DATA, struct.pack('<8I', *status))
        engine.u.mem_write(0xb180681c, struct.pack('<8I', *status))
        result = engine.call(0x1ea71a, 0, engine.DATA)
        require(result == logical, 'Physical-to-logical stop translation differs')
        engine.events.clear()
        engine.call(0x1ec0a8, 0, result)
        require(engine.events == events, 'Stop callback waiter events differ')
        cases.append(dict(entry=hex(entry), command=hex(command), logical=hex(logical),
                          status=[hex(value) for value in status],
                          waiter_events=[hex(value) for value in engine.events]))
    return dict(format=1, firmware_included=False, master_sha256=MASTER_SHA,
                decoder='0x1020a71a', callback='0x1020c0a8', cases=cases,
                limitations=['Synthetic memory and event API boundaries only.',
                             'No physical response latency or pixel transfer is established.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    report = probe(args.master.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(stop_commands=len(report['cases']))))


if __name__ == '__main__':
    main()
