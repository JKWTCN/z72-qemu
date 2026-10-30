# SPDX-License-Identifier: GPL-2.0-or-later
"""Verify original dual capture configuration, latch reads and IRQ forwarding."""
import argparse
import json
from pathlib import Path
import struct
import sys

from unicorn import UC_HOOK_MEM_WRITE
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_PC, UC_ARM_REG_LR

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import MASTER_SHA, require
from tools.boot_region_probe import RegionProbe


class CaptureProbe(RegionProbe):
    RECORDER = RegionProbe.DATA + 0x4000

    def __init__(self, image):
        super().__init__(image)
        self.u.mem_map(0x2c010000, 0x2000)
        self.writes, self.callbacks, self.events, self.tasks = [], [], [], []
        self.u.hook_add(UC_HOOK_MEM_WRITE, self.write, begin=0x2c010000, end=0x2c011fff)

    def write(self, u, access, address, size, value, unused):
        self.writes.append(dict(address=hex(address), size=size, value=hex(value)))

    def boundary(self, u, address, size, unused):
        a, b = u.reg_read(UC_ARM_REG_R0), u.reg_read(UC_ARM_REG_R1)
        if address == self.RECORDER:
            self.callbacks.append(dict(notification=hex(a), status=hex(b)))
        elif address == 0x103a30f0:
            u.mem_write(a, struct.pack('<2I', 0x12345678, 0))
        elif address == 0x103610cc:
            self.events.append([hex(a), hex(b)])
        elif address == 0x103606e4:
            self.tasks.append([hex(a), hex(b)])
        else:
            return super().boundary(u, address, size, unused)
        u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))


def check(image):
    native = CaptureProbe(image)
    capabilities, configurations, reads, interrupts = [], [], [], []
    for channel in range(12):
        descriptor = 0xb18063ac + channel * 20
        table = native.word(descriptor + 8)
        registers = [native.word(table + i) for i in (0x28, 0x2c, 0x30)]
        require(bool(registers[0]) == (channel in (5, 6)), 'Capture capability differs')
        capabilities.append(dict(channel=channel, registers=[hex(x) for x in registers]))
        for enable, mode in ((0, 0), (1, 0), (1, 1)):
            native.u.mem_write(0x2c010000, bytes(0x2000))
            native.u.mem_write(native.DATA, struct.pack('<2I', enable, mode))
            a = 0x2c010100 + channel * 0x100
            native.u.mem_write(a, struct.pack('<I', 1))
            native.writes.clear()
            result = native.call(0x34e8ea, descriptor, native.DATA)
            supported = channel in (5, 6)
            require(result == (0 if supported else 2), 'Configuration status differs')
            if supported:
                require(native.word(a + 0x1010) == enable and
                        native.word(a) == (7 if enable and not mode else 1) and
                        native.word(a + 8) == (0x20 if enable and mode else 0),
                        'Capture enable or event configuration differs')
            else:
                require(not native.writes, 'Unsupported channel wrote registers')
            configurations.append(dict(channel=channel, enable=enable, mode=mode,
                                       result=result, writes=list(native.writes)))
        if channel not in (5, 6):
            continue
        native.u.mem_write(registers[1], struct.pack('<2I', 0x12345678, 0x9abcdef0))
        result = native.call(0x34e930, descriptor, native.DATA)
        values = list(struct.unpack('<2I', native.u.mem_read(native.DATA, 8)))
        require(result == 0 and values == [0x12345678, 0x9abcdef0], 'Latch read order differs')
        reads.append(dict(channel=channel, values=[hex(x) for x in values]))
        native.u.mem_write(descriptor + 0x10, struct.pack('<I', native.RECORDER | 1))
        for status in (1, 2, 4, 6, 7):
            pending = 0x2c010110 + channel * 0x100
            native.u.mem_write(pending, struct.pack('<I', status))
            native.writes.clear()
            native.callbacks.clear()
            native.call(0x34ea8a, descriptor)
            expected = dict(notification=hex(native.word(descriptor + 0xc)), status=hex(status))
            require(native.callbacks == [expected] and native.writes ==
                    [dict(address=hex(pending), size=4, value=hex(status))],
                    'Original interrupt acknowledgement or callback differs')
            interrupts.append(dict(channel=channel, callback=expected, writes=list(native.writes)))
    sampling = []
    for state, status, inhibited in ((7, 1, 0), (7, 2, 0), (7, 4, 0), (7, 6, 0),
                                      (6, 6, 0), (7, 6, 1)):
        native.u.mem_write(0xb1868628, bytes(0x100))
        native.u.mem_write(0xb1868628, bytes([state]))
        for offset, value in ((0x4c, 1), (0x50, 1), (0xe8, inhibited), (0xec, inhibited)):
            native.u.mem_write(0xb1868628 + offset, struct.pack('<I', value))
        native.u.mem_write(0xb1868880, bytes(0x48))
        native.u.mem_write(0xb18688b0, bytes([2]))
        native.u.mem_write(0xb18688b4, struct.pack('<I', 0x102e8611))
        native.u.mem_write(0xb18688bc, struct.pack('<I', 7))
        native.events.clear()
        native.tasks.clear()
        native.call(0x2cb778, 0x410a1807, status)
        active = status & 6 if not inhibited else 0
        events = [[hex(0xb1868718), hex(flag)] for bit, flag in ((4, 1), (2, 2)) if active & bit]
        tasks = [[hex(0xb23ed8d8), hex(flag)] for bit, flag in ((4, 0x100), (2, 0x1000))
                 if active & bit and state == 7]
        require(native.events == events and native.tasks == tasks,
                'Original sampling capture event or task routing differs')
        require(native.word(0xb186867c) == bool(active & 4) and
                native.word(0xb1868680) == bool(active & 2), 'Sampling capture flags differ')
        first_events, first_tasks = list(native.events), list(native.tasks)
        native.events.clear()
        native.tasks.clear()
        native.call(0x2cb778, 0x410a1807, status)
        require(not native.events and not native.tasks, 'Consumed capture wait posted repeatedly')
        sampling.append(dict(state=state, status=hex(status), inhibited=bool(inhibited),
                             events=first_events, tasks=first_tasks))
    return dict(format=1, result='passed', firmware_included=False, master_sha256=MASTER_SHA,
        configure='0x1036e8ea', read='0x1036e930', interrupt='0x1036ea8a',
        capabilities=capabilities, configurations=configurations, reads=reads, interrupts=interrupts,
        sampling_callback='0x102eb778', sampling=sampling,
        host_boundaries=['synthetic MMIO storage', 'record callback arguments and register writes',
                         'supply synthetic sampling state and timestamp; record event and task posts'],
        limitations=['Does not prove external input routing, polarity, physical timing or capture generation',
                     'Acknowledgement writes are observed; synthetic storage does not implement W1C'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = check(args.master.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8', newline='\n')
    print('PASS original delay capture: capabilities, enable, latch reads and interrupt forwarding')
