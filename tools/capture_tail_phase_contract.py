# SPDX-License-Identifier: GPL-2.0-or-later
"""Check native frame-sync notification and tail phase mask selection."""
import argparse
import json
from pathlib import Path
import struct
import sys

from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R4, UC_ARM_REG_PC, UC_ARM_REG_LR

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import MASTER_SHA, require
from tools.boot_region_probe import RegionProbe


class PhaseProbe(RegionProbe):
    CALLBACK = RegionProbe.DATA + 0x2f000

    def __init__(self, image):
        super().__init__(image)
        self.notifications, self.queue_masks, self.posts = [], [], []

    def boundary(self, u, address, size, unused):
        if address == 0x103a30f0:
            u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))
            return
        if address == self.CALLBACK:
            self.notifications.append(u.reg_read(UC_ARM_REG_R0))
        elif address == 0x1022de00:
            self.queue_masks.append(u.reg_read(UC_ARM_REG_R0))
        elif address == 0x103606e4:
            self.posts.append([hex(u.reg_read(reg)) for reg in (UC_ARM_REG_R0, UC_ARM_REG_R1)])
        else:
            return super().boundary(u, address, size, unused)
        u.reg_write(UC_ARM_REG_PC, self.STOP)
        u.emu_stop()


def check(image):
    native = PhaseProbe(image)
    native.u.mem_write(0xb18a75fc, struct.pack('<I', native.CALLBACK | 1))
    sync_cases = []
    for flags in (0, 1, 2, 3):
        native.notifications = []
        native.call(0x2b6c38, 0, flags)
        expected = [0x02010003] if flags & 1 else []
        require(native.notifications == expected, 'Native group-1 notification differs')
        sync_cases.append(dict(flags=hex(flags), notifications=[hex(x) for x in native.notifications]))
    queue_cases = []
    packet = native.DATA + 0x1000
    for value in (0, 1, 2, 255):
        native.queue_masks = []
        native.u.mem_write(packet, bytes([value]))
        native.u.reg_write(UC_ARM_REG_R4, packet)
        native.call(0x20f4a0)
        require(native.queue_masks == [2 if value else 1], 'Native tail phase clear mask differs')
        queue_cases.append(dict(first_byte=value, clear_mask=hex(native.queue_masks[0])))
    flag_cases = []
    for index in (0, 1):
        native.posts = []
        native.u.mem_write(0xb23ed65c, b'\xa5' * 16)
        native.call(0x24f714, index)
        words = list(struct.unpack('<4I', native.u.mem_read(0xb23ed65c, 16)))
        expected = [0xa5a5a5a5] * 4
        expected[index + 1] = 1
        require(words == expected and native.posts == [['0xb23ed628', '0x400']],
                'Native delegate phase flag or post differs')
        flag_cases.append(dict(index=index, words=[hex(x) for x in words], posts=native.posts))
    return dict(format=1, firmware_included=False, result='passed', master_sha256=MASTER_SHA,
        sync_callback='0x102d6c38', sync_cases=sync_cases,
        tail_gate='0x1022f4a0', queue_cases=queue_cases,
        delegate_setter='0x1026f714', flag_cases=flag_cases,
        host_boundaries=['Synthetic callback registration and packet RAM',
            'Timestamp query is intercepted without producing a timestamp',
            'Stop at native callback, queue getter or event post; their consumers do not execute'],
        limitations=['Gate fragments do not execute earlier packet routing or producer preconditions',
            'The sync callback is not a pixel producer or physical exposure timing model',
            'No whole-machine event, queue mask or descriptor is supplied'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = check(args.master.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8', newline='\n')
    print('PASS native frame-sync notification, delegate flags and tail phase masks')
