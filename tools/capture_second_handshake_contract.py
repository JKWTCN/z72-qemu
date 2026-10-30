# SPDX-License-Identifier: GPL-2.0-or-later
"""Verify original second-handshake gating and GPIO reply routing in isolation."""
import argparse
import json
from pathlib import Path
import struct
import sys

from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_PC, UC_ARM_REG_LR

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import MASTER_SHA, require
from tools.boot_region_probe import RegionProbe


class HandshakeProbe(RegionProbe):
    RECORDER = RegionProbe.DATA + 0x4000

    def __init__(self, image):
        super().__init__(image)
        self.producer = None
        self.hardware, self.notifications, self.tasks = [], [], []

    def boundary(self, u, address, size, unused):
        a, b = u.reg_read(UC_ARM_REG_R0), u.reg_read(UC_ARM_REG_R1)
        if address == 0x10394710:
            self.producer = a
            u.reg_write(UC_ARM_REG_PC, self.STOP)
            u.emu_stop()
            return
        if address == 0x103a30f0:
            u.mem_write(a, bytes(8))
        elif address in (0x10385f5e, 0x10385d50, 0x103bf214, 0x103bf224):
            self.hardware.append(dict(entry=hex(address), object=hex(a), argument=b))
        elif address == self.RECORDER:
            self.notifications.append(a)
        elif address == 0x103606e4:
            self.tasks.append((a, b))
        else:
            return super().boundary(u, address, size, unused)
        u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))


def probe(image):
    native = HandshakeProbe(image)
    payload = struct.pack('<2I', 0x12345678, 0x9abcdef0)
    native.u.mem_write(native.DATA, payload)
    cases = []
    for device20 in (0, 1):
        for device22 in (0, 2):
            for processing05 in (0, 1):
                for processing12 in (0, 1):
                    for address, value in ((0xb23ecdd0, device20), (0xb23ecdd2, device22),
                                           (0xb1868315, processing05), (0xb1868322, processing12)):
                        native.u.mem_write(address, bytes([value]))
                    native.producer = None
                    native.call(0x374d06, 0x04200185, native.DATA)
                    expected = not (device20 == 1 or device22 == 2 or processing05 or processing12 == 1)
                    require(native.producer == (4 if expected else None),
                            'Native device notification second-handshake gate differs')
                    if not expected:
                        require(bytes(native.u.mem_read(0xb1868430, 8)) == payload,
                                'Suppressed branch did not retain the original device timestamp')
                    cases.append(dict(device_20=device20, device_22=device22,
                        processing_05=processing05, processing_12=processing12,
                        second_handshake=native.producer))

    native.u.mem_write(0xb18a7928, struct.pack('<2I', native.DATA + 0x100, native.DATA + 0x120))
    native.u.mem_write(0xb18a793c, struct.pack('<I', native.RECORDER | 1))
    routes = []
    for entry, mode, notification, task_event, forwarded in (
            (0x22229c, 1, 0x03030024, 0x10, 0x03030004),
            (0x2222c4, 2, 0x03030025, 0x20, 0x03030005)):
        native.hardware.clear()
        native.notifications.clear()
        native.call(entry)
        require(native.u.mem_read(0xb18a7920, 1) == bytes([mode]) and
                native.word(0xb18a7924) == 1, 'Native GPIO handshake did not arm')
        armed_hardware = list(native.hardware)
        native.call(0x222124)
        require(native.notifications == [] and native.word(0xb18a7924) == 1,
                'Pulse timer manufactured a completion notification')
        require(native.hardware[-1] == dict(entry='0x10385d50',
            object=hex(native.DATA + 0x100), argument=0), 'Timer did not lower the original output')
        native.call(0x2222ec)
        require(native.notifications == [notification] and native.word(0xb18a7924) == 0 and
                native.u.mem_read(0xb18a7920, 1) == bytes(1),
                'Original input callback did not clear and notify the matching handshake')
        native.tasks.clear()
        native.call(0x221fb2, notification)
        require(native.tasks == [(0xb2b3a1ec, task_event)], 'GPIO reply task routing differs')
        native.notifications.clear()
        native.u.mem_write(0xb18a7914, struct.pack('<I', native.RECORDER | 1))
        native.call(0x221ed8, task_event)
        require(native.notifications == [forwarded], 'GPIO reply forwarding differs')
        routes.append(dict(mode=mode, entry=hex(entry + 0x10020000),
            armed_hardware=armed_hardware, gpio_notification=hex(notification),
            task_event=hex(task_event), processing_notification=hex(forwarded)))
    return dict(format=1, firmware_included=False, master_sha256=MASTER_SHA,
        device_callback='0x10394d06', device_notification='0x04200185',
        producer='0x10394710', producer_argument=4, gate_cases=cases,
        gpio_routes=routes, timer_callback='0x10242124', input_callback='0x102422ec',
        host_boundaries=['supply synthetic parameters and timestamps',
            'stop at the second-handshake request entry', 'record GPIO and timer requests',
            'explicitly invoke the input callback in the isolated GPIO case',
            'record notifications and deferred task posts, then run their original forwarding'],
        limitations=['Does not prove native production of the device notification',
            'Does not supply a completion to a running camera or prove photo completion'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = probe(args.master.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8', newline='\n')
    print('PASS original second-handshake gates, pulse timer and input reply routing')


if __name__ == '__main__':
    main()
