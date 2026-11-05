# SPDX-License-Identifier: GPL-2.0-or-later
"""Follow the original still-request notification to its consumer branch."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

from unicorn import UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.boot_region_probe import RegionProbe


def check(image):
    cases = []
    for count in (0, 1):
        native = RegionProbe(image)
        u = native.u
        payload = native.DATA + 0x100
        u.mem_write(payload, bytes(range(48)))
        u.mem_write(0xb18698cd, bytes([count]))
        u.mem_write(0xb1869908, struct.pack('<I', 0x103ed471))
        events = []

        def observe(u, address, size, unused):
            if address == 0x103ed470:
                events.append(dict(entry=hex(address), opcode=hex(u.reg_read(UC_ARM_REG_R0)),
                                   payload=hex(u.reg_read(UC_ARM_REG_R1))))
            if address == 0x103edaea:
                events.append(dict(consumer=hex(address), payload=hex(u.reg_read(UC_ARM_REG_R0))))
                u.emu_stop()
            elif not (0x1022cfbc <= address < 0x1022cfe8 or
                      0x102282ba <= address < 0x102282c0 or
                      0x103ed470 <= address < 0x103edce0):
                raise AssertionError(f'Unexpected notification path at {address:#x}')

        u.hook_add(UC_HOOK_CODE, observe)
        for reg, value in ((UC_ARM_REG_R0, 0xac), (UC_ARM_REG_R1, payload),
                           (UC_ARM_REG_SP, native.DATA + 0x18000),
                           (UC_ARM_REG_LR, native.STOP | 1)):
            u.reg_write(reg, value)
        u.emu_start(0x1022cfbd, native.STOP, count=10000)
        expected = ([dict(entry='0x103ed470', opcode='0x41000ac', payload=hex(payload)),
                     dict(consumer='0x103edaea', payload=hex(payload))] if count else [])
        assert events == expected, events
        assert u.reg_read(UC_ARM_REG_PC) == (0x103edaea if count else native.STOP)
        assert bytes(u.mem_read(payload, 48)) == bytes(range(48))
        cases.append(dict(subscribers=count, events=events, payload_unchanged=True))
    native = RegionProbe(image)
    choices = []
    for state, expected in ((0, 7), (1, 3), (2, 3), (3, 7), (4, 7), (5, 7), (6, 7)):
        actual = native.call(0x1022b718 - 0x10020000, state, 2)
        assert actual == expected, (state, actual)
        choices.append(dict(state=state, event=2, choice=actual))
    return dict(result='passed-original-notification-route',
                firmware_sha256=hashlib.sha256(image).hexdigest(), cases=cases,
                event_two_choices=choices,
                scope='Original broadcaster, opcode wrapper and dispatcher execute with a synthetic subscription and payload.',
                limitations=['Stops before the consumer body and capture initialization.',
                             'Does not prove runtime registration, shutter admission, sensor completion or photo output.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = check(args.master.read_bytes())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print('PASS original still notification route and empty subscription control')


if __name__ == '__main__':
    main()
