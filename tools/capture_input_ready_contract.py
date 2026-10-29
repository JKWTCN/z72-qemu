# SPDX-License-Identifier: GPL-2.0-or-later
"""Distinguish native preview readiness from capture metadata task submission."""
import argparse
import json
from pathlib import Path
import struct
import sys

from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                               UC_ARM_REG_R3, UC_ARM_REG_PC, UC_ARM_REG_LR)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import MASTER_SHA, require
from tools.boot_region_probe import RegionProbe


class ReadyProbe(RegionProbe):
    def __init__(self, image):
        super().__init__(image)
        self.jobs, self.status = [], []
        self.events = []
        self.clears = []
        self.producer = None
        self.flags = None

    def boundary(self, u, address, size, unused):
        if address == 0x10319d56:
            entry, pointer, length, callback = [u.reg_read(reg) for reg in
                (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)]
            require(length in (0, 40), 'Unexpected ready task payload size')
            self.jobs.append(dict(entry=hex(entry), bytes=length, callback=hex(callback),
                words=list(struct.unpack('<10I', u.mem_read(pointer, 40))) if length else []))
        elif address == 0x10321894:
            self.status.append(u.reg_read(UC_ARM_REG_R0))
        elif address in (0x103606e4, 0x103610cc):
            self.events.append((u.reg_read(UC_ARM_REG_R0), u.reg_read(UC_ARM_REG_R1)))
        elif address == 0x103610d2:
            self.clears.append((u.reg_read(UC_ARM_REG_R0), u.reg_read(UC_ARM_REG_R1)))
        elif address == 0x103a30f0:
            u.mem_write(u.reg_read(UC_ARM_REG_R0), bytes(8))
        elif address == 0x103aeafe:
            require(u.reg_read(UC_ARM_REG_R0) == self.DATA + 0x1000,
                    'Capture constructor did not validate the payload context')
            u.reg_write(UC_ARM_REG_R0, 1)
        elif address == 0x1031eabe:
            self.flags = u.reg_read(UC_ARM_REG_R0)
            u.reg_write(UC_ARM_REG_PC, self.STOP)
            u.emu_stop()
            return
        elif address == 0x10395cf4:
            self.producer = hex(address)
            u.reg_write(UC_ARM_REG_PC, self.STOP)
            u.emu_stop()
            return
        else:
            return super().boundary(u, address, size, unused)
        u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))


def probe(image):
    native = ReadyProbe(image)
    words = list(range(10))
    words[7] = 3
    words[8] = native.DATA + 0x1000
    native.u.mem_write(native.DATA, struct.pack('<10I', *words))
    routes = []
    for code, pointer, entry, length in (
            (0x041a0002, 0, 0x10326677, 0),
            (0x041a0003, native.DATA, 0x103266fb, 0),
            (0x041a0005, native.DATA, 0x10326e87, 40)):
        native.jobs.clear()
        native.status.clear()
        native.call(0x307976, code, pointer)
        expected = dict(entry=hex(entry), bytes=length, callback='0x0',
                        words=words if length else [])
        require(native.jobs == [expected], 'Native notification selected a different task')
        require(native.status == ([3] if length else []), 'Native ready status differs')
        routes.append(dict(code=hex(code), payload=bool(pointer), jobs=list(native.jobs),
                           status=list(native.status)))

    payload = struct.pack('<6I', *range(6))
    native.u.mem_write(native.DATA, payload)
    native.u.mem_write(0xb18a7914, struct.pack('<I', 0x10394763))
    native.call(0x221fb2, 0x03030023, native.DATA)
    require(native.events == [(0xb2b3a1ec, 8)], 'Adapter reply selected a different task event')
    require(bytes(native.u.mem_read(0xb2b3a218, 24)) == payload, 'Adapter result copy differs')
    native.events.clear()
    native.call(0x221ed8, 8)
    require(native.events == [(0xb186832c, 0x40)], 'Processing completion event differs')
    require(bytes(native.u.mem_read(0xb23ed020, 24)) == payload, 'Processing result copy differs')
    native.events.clear()
    native.call(0x374762, 0x0420010b)
    require(native.events == [(0xb23ecc80, 0x20)], 'Input ready phase selected a different task event')
    require(native.clears == [(0xb186832c, 0x1000000)], 'Input ready phase clear differs')
    native.call(0x377b5c, native.events[0][1])
    require(native.producer == '0x10395cf4', 'Processing task selected a different producer')

    task, context, parameter = native.DATA + 0x100, native.DATA + 0x1000, native.DATA + 0x3000
    native.u.mem_write(task + 40, struct.pack('<I', context))
    native.u.mem_write(context + 0x4f4, struct.pack('<I', parameter))
    cases = []
    for auxiliary, selection, extra_context, expected in (
            (0, 0, 0, 0x220800), (0, 0, 1, 0x110400),
            (1, 0, 0, 0x882000), (1, 1, 0, 0x441000)):
        for extra_output in (0, 1):
            native.u.mem_write(context + 0x2b4, struct.pack('<I', extra_context))
            native.u.mem_write(parameter + 0xc0, bytes([auxiliary]))
            native.u.mem_write(parameter + 0xc4, struct.pack('<I', selection))
            native.u.mem_write(parameter + 0xdc, struct.pack('<I', extra_output))
            native.flags = None
            native.call(0x306e86, task)
            flags = expected | (0x4000 if extra_output else 0x8000)
            require(native.flags == flags, 'Native constructor input prerequisites differ')
            cases.append(dict(parameter_c0=auxiliary, parameter_c4=selection,
                context_2b4=extra_context, parameter_dc=extra_output, flags=hex(flags)))
    return dict(format=1, firmware_included=False, master_sha256=MASTER_SHA,
        notification='0x10327976', routes=routes, constructor='0x10326e86',
        constructor_context_payload_offset='0x20', initial_flag_cases=cases,
        upstream=dict(adapter_callback='0x10241fb2', notification='0x03030023',
            adapter_task='0x10241ed8', adapter_event='0x8', forwarded_notification='0x03030003',
            processing_callback='0x10394762', processing_task='0x10397b5c',
            completion_object='0xb186832c', completion_event='0x40',
            task_trigger='0x0420010b', task_object='0xb23ecc80', task_event='0x20',
            cleared_completion_mask='0x1000000',
            producer=native.producer, copied_bytes=24),
        host_boundaries=['record deferred task submission', 'record status update',
                         'record adapter and processing task events', 'copy synthetic results',
                         'supply a zero timestamp and record completion flag clear',
                         'stop at processing notification producer',
                         'accept synthetic context validation', 'stop at initial aggregate call'],
        limitations=['Synthetic payload and context; original routing and initial flag selection execute.',
                     'Constructor metadata work after its initial aggregate call is not executed.',
                     'Processing notification producer is selected but its body is not executed.',
                     'Completion flag and processing task use distinct objects; their connection is not executed.',
                     'Does not deliver a notification to the running camera or prove a hardware result.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    result = probe(args.master.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(routes=len(result['routes']), flag_cases=len(result['initial_flag_cases']))))


if __name__ == '__main__':
    main()
