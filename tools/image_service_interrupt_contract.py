# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute original image interrupt, service forwarding and event translation."""
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


class InterruptProbe(RegionProbe):
    def __init__(self, image):
        super().__init__(image)
        self.u.mem_map(0x20380000, 0x80000)
        self.events, self.forwarded, self.classifications, self.acknowledgements = [], [], [], []
        self.control_writes = []
        self.u.hook_add(UC_HOOK_MEM_WRITE, self.record_write)

    def record_write(self, u, access, address, size, value, unused):
        if address in (0x20380024, 0x203c0024):
            self.acknowledgements.append(dict(address=hex(address), bytes=size, value=hex(value)))
        if address in (0x20380054, 0x20380060, 0x2038006c, 0x20380078, 0x20380084, 0x203800f0):
            self.control_writes.append(dict(address=hex(address), bytes=size, value=hex(value)))

    def boundary(self, u, address, size, unused):
        a, b = u.reg_read(UC_ARM_REG_R0), u.reg_read(UC_ARM_REG_R1)
        if address in (0x102e468a, 0x102e4608):
            self.classifications.append(dict(callback=hex(address), category=a, status=hex(b)))
        if address == 0x102637c2:
            self.forwarded.append(dict(code=hex(a), payload=hex(b)))
        if address in (0x103610cc, 0x103854c4):
            self.events.append(dict(api=hex(address), object=hex(a), bits=hex(b)))
            u.reg_write(UC_ARM_REG_R0, 1)
            u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))
        else:
            super().boundary(u, address, size, unused)


def probe(image):
    native = InterruptProbe(image)
    bindings = []
    device, parameters = native.DATA, native.DATA + 0x100
    for bank in (0, 1):
        base = 0x20380000 + bank * 0x40000
        native.u.mem_write(device, bytes(4) + bytes([bank]) + bytes(3))
        native.u.mem_write(parameters, bytes([2, 5]))
        native.call(0x1036a62c - 0x10020000, device, parameters)
        require(native.word(base + 0x300) == 0x205, 'Original input control byte order differs')
        native.u.mem_write(parameters, struct.pack('<4H', 0, 0, 1380, 918))
        native.call(0x1036a642 - 0x10020000, device, parameters)
        require([native.word(base + offset) for offset in (0x304, 0x308)] == [0, 0x05640396],
                'Original input rectangle order differs')
        addresses = [0x61000000 + index * 0x10000 for index in range(16)]
        native.u.mem_write(parameters, struct.pack('<16IH', *addresses, 2080))
        native.call(0x1036a672 - 0x10020000, device, parameters)
        actual = [native.word(base + 0x310 + index * 4) for index in range(16)]
        require(actual == addresses and native.word(base + 0x30c) == 2080,
                'Original input binding or stride differs')
        native.call(0x1036a246 - 0x10020000, device, 0x1402)
        native.call(0x10369faa - 0x10020000, device)
        require([native.word(base + offset) for offset in (8, 0x10, 0x20)] == [1, 1, 0x1402],
                'Original input start or interrupt mask differs')
        bindings.append(dict(bank=bank, control_300='0x205', rectangle_304='0x0',
            size_308='0x5640396', stride_30c=2080,
            addresses_310_to_34c=[hex(value) for value in actual],
            start_08=1, start_10=1, interrupt_mask_20='0x1402'))
        native.events.clear()
        native.call(0x10369fc4 - 0x10020000, device)
        require(native.word(base + 0xc) == 1 and not native.events,
                'Original input stop command differs')
        bindings[-1]['stop_command_0c'] = 1
    cases = []
    for bank, handler, callback in ((0, 0x103699a4, 0x102e468a), (1, 0x10369968, 0x102e4608)):
        status_address = 0x20380024 + bank * 0x40000
        for name, status, forward_mask, mode, forwarded in (
                ('empty', 0, 0x1000, 0, False),
                ('bit12-forwarded', 0x1000, 0x1000, 0, True),
                ('service-masked', 0x1000, 0, 0, False),
                ('library-mode-one', 0x1000, 0x1000, 1, False),
                ('bit12-with-error-bit7', 0x1080, 0x1000, 0, True)):
            native.u.mem_write(0xb1801ecc, bytes(16))
            native.u.mem_write(0xb1801ecc + bank, bytes([mode]))
            native.u.mem_write(0xb1801ed4 + bank * 4, struct.pack('<I', callback | 1))
            native.u.mem_write(0xb18095c4, bytes(0x60))
            native.u.mem_write(0xb18095c4 + 0x18 + bank * 4, struct.pack('<I', forward_mask))
            native.u.mem_write(0xb18095c4 + 0x50 + bank * 4, struct.pack('<I', 0x102637c3))
            native.u.mem_write(status_address, struct.pack('<I', status))
            native.u.mem_write(0xb1864890 + 0x64, bytes(4))
            native.u.mem_write(0xb1864890 + 0x48, bytes(4))
            native.events.clear()
            native.forwarded.clear()
            native.classifications.clear()
            native.acknowledgements.clear()
            native.call(handler - 0x10020000)
            expected = [dict(code='0x42190805', payload=hex(status))] if forwarded else []
            require(native.forwarded == expected, 'Original service forwarding differs: ' + name)
            expected_events = [dict(api='0x103610cc', object=hex(target), bits=hex(bits))
                               for target, bits in ((0xb1864850, 0x400000), (0xb186487c, 8))] if forwarded else []
            if status & 0x80:
                expected_events.insert(0, dict(api='0x103854c4',
                    object=hex(0xb1d52938 if bank == 0 else 0xb1d52a8c), bits='0x100'))
            require(native.events == expected_events,
                    'Original service event translation differs: ' + name + ' ' + repr(native.events))
            require(native.acknowledgements == [dict(address=hex(status_address), bytes=4, value=hex(status))],
                    'Original image status acknowledgement differs')
            require(native.word(0xb1864890 + 0x48) == int(forwarded),
                    'Original service sequence update differs')
            cases.append(dict(bank=bank, name=name, status=hex(status), service_forward_mask=hex(forward_mask),
                library_mode=mode, classifications=list(native.classifications),
                acknowledgements=list(native.acknowledgements), forwarded=list(native.forwarded),
                events=list(native.events)))
    stage1_cases = []
    for skip in (0, 1):
        native.u.mem_write(0xb18648b4, bytes(0x50))
        native.u.mem_write(0xb1864900, struct.pack('<I', skip))
        native.events.clear()
        native.call(0x10262e40 - 0x10020000, 0x42193081, 1)
        expected = [dict(api='0x103610cc', object=hex(target), bits=hex(bits))
                    for target, bits in ((0xb1864850, 0x2000000),
                                         (0xb1864850, 0x40000000), (0xb186487c, 2),
                                         (0xb1864850, 0x800000))]
        if not skip:
            expected.append(dict(api='0x103610cc', object='0xb186487c', bits='0x20'))
        require(native.events == expected and native.word(0xb1864900) == 0,
                'Original stage1 input event skip differs')
        stage1_cases.append(dict(notification='0x42193081', payload='0x1',
            skip_before=skip, skip_after=0, events=list(native.events)))
    stop_cases = []
    for entry, code, bits in ((0x102637c2, 0x42190806, 0x10000),
                              (0x10264282, 0x42193084, 0x2000)):
        # No aggregate wait is requested here: recover each message's event
        # translation independently, without claiming that both arrived natively.
        native.u.mem_write(0xb1864854, bytes(4))
        native.events.clear()
        native.call(entry - 0x10020000, code)
        require(native.events == [dict(api='0x103610cc', object='0xb1864850', bits=hex(bits))],
                'Original processing-stop event translation differs')
        stop_cases.append(dict(translator=hex(entry), notification=hex(code),
                               events=list(native.events)))
    stop_ack_cases = []
    for armed in (0, 1):
        native.u.mem_write(0xb1801ecc, bytes(16))
        native.u.mem_write(0xb1801ed4, struct.pack('<I', 0x102e468b))
        native.u.mem_write(0xb18095c4, bytes(0x60))
        native.u.mem_write(0xb18095f0, struct.pack('<I', armed))
        native.u.mem_write(0x20380024, struct.pack('<I', 2))
        native.events.clear()
        native.call(0x103699a4 - 0x10020000)
        expected = [dict(api='0x103854c4', object='0xb1d52938', bits='0x20')] if armed else []
        require(native.events == expected and native.word(0xb18095f0) == 0,
                'Original armed processor stop acknowledgement differs')
        stop_ack_cases.append(dict(armed=armed, status='0x2', events=list(native.events)))
    native.u.mem_write(device, bytes(8))
    native.control_writes.clear()
    native.events.clear()
    native.call(0x10369fd2 - 0x10020000, device)
    drain_writes = list(native.control_writes)
    require(drain_writes == [dict(address=hex(address), bytes=4, value=hex(value))
                            for address, value in ((0x20380084, 0), (0x203800f0, 0xfc400),
                                (0x20380054, 1), (0x20380060, 1), (0x2038006c, 1), (0x20380078, 1))]
            and not native.events, 'Original drain request writes differ')
    drain_cases = []
    for scratch in (0, 0x53000000):
        native.u.mem_write(0xb1801ecc, bytes(16))
        native.u.mem_write(0xb1801ed4, struct.pack('<I', 0x102e468b))
        native.u.mem_write(0xb18095c4, bytes(0x60))
        native.u.mem_write(0xb18095c8, struct.pack('<I', device))
        native.u.mem_write(0xb1809600, struct.pack('<I', scratch))
        native.u.mem_write(0xb1809610, struct.pack('<I', 0xffffffff))
        native.events.clear()
        rows = []
        for status in (0x20000, 0x80000, 0x400000, 0x1000000):
            native.u.mem_write(0x20380024, struct.pack('<I', status))
            native.call(0x103699a4 - 0x10020000)
            rows.append(dict(status=hex(status), accumulated=hex(native.word(0xb1809608)),
                             events=list(native.events)))
            if status != 0x1000000 or scratch:
                require(not native.events, 'Incomplete drain generated the worker result')
        if scratch:
            require(native.word(0x20380048) == 0x14000e and native.word(0x20380300) == 2 and
                    native.word(0x2038030c) == 0x20 and native.word(0x20380310) == scratch,
                    'Original drain scratch profile differs')
            scratch_profile = {hex(offset): hex(native.word(0x20380000 + offset))
                for offset in (0, 4, 0x10, 0x44, 0x48, 0x4c, 0x50, 0x54, 0x84,
                               0xbc, 0xc0, 0xc4, 0xc8, 0xcc,
                               0x120, 0x124, 0x128, 0x12c, 0x130,
                               0x300, 0x30c, 0x310, 0x3e8, 0x3ec, 0x3f0,
                               0x410, 0x420, 0x580, 0x67c)}
            require(native.word(0x203800bc) == 1 and native.word(0x203800c4) == 20 and
                    native.word(0x203800cc) == 0 and
                    native.word(0x203803ec) == scratch and native.word(0x203803f0) == 32,
                    'Original single-bank scratch bounds or second descriptor differs')
            native.u.mem_write(0x20380024, struct.pack('<I', 2))
            native.call(0x103699a4 - 0x10020000)
        require(native.events == [dict(api='0x103854c4', object='0xb1d52938', bits='0x80')],
                'Original drain acknowledgement differs')
        drain_cases.append(dict(scratch=hex(scratch), partial_statuses=rows,
                                result_events=list(native.events)))
        if scratch:
            drain_cases[-1]['scratch_profile'] = scratch_profile
    return dict(format=1, firmware_included=False, master_sha256=MASTER_SHA,
        handlers=['0x103699a4', '0x10369968'], interrupt_ids=[99, 100],
        status_addresses=['0x20380024', '0x203c0024'], callbacks=['0x102e468a', '0x102e4608'],
        translator='0x102637c2', cases=cases,
        stage1_input_event=dict(translator='0x10262e40', skip_address='0xb1864900',
                               cases=stage1_cases),
        processing_stop_events=dict(wait_mask='0xb1864854', cases=stop_cases,
            limitation='Synthetic messages with wait mask zero; no aggregate completion or native delivery is supplied'),
        processor_stop_ack=dict(command='0x10369fc4', address='0x2038000c', value=1,
            handler='0x103699a4', armed_word='0xb18095f0', cases=stop_ack_cases),
        processor_drain=dict(command='0x10369fd2', writes=drain_writes, mask='0x14a0000',
            cases=drain_cases, limitation='Synthetic causes and scratch address; original register programming only, no DMA or hardware completion'),
        input_bindings=dict(control_setter='0x1036a62c', rectangle_setter='0x1036a642',
            addresses_setter='0x1036a672', start_setter='0x10369faa',
            interrupt_mask_setter='0x1036a246', cases=bindings,
            limitation='Register packing only; address groups, ring phase and control semantics remain unverified.'),
        host_boundaries=['Record task/event API calls without scheduling tasks.'],
        limitations=['Synthetic status, library mode and callback registration; actual binding requires runtime evidence.',
                    'Service forwarding masks are distinct from unverified hardware interrupt masks.',
                    'Ordinary register storage records acknowledgement writes without hardware clearing.',
                    'No image processing, DMA transfer, device completion or photo is generated.',
                    'Bit 12 can be forwarded together with an error category; notification alone is not success.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = probe(args.master.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print('PASS original image interrupt, service forwarding and event translation')
