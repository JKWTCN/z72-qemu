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
        self.u.hook_add(UC_HOOK_MEM_WRITE, self.record_write)

    def record_write(self, u, access, address, size, value, unused):
        if address in (0x20380024, 0x203c0024):
            self.acknowledgements.append(dict(address=hex(address), bytes=size, value=hex(value)))

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
    return dict(format=1, firmware_included=False, master_sha256=MASTER_SHA,
        handlers=['0x103699a4', '0x10369968'], interrupt_ids=[99, 100],
        status_addresses=['0x20380024', '0x203c0024'], callbacks=['0x102e468a', '0x102e4608'],
        translator='0x102637c2', cases=cases,
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
