# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute the original JPEG encoder interrupt handler with synthetic status."""
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


class EncoderProbe(RegionProbe):
    RECORDER = RegionProbe.DATA + 0x4000

    def __init__(self, image):
        super().__init__(image)
        self.u.mem_map(0x24073000, 0x1000)
        self.events = []
        self.acknowledgements = []
        self.u.hook_add(UC_HOOK_MEM_WRITE, self.record_write)

    def record_write(self, u, access, address, size, value, unused):
        if address == 0x24073480:
            self.acknowledgements.append(dict(address=hex(address), bytes=size, value=hex(value)))

    def boundary(self, u, address, size, unused):
        if address == self.RECORDER:
            pointer = u.reg_read(UC_ARM_REG_R1)
            self.events.append(dict(notification=hex(u.reg_read(UC_ARM_REG_R0)),
                result_pointer=hex(pointer), flags=hex(self.word(pointer + 0x90)),
                result_word_88=self.word(pointer + 0x88)))
            u.reg_write(UC_ARM_REG_R0, 0)
            u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))
        else:
            super().boundary(u, address, size, unused)


def probe(image):
    native = EncoderProbe(image)
    current = native.DATA + 0x200
    cases = []
    for name, status, mask, mode, expected_flags, accumulated, notified in (
            ('empty', 0, 0xffffffff, 1, 0, 0, False),
            ('result-word-only', 0x08000000, 0, 1, 1, 1, False),
            ('mode-done-only', 0x1000, 0x1000, 1, 2, 2, False),
            ('masked-mode-done', 0x08001000, 0, 1, 1, 1, False),
            ('mode-zero', 0x08001000, 0x1000, 0, 3, 1, False),
            ('combined-mode-one', 0x08001000, 0x1000, 1, 3, 3, True),
            ('combined-output-bounds', 0x0800c000, 0xc000, 0, 0x60001, 0x60001, True),
            ('enabled-summary-cause', 0x20040000, 0x40000, 1, 0x20, 0, True)):
        native.u.mem_write(0x24073000, bytes(0x1000))
        native.u.mem_write(0xb1801eb0, bytes(16))
        native.u.mem_write(0xb1801eb8, struct.pack('<I', current))
        native.u.mem_write(current, bytes(0xb0))
        native.u.mem_write(current + 0x10, struct.pack('<I', mode))
        native.u.mem_write(current + 0xa8, struct.pack('<I', native.RECORDER | 1))
        native.u.mem_write(0x2407300b, bytes((0x34, 0x56, 0x78, 0x80, 0x12)))
        native.u.mem_write(0x24073470, struct.pack('<2I', 0xabcd5678, 0x13572468))
        native.u.mem_write(0x24073480, struct.pack('<2I', status, mask))
        native.events.clear()
        native.acknowledgements.clear()
        native.call(0x1036939e - 0x10020000)
        flags = native.word(current + 0x90)
        result_word_88 = native.word(current + 0x88)
        require(flags == expected_flags and native.word(0xb1801eb0) == accumulated,
                'Original JPEG encoder flag accumulation differs: ' + name)
        require(result_word_88 == (0x12345678 if status & 0x08000000 else 0),
                'Original JPEG encoder result-word order differs: ' + name)
        require(native.acknowledgements == [dict(address='0x24073480', bytes=4, value=hex(status))],
                'Original JPEG encoder status acknowledgement differs')
        expected = [dict(notification='0x41051501', result_pointer=hex(current),
                         flags=hex(expected_flags), result_word_88=result_word_88)] if notified else []
        require(native.events == expected, 'Original JPEG encoder notification differs: ' + name)
        require(native.word(current + 0xa4) == status,
                'Original JPEG raw status was not retained')
        cases.append(dict(name=name, status=hex(status), mask=hex(mask), mode=mode,
            result_flags=hex(flags), accumulated=hex(accumulated), result_word_88=result_word_88,
            acknowledgements=list(native.acknowledgements), notifications=list(native.events)))
    return dict(format=1, firmware_included=False, master_sha256=MASTER_SHA,
        handler='0x1036939e', interrupt_id=106, status='0x24073480', mask='0x24073484',
        current_pointer='0xb1801eb8', accumulated_flags='0xb1801eb0', cases=cases,
        host_boundaries=['Record the registered completion callback.'],
        limitations=['Synthetic status, mask, mode, register bytes and current descriptor.',
                    'Ordinary test storage records acknowledgement writes; no device is simulated.',
                    'No input pixels, JPEG bitstream, hardware completion or photograph is produced.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    report = probe(args.master.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('PASS original JPEG encoder interrupt flags and result-word extraction')
