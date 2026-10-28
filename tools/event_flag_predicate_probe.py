# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute the original C 1.70 event-flag predicate, without its scheduler."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM
from unicorn.arm_const import (UC_ARM_REG_R2, UC_ARM_REG_R4, UC_ARM_REG_R6,
                               UC_ARM_REG_R7, UC_ARM_REG_PC)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import require, validate_master


def check(image):
    validate_master(image)

    def word(address):
        return struct.unpack_from('<I', image, address - 0x10020000)[0]

    require(struct.unpack_from('<H', image, 0x3411a2)[0] == 0x2200,
            'Wait wrapper no longer selects mode 0')
    selector = (0x80300500 >> 16) - (1 << 16)
    table = word(0x101077e0)
    require(word(table + selector * 4) == 0x10111410, 'Wait syscall target changed')
    machine = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    machine.mem_map(0x10111000, 0x1000)
    machine.mem_write(0x10111000, image[0xf1000:0xf2000])
    machine.mem_map(0x50000000, 0x1000)
    cases = []
    for mode in (0, 1):
        for available in (0, 8, 0x10, 0x18):
            machine.mem_write(0x50000014, struct.pack('<I', available))
            for register, value in ((UC_ARM_REG_R4, 0x50000000),
                    (UC_ARM_REG_R6, mode), (UC_ARM_REG_R7, 0x18), (UC_ARM_REG_R2, 0xdead)):
                machine.reg_write(register, value)
            machine.emu_start(0x10111608, 0x10111634, count=16)
            require(machine.reg_read(UC_ARM_REG_PC) == 0x10111634, 'Predicate escaped its bound')
            matched = bool(machine.reg_read(UC_ARM_REG_R2))
            expected = (available & 0x18) == 0x18 if mode == 0 else bool(available & 0x18)
            require(matched == expected, 'Original predicate differs from the expected wait modes')
            cases.append(dict(mode=mode, available=hex(available), requested='0x18', matched=matched))
    window = image[0xf1608:0xf166c]
    return dict(observation='original-kernel-event-flag-predicate', firmware_used=True,
        wrapper='0x10361192', wrapper_mode=0, svc_descriptor='0x80300500',
        syscall_table=hex(table), handler='0x10111410', predicate='0x10111608',
        stop_before='0x10111634', synthetic_flag_object=True, scheduler_executed=False,
        code_window=dict(file_offset='0xf1608', length=len(window),
                         sha256=hashlib.sha256(window).hexdigest()),
        result='passed', cases=cases,
        conclusion='Mode 0 requires all requested bits; mode 1 accepts any requested bit.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    report = check(args.master.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
    print('PASS original event-flag predicate: 8 cases, bounded instruction execution')
