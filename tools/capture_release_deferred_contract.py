# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute C1.70 deferred contact qualification against isolated mask inputs."""
import argparse
import json
from pathlib import Path
import struct
import sys

from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_PC, UC_ARM_REG_LR

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import BASE, MASTER_SHA, require
from tools.boot_region_probe import RegionProbe


class DeferredProbe(RegionProbe):
    def __init__(self, image):
        super().__init__(image)
        self.operations = []

    def boundary(self, u, address, size, unused):
        if address == 0x1022cfbc:
            self.operations.append(u.reg_read(UC_ARM_REG_R0))
        elif address != 0x10350f08:
            return super().boundary(u, address, size, unused)
        u.reg_write(UC_ARM_REG_R0, 0)
        u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))


def probe(image):
    native = DeferredProbe(image)
    cases = []
    for callback, label, pending in (
            (0x1022aa82, 'half-press', 0x20),
            (0x1022aa5c, 'full-press', 0x24)):
        for mask in (0, 1, 2):
            native.u.mem_write(0xb23f7e64, bytes(0x100))
            native.u.mem_write(0xb18698cc, bytes(0x50))
            native.u.mem_write(0xb23f7e70, struct.pack('<I', mask))
            native.operations.clear()
            native.call(callback - BASE)
            expected = [0x1a if label == 'half-press' else 0x1b] if mask == 0 else []
            require(native.operations == expected, 'Deferred contact dispatch differs')
            deferred = native.word(0xb18698cc + pending)
            require(deferred == (1 if mask == 1 else 0), 'Deferred contact flag differs')
            cases.append(dict(contact=label, callback=hex(callback), mask=mask,
                              operations=list(native.operations), deferred=deferred))
    for mask, deferred, active, expected, remaining in (
            (1, 0, 1, [], 1), (0, 1, 1, [], 1),
            (0, 0, 0, [0xaa, 0x1d], 0),
            (0, 0, 1, [0xaa, 0x1d], 0),
            (0, 0, 3, [0xaa], 2)):
        native.u.mem_write(0xb23f7e64, bytes(0x100))
        native.u.mem_write(0xb18698cc, bytes(0x50))
        native.u.mem_write(0xb23f7e70, struct.pack('<I', mask))
        native.u.mem_write(0xb23f7e6c, struct.pack('<I', active))
        native.u.mem_write(0xb18698f0, struct.pack('<I', deferred))
        native.operations.clear()
        native.call(0x1022aa24 - BASE)
        require(native.operations == expected and native.word(0xb23f7e6c) == remaining,
                'Deferred full release qualification differs')
        cases.append(dict(contact='full-release', callback='0x1022aa24', mask=mask,
            deferred=deferred, active_mask=active, remaining_mask=remaining,
            operations=list(native.operations)))
    return dict(format=1, firmware_included=False, master_sha256=MASTER_SHA,
        mask_address='0xb23f7e70', active_mask_address='0xb23f7e6c',
        deferred_half_address='0xb18698ec', deferred_full_address='0xb18698f0',
        cases=cases,
        host_boundaries=['Isolated RAM masks and flags supplied before each native callback',
                         'Record operation dispatch at 0x1022cfbc without executing subscribers',
                         'Return zero at 0x10350f08 without executing its downstream service'],
        limitations=['Does not establish native mask production or hardware wiring',
                     'Does not execute capture operations or prove repeated photo saving'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = probe(args.master.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8', newline='\n')
    print('PASS native deferred half/full qualification and full-release mask branches')


if __name__ == '__main__':
    main()
