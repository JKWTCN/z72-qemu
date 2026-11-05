# SPDX-License-Identifier: GPL-2.0-or-later
"""Check the diagnostic readiness result against the original predicate."""
import argparse
import json
from pathlib import Path
import struct
import sys

from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_PC, UC_ARM_REG_LR

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import MASTER_SHA, require
from tools.boot_region_probe import RegionProbe
from tools.body_shutter_gate_probe import delegate_readiness_snapshot


class ReadinessProbe(RegionProbe):
    def read(self, address, size):
        return bytes(self.u.mem_read(address, size))

    def boundary(self, u, address, size, unused):
        if address != 0x10360f44:
            return super().boundary(u, address, size, unused)
        a, b, c = (u.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2))
        require(b == 0xb23ed698 and c == 0x38, 'Unexpected readiness copy')
        u.mem_write(a, bytes(u.mem_read(b, c)))
        u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))


def check(image):
    probe = ReadinessProbe(image)
    cases = []
    for mode, phase, kind, extra in ((0, 0, 0, 0), (2, 0, 0, 0),
                                   (0, 1, 3, 1), (2, 2, 3, 1), (1, 3, 1, 0)):
        header = bytearray(0x48)
        header[0xc:0xf] = bytes((mode, phase, kind))
        struct.pack_into('<I', header, 0x44, extra)
        probe.u.mem_write(0xb1868510, bytes(header))
        variants = [('empty', [0] * 14), ('override', [0] * 13 + [1]),
                    ('complete', [1] * 13 + [0])]
        for index in range(13):
            values = [1] * 13 + [0]
            values[index] = 0
            variants.append((f'missing-{index}', values))
        for name, values in variants:
            probe.u.mem_write(0xb23ed698, struct.pack('<14I', *values))
            observed = delegate_readiness_snapshot(probe)
            native = probe.call(0x24f6a4)
            require(native in (0, 1) and bool(native) == observed['ready'],
                    f'Readiness mismatch: {mode, phase, kind, extra, name}')
            cases.append(dict(mode=[mode, phase, kind, extra], case=name,
                              native=native, missing=observed['missing_indices']))
    return dict(result='passed', master_sha256=MASTER_SHA, cases=cases,
                limitations=['Synthetic RAM; only the bounded 56-byte copy is substituted.',
                             'Predicate agreement does not establish capture completion.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = check(args.master.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(f"PASS {len(result['cases'])} native readiness cases")
