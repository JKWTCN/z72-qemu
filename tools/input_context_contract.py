# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute original context consumer masks and counter-derived flags."""
import argparse
import json
from pathlib import Path
import struct
import sys

from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_LR, UC_ARM_REG_PC

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import MASTER_SHA, require
from tools.boot_region_probe import RegionProbe


class ContextProbe(RegionProbe):
    def boundary(self, u, address, size, unused):
        if address in (0x10360f2e, 0x10360f12, 0x10350d86, 0x1034ffbe):
            # Uncontended lock, inactive query flags and zero setting value.
            u.reg_write(UC_ARM_REG_R0, int(address == 0x10360f2e))
            u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))
        else:
            super().boundary(u, address, size, unused)


def probe(image):
    engine = ContextProbe(image)
    context = engine.DATA
    engine.u.mem_write(context + 12, b'\x03')
    releases = []
    for mask, expected in ((1, 2), (2, 0), (2, 0)):
        result = engine.call(0x30a792, context, mask)
        value = bytes(engine.u.mem_read(context + 12, 1))[0]
        require(result == expected and value == expected, 'Consumer mask release differs')
        releases.append(dict(mask=hex(mask), remaining=hex(value)))
    root = 0xb1868af0
    engine.u.mem_write(root + 6, b'\x01')
    engine.u.mem_write(root + 0xa4, struct.pack('<2I', 0, 2))
    flags = []
    for expected_flag, expected_count, expected_state in ((1, 1, 1), (1, 2, 1), (0, 2, 2)):
        engine.call(0x304f04, context + 8)
        flag = engine.word(context + 0x40)
        count = engine.word(root + 0xa4)
        state = bytes(engine.u.mem_read(root + 6, 1))[0]
        require((flag, count, state) == (expected_flag, expected_count, expected_state),
                'Counter-derived context flag differs')
        flags.append(dict(field_40=flag, counter=count, state_6=state))
    return dict(format=1, firmware_included=False, master_sha256=MASTER_SHA,
                release_entry='0x1032a792', consumer_offset='0xc', releases=releases,
                header_entry='0x10324f04', caller_argument='context + 8', flags=flags,
                limitations=['Synthetic context, driver counters, query results and uncontended locks.',
                             'These fields alone do not identify a display request or pixel-processing job.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    report = probe(args.master.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(releases=len(report['releases']), flags=len(report['flags']))))


if __name__ == '__main__':
    main()
