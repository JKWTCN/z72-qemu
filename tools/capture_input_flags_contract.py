# SPDX-License-Identifier: GPL-2.0-or-later
"""Recover original capture-input aggregate prerequisites with synthetic flags."""
import argparse
import json
from pathlib import Path
import struct
import sys

from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_PC, UC_ARM_REG_LR

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import MASTER_SHA, require
from tools.boot_region_probe import RegionProbe


class FlagsProbe(RegionProbe):
    def __init__(self, image):
        super().__init__(image)
        self.releases, self.jobs = [], []
        self.record_releases = True

    def boundary(self, u, address, size, unused):
        if address == 0x1032ae3c:
            if not self.record_releases:
                return
            self.releases.append(u.reg_read(UC_ARM_REG_R0))
        elif address == 0x10319d56:
            pointer, length = u.reg_read(UC_ARM_REG_R1), u.reg_read(UC_ARM_REG_R2)
            require(length in (0, 4), 'Unexpected deferred input job size')
            self.jobs.append(dict(entry=hex(u.reg_read(UC_ARM_REG_R0)), bytes=length,
                words=list(struct.unpack('<I', u.mem_read(pointer, 4))) if length else []))
        elif address not in (0x103d5938, 0x103d58fa, 0x10234f86):
            return super().boundary(u, address, size, unused)
        u.reg_write(UC_ARM_REG_R0, 1)
        u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))

    def run(self, flags, previous=0):
        self.u.mem_write(0xb1868ca0, struct.pack('<I', previous))
        self.releases.clear()
        self.jobs.clear()
        self.call(0x2feabe, flags)
        require(self.word(0xb1868ca0) == flags | previous, 'Original aggregate OR differs')
        return set(self.releases), list(self.jobs)


def probe(image):
    native = FlagsProbe(image)
    all_releases, all_jobs = native.run(0xffffffff)
    require(all_releases, 'Original aggregate produced no release paths')
    required = dict.fromkeys(all_releases, 0)
    for bit in range(32):
        releases, _ = native.run(0xffffffff ^ (1 << bit))
        require(releases <= all_releases, 'Unexpected release in an omitted-bit case')
        for output in all_releases - releases:
            required[output] |= 1 << bit
    cases = []
    for output, mask in sorted(required.items()):
        releases, jobs = native.run(mask)
        require(output in releases, 'Recovered minimal prerequisites do not release')
        for bit in range(32):
            if mask & (1 << bit):
                missing, _ = native.run(mask ^ (1 << bit))
                require(output not in missing, 'Recovered prerequisite is not necessary')
        accumulated, _ = native.run(mask & -mask, mask & (mask - 1))
        require(output in accumulated, 'Prerequisites did not accumulate across calls')
        cases.append(dict(released_mask=hex(output), required_flags=hex(mask),
                          deferred_jobs=jobs))
    only_tail, tail_jobs = native.run(1)
    require(not only_tail and not tail_jobs, 'Input tail alone unexpectedly releases work')
    release_effects = []
    native.record_releases = False
    for before, mask in ((0xffffffff, 0x4000), (0xa5a5a5a5, 0x10000), (0xffffffff, 0xffffffff)):
        native.u.mem_write(0xb1868ca0, struct.pack('<I', before))
        native.call(0x30ae3c, mask)
        after = native.word(0xb1868ca0)
        require(after == before & ~mask, 'Original mask release did not clear its aggregate bits')
        release_effects.append(dict(before=hex(before), mask=hex(mask), after=hex(after)))
    return dict(format=1, firmware_included=False, master_sha256=MASTER_SHA,
        entry='0x1031eabe', aggregate='0xb1868ca0', release='0x1032ae3c',
        omitted_bit_cases=32, cases=cases, all_flags_jobs=all_jobs,
        release_effects=release_effects,
        tail_only=dict(flags='0x1', releases=[], jobs=[]),
        host_boundaries=['uncontended lock/unlock', 'record mask release',
                         'record deferred task submission', 'parameter refresh return'],
        limitations=['Synthetic aggregate inputs; native OR, prerequisite checks and job construction execute.',
                     'Does not identify runtime flag producers or supply flags to the running firmware.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    result = probe(args.master.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(release_paths=len(result['cases']))))


if __name__ == '__main__':
    main()
