# SPDX-License-Identifier: GPL-2.0-or-later
"""Recover original GPIO write selection and native pin initialization readback."""
import argparse
import json
from pathlib import Path
import struct
import sys

from unicorn import UC_HOOK_MEM_WRITE

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import MASTER_SHA, require
from analyze.firmware_structure import analyze_eg
from analyze.library_boot import library_table, pin_words
from tools.boot_region_probe import RegionProbe


class GPIOProbe(RegionProbe):
    def __init__(self, image):
        super().__init__(image)
        self.u.mem_map(0x04282000, 0x1000)
        self.writes = []
        self.u.hook_add(UC_HOOK_MEM_WRITE, self.write,
                        begin=0x04282000, end=0x04282fff)

    def write(self, u, access, address, size, value, unused):
        self.writes.append(dict(address=hex(address), size=size, value=hex(value)))


def check(image):
    native = GPIOProbe(image)
    ports = {}
    for index in range(232):
        descriptor = 0xb180249c + index * 56
        address = native.word(descriptor + 8)
        if address:
            ports.setdefault(address, []).append(descriptor)
    require(sorted(ports) == list(range(0x04282000, 0x0428203c, 4)),
            'Original PDR descriptor addresses differ')
    cases = []
    for address, descriptors in sorted(ports.items()):
        # End pins exercise different mask positions in each descriptor group.
        for descriptor in (descriptors[0], descriptors[-1]):
            pin = native.word(descriptor + 4)
            require(pin < 16, 'PDR pin outside low halfword')
            for level in (0, 1):
                native.u.mem_write(address, struct.pack('<I', 0xa55a))
                native.writes.clear()
                native.call(0x365d50, descriptor, level)
                command = (1 << (pin + 16)) | (level << pin)
                require(native.writes == [dict(address=hex(address), size=4, value=hex(command))],
                        'Original GPIO writer did not select exactly its descriptor pin')
                cases.append(dict(resource=hex(native.word(descriptor)), register=hex(address),
                                  pin=pin, level=level, command=hex(command)))
    structure = analyze_eg(image, 'master')
    table = library_table(image, structure, 'master')['words']
    sampling = dict(register='0x04282028', pin=12,
        startup_words=[hex(value) for value in table[50:55]],
        latch=bool(table[50] & 0x1000), direction=bool(table[51] & 0x1000),
        pull_enabled=bool(table[53] & 0x1000), pull_select=bool(table[54] & 0x1000))
    require(not sampling['pull_enabled'] and not sampling['direction'],
            'Sampling startup pull or direction differs')
    readback = pin_words(table)
    require(all(readback[0x04282000 + group * 4] == table[group * 5] & 0xffff
                for group in range(12)), 'Full-selection startup PDR readback differs')
    return dict(format=1, result='passed', firmware_included=False, master_sha256=MASTER_SHA,
        writer='0x10385d50', cases=cases, sampling_startup=sampling,
        boundaries=['Synthetic MMIO stores record the original writer commands',
                    'Original startup table is decoded; full native startup is verified separately'],
        limitations=['No electrical or external signal source is supplied',
                     'Direction and pull words are reported, not a physical pin model'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    report = check(args.master.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
    print('PASS original GPIO writer: 15 PDR words, 60 selected-pin commands and startup sampling configuration')
