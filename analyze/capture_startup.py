# SPDX-License-Identifier: GPL-2.0-or-later
"""Recover the C1.70 capture task binding with explicit address coordinates."""
import argparse
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import BASE, require
from analyze.firmware_structure import analyze_eg, u32


def thumb_call(image, offset):
    first, second = struct.unpack_from('<HH', image, offset)
    require(first & 0xf800 == 0xf000 and second & 0xd000 == 0xd000,
            'Expected Thumb BL at capture startup call site')
    sign = (first >> 10) & 1
    displacement = (sign << 24 | (((second >> 13) & 1) ^ sign ^ 1) << 23 |
                    (((second >> 11) & 1) ^ sign ^ 1) << 22 |
                    (first & 0x3ff) << 12 | (second & 0x7ff) << 1)
    if sign:
        displacement -= 1 << 25
    return BASE + offset + 4 + displacement


def capture_startup_profile(image):
    identity = analyze_eg(image, 'master')

    def location(offset):
        return dict(file_offset=hex(offset), runtime_address=hex(BASE + offset))

    calls = []
    for source, target in ((0x40f65e, 0x3acef0),
                           (0x40f664, 0x3acfd2),
                           (0x3ac9da, 0x3ac408),
                           (0x302a84, 0x3b01dc),
                           (0x302b28, 0x3b01dc),
                           (0x305772, 0x3b01dc),
                           (0x3abfe4, 0x3abccc),
                           (0x3b13ae, 0x3abccc)):
        require(thumb_call(image, source) == BASE + target,
                'Unexpected capture startup call target')
        calls.append(dict(source=location(source), target=location(target)))
    # The task callback is loaded from a literal pool, not a relocated table.
    require(u32(image, 0x3ad134) == BASE + 0x3ac9ca + 1,
            'Unexpected capture task callback')
    # This getter returns the module method table in copied initialized RAM.
    require(u32(image, 0x40f6a0) == 0xb186497c,
            'Unexpected capture method table address')
    methods = [u32(image, 0x23de910 + index * 4) for index in range(4)]
    require(methods == [BASE + offset + 1 for offset in
                        (0x40f650, 0x40f66c, 0x40f688, 0x40f69c)],
            'Unexpected capture method table')
    # The queue's emptiness predicate reads +8, beyond its two link words.
    require(image[0x32faa2:0x32faae] == bytes.fromhex(
        '806808b10020704701207047'), 'Unexpected queue predicate')
    events = {}
    for offset, name in ((0x3ac9d6, 'open_device'),
                         (0x3ac9ee, 'work'),
                         (0x3ac9fe, 'configure_mode')):
        instruction = struct.unpack_from('<H', image, offset)[0]
        require(instruction & 0xf83f == 0x0020,
                'Expected capture event test shift')
        events[name] = 31 - ((instruction >> 6) & 31)
    return dict(format=1, firmware_sha256=identity['sha256'],
                master_load_base=hex(BASE), evidence_kind='static', calls=calls,
                task_callback_literal=location(0x3ad134),
                task_callback=location(0x3ac9ca),
                method_table_ram='0xb186497c',
                method_table_source=location(0x23de910),
                methods=[hex(method) for method in methods],
                dispatch_event_bits=events,
                task='0xb238e654', queue_offsets=['0x40', '0x60'],
                queue_count_offset='0x8',
                limitations=['Static call edges do not establish execution.',
                             'No sensor pixels or capture completion verified.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(capture_startup_profile(args.master.read_bytes()), indent=2))


if __name__ == '__main__':
    main()
