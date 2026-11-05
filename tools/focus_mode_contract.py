# SPDX-License-Identifier: GPL-2.0-or-later
"""Verify the C1.70 focus-mode property through its original PTP getter."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.boot_region_probe import RegionProbe


def check(image):
    native = RegionProbe(image)
    property_id = 0x1625
    group = 0x11906924 + (property_id >> 8) * 28
    index = struct.unpack('<H', native.u.mem_read(group + 12, 2))[0] + (property_id & 255)
    descriptor = 0x118fb024 + index * 16
    kind, size, address, _ = struct.unpack('<4I', native.u.mem_read(descriptor, 16))
    assert (kind, size, address) == (7, 4, 0xb2551808)
    assert native.word(0x119e9ad0) == 0x500a
    assert native.word(0x119e9ad4) == 0x104cda55
    cases = []
    for value, expected in ((0, 1), (1, 0x8010), (2, 0x8011), (3, 0x8010), (4, 0x8013)):
        native.u.mem_write(address, struct.pack('<I', value))
        actual = native.call(0x104cda3a - 0x10020000)
        assert actual == expected, (value, actual, expected)
        cases.append(dict(internal=value, ptp=hex(actual)))
    return dict(result='passed-original-focus-mode-getter',
                firmware_sha256=hashlib.sha256(image).hexdigest(),
                property=hex(property_id), descriptor=hex(descriptor), address=hex(address),
                ptp_property='0x500a', ptp_record='0x119e9ad0', getter='0x104cda3a',
                cases=cases,
                scope='Original getter and conversion executed with synthetic property RAM; no whole-guest writes.',
                limitations=['Does not prove autofocus, capture admission or hardware readiness.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    result = check(args.master.read_bytes())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print('PASS five original focus-mode conversions')


if __name__ == '__main__':
    main()
