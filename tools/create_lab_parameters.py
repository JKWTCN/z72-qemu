# SPDX-License-Identifier: GPL-2.0-or-later
"""Create experimental internal parameter storage for the C 1.70 boot probe."""
import argparse
import json
from pathlib import Path
import struct


def parameter_images():
    primary = bytearray(0x20000)
    secondary = bytearray(0xa0000)
    primary[-4:] = secondary[-4:] = b'ENDM'
    struct.pack_into('<I', primary, 0xa420, 81)
    struct.pack_into('<3I', primary, 0xa124, 1120, 1120, 1120)
    primary[0xb4e4] = 70
    primary[0xb4e8] = 75
    return bytes(primary), bytes(secondary)


def resource_header_image():
    """Supply an experimental resource header, not calibrated resource data."""
    image = bytearray(0x180000)
    image[0xbe014:0xbe016] = bytes.fromhex('1500')
    image[-4:] = b'ENDM'
    return bytes(image)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--destination', type=Path, required=True)
    parser.add_argument('--resource-header', action='store_true',
                        help='Also create an experimental group-32 header with a zero body')
    args = parser.parse_args()
    args.destination.mkdir(parents=True, exist_ok=False)
    primary, secondary = parameter_images()
    (args.destination / 'group17.bin').write_bytes(primary)
    (args.destination / 'group18.bin').write_bytes(secondary)
    groups = [dict(file='group17.bin', address='0x132c0000', size=len(primary)),
              dict(file='group18.bin', address='0x132e0000', size=len(secondary))]
    if args.resource_header:
        resource = resource_header_image()
        (args.destination / 'group32.bin').write_bytes(resource)
        groups.append(dict(file='group32.bin', address='0x13e80000', size=len(resource),
                           header_only=True, resource_contents_validated=False))
    (args.destination / 'parameters.json').write_text(json.dumps(dict(
        format=1, experimental=True, factory_calibration=False,
        firmware_version='C 1.70',
        storage_groups=groups,
        sampling_delay=81, sensor_limit_codes=[1120, 1120, 1120],
        power_limit_codes=dict(steady=70, initial=75)), indent=2) + '\n',
        encoding='utf-8', newline='\n')
    print(f'Created experimental parameter storage in {args.destination}')


if __name__ == '__main__':
    main()
