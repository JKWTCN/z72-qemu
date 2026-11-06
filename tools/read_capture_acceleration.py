# SPDX-License-Identifier: GPL-2.0-or-later
"""Read sixteen raw three-axis samples, oldest first, from a Z7 II ShotInfo 0803 JPEG."""
import argparse
import json
from pathlib import Path
import struct
import subprocess


def read_capture(path, exiftool):
    command = [exiftool, '-j', '-G1', '-n', '-U', '-Model', '-ShotInfoVersion',
               '-Nikon_OrientationInfo*', '-IFD0:Orientation', str(path.resolve())]
    tags, = json.loads(subprocess.check_output(command))
    if tags.get('IFD0:Model', '').strip() != 'NIKON Z 7_2' or str(tags.get('Nikon:ShotInfoVersion')) != '0803':
        raise ValueError('Expected a Z 7_2 JPEG with ShotInfo version 0803')
    data = bytes(tags[f'Nikon:Nikon_OrientationInfo_0x{offset:04x}'] for offset in range(12, 108))
    x, y, z = struct.iter_unpack('<16h', data)
    return dict(exif_orientation=tags.get('IFD0:Orientation'), raw_xyz=list(zip(x, y, z)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('jpeg', type=Path)
    parser.add_argument('--exiftool', default='exiftool')
    args = parser.parse_args()
    try:
        print(json.dumps(read_capture(args.jpeg, args.exiftool)))
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        parser.exit(1, f'Could not read acceleration: {error}\n')
