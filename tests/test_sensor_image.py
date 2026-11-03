# SPDX-License-Identifier: GPL-2.0-or-later
"""Reject malformed scene files before a firmware-free machine starts."""
import argparse
from pathlib import Path
import subprocess
import tempfile


def check(qemu):
    cases = (
        b'P2\n1 1\n255\n0\n',
        b'P5\n1 1\n256\n\0',
        b'P5\n0 1\n255\n',
        b'P5\n16385 1\n255\n',
        b'P5\n16384 16384\n255\n',
        b'P5\n2 1\n255\n\0',
        b'P5\n1 1\n255\n\0\0',
        b'P5\n#' + b'x' * 4096 + b'\n1 1\n255\n\0',
    )
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / 'invalid.pgm'
        for data in cases:
            path.write_bytes(data)
            result = subprocess.run([qemu, '-M', 'nikon-z72-lab', '-S',
                '-display', 'none', '-serial', 'none', '-monitor', 'none',
                '-global', f'nikon-z72-boot-config.sensor-image={path}'],
                capture_output=True, timeout=10)
            assert result.returncode != 0
            assert b'Sensor image requires one binary P5 image' in result.stderr, result.stderr
    print('PASS scene format, dimensions, size, header, truncation and trailing-data rejection')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    check(parser.parse_args().qemu)
