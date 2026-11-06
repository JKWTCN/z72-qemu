# SPDX-License-Identifier: GPL-2.0-or-later
"""Check the C1.70 sample reader against a timed bus, with bus services isolated."""
import argparse
import hashlib
from pathlib import Path
import struct
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import require
from tools.boot_probe import reset_machine
from tools.smp_boot_probe import reach


def check(qemu, master):
    image = master.read_bytes()
    require(hashlib.sha256(image).hexdigest() ==
            '478caf02dba41fa9144c0c4b6e1a051dc556d40e51a79a308bdd1169efb9dbbe',
            'Expected the C1.70 master image')
    device = ('nikon-z72-acceleration,bus=master-i2c2,address=29,sample-present=on,'
              'sample-x=-2048,sample-y=2047,sample-z=-1')
    with tempfile.TemporaryDirectory() as folder, reset_machine(
            qemu, Path(folder) / 'machine', image, 'master',
            icount='shift=4,sleep=off', devices=(device,)) as remote:
        bus, delay, result = 0x2c01a000, 0xb1800700, 0xb1800100
        remote.write(delay, struct.pack('<3I', 0xe2500001, 0x1afffffd, 0xeafffffe))

        def write(offset, value):
            remote.write(bus + offset, struct.pack('<I', value))

        def transfer(address, payload=b'', count=0):
            write(0, 0x63 if count else 0x62)
            if count:
                write(20, count)
            for byte in payload:
                write(12, byte)
            write(0, 0x2b if count else 0x2a)
            write(8, address)
            remote.set(pc=delay, cpsr=0x1d3, r0=16384)
            reach(remote, delay + 8)
            require(int.from_bytes(remote.read(bus + 16, 4), 'little') == 3,
                    'Bus transaction did not complete')
            return bytes(remote.read(bus + 12, 4)[0] for _ in range(count))

        transfer(0x1d, b'\x2a\x01')
        remote.write(0xb1807efc, b'\x01')  # Select the six-byte device variant.
        remote.write(result, b'\xa5' * 12)
        remote.set(pc=0x103d4752, cpsr=0x1f3, sp=0xb1808000, lr=0x10021001, r0=result)

        def return_success(regs):
            remote.set(pc=remote.get(regs, 'lr') & ~1, r0=0)

        _, regs = reach(remote, 0x103886a8)  # Bus acquire.
        return_success(regs)
        _, regs = reach(remote, 0x1038871c)
        descriptor = remote.get(regs, 'r1')
        mode, address, tx, rx, tx_size, rx_size = struct.unpack(
            '<BxH4I', remote.read(descriptor, 20))
        require((mode, address, tx_size, rx_size) == (1, 0x1d, 1, 6),
                'Unexpected sample transfer descriptor')
        selector = remote.read(tx, tx_size)
        require(selector == b'\x01', 'Unexpected sample selector')
        transfer(address, selector)
        wire = transfer(address, count=rx_size)
        remote.write(rx, wire)
        require(remote.command('G' + regs.hex()) == 'OK', 'Could not resume bus caller')
        return_success(regs)
        _, regs = reach(remote, 0x103886e6)  # Bus release.
        return_success(regs)
        _, regs = reach(remote, 0x10021000)
        fields = struct.unpack('<HhhhHH', remote.read(result, 12))
        require(remote.get(regs, 'r0') == 1 and fields ==
                (0xa5a5, -2048, 2047, -1, 0, 0xa5a5), 'Unexpected firmware sample result')
        print(f'PASS C1.70 sample reader: wire={wire.hex()}, axes={fields[1:4]}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    parser.add_argument('--master', type=Path, required=True)
    args = parser.parse_args()
    check(args.qemu, args.master)
