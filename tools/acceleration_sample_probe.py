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
        # Use the firmware's own memory attributes for its unaligned copy.
        reach(remote, 0x1002bda4)
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

        remote.write(0xb1807efc, b'\x01')  # Select the six-byte device variant.

        def return_success(regs):
            remote.set(pc=remote.get(regs, 'lr') & ~1, r0=0)

        def service(payload, count=0):
            _, regs = reach(remote, 0x103886a8)  # Bus acquire.
            return_success(regs)
            _, regs = reach(remote, 0x1038871c)
            descriptor = remote.get(regs, 'r1')
            mode, address, tx, rx, tx_size, rx_size = struct.unpack(
                '<BxH4I', remote.read(descriptor, 20))
            require((mode, address, tx_size, rx_size) == (1, 0x1d, len(payload), count),
                    'Unexpected acceleration transfer descriptor')
            sent = remote.read(tx, tx_size)
            require(sent == payload, f'Unexpected programming bytes {sent.hex()}')
            transfer(address, sent)
            wire = b''
            if count:
                wire = transfer(address, count=count)
                remote.write(rx, wire)
            require(remote.command('G' + regs.hex()) == 'OK', 'Could not resume bus caller')
            return_success(regs)
            _, regs = reach(remote, 0x103886e6)  # Bus release.
            return_success(regs)
            return wire

        # Supply the qualified programming record to the original configuration
        # routine. The timing field selects its branch without an RTOS sleep.
        owner, record = 0xb1802000, 0xb1803000
        remote.write(0xb1807f00, struct.pack('<I', owner))
        remote.write(owner + 0x1a8, struct.pack('<I', record))
        config = bytearray(0xb0)
        config[0x20], config[0x90], config[0x94] = 0x51, 0x2d, 2
        remote.write(record, config)
        remote.set(pc=0x103d48d0, cpsr=0x1f3, sp=0xb1810000, lr=0x10021001)
        for reg, size in ((0x0e, 2), (0x11, 1), (0x15, 1), (0x17, 2), (0x1d, 4)):
            service(bytes([reg]) + bytes(size))
        service(b'\x23' + bytes(7) + b'\x2c\x02' + bytes(6))
        service(b'\x2a\x2d')
        _, regs = reach(remote, 0x10021000)
        require(remote.get(regs, 'r0') == 1, 'Firmware configuration failed')

        remote.write(result, b'\xa5' * 12)
        remote.set(pc=0x103d4752, cpsr=0x1f3, sp=0xb1810000, lr=0x10021001, r0=result)
        wire = service(b'\x01', 6)
        _, regs = reach(remote, 0x10021000)
        fields = struct.unpack('<HhhhHH', remote.read(result, 12))
        require(remote.get(regs, 'r0') == 1 and fields ==
                (0xa5a5, -2048, 2047, -1, 0, 0xa5a5), 'Unexpected firmware sample result')
        print(f'PASS C1.70 sample reader: wire={wire.hex()}, axes={fields[1:4]}')

        # Exercise the original publication and capture-copy routines with a
        # full ring whose next write lands in the middle of the array.
        samples = [(i, -i, 1024 - i) for i in range(1, 17)]
        next_slot = 5
        physical = samples[-next_slot:] + samples[:-next_slot]
        for offset, axis in zip((0x2c, 0x4c, 0x6c), zip(*physical)):
            remote.write(owner + offset, struct.pack('<16h', *axis))
        remote.write(owner + 0xac, struct.pack('<I', next_slot))
        remote.set(pc=0x103d40d0, cpsr=0x1f3, sp=0xb1810000, lr=0x10021001,
                   r0=0xb1cf7978, r1=owner)
        reach(remote, 0x10021000)
        remote.set(pc=0x103d5530, cpsr=0x1f3, sp=0xb1810000, lr=0x10021001, r0=result)
        reach(remote, 0x10021000)
        axes = struct.iter_unpack('<16h', remote.read(result + 2, 96))
        require(list(zip(*axes)) == samples, 'Capture copy changed the order of the ring')
        print('PASS C1.70 capture history: oldest through newest across ring wrap')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    parser.add_argument('--master', type=Path, required=True)
    args = parser.parse_args()
    check(args.qemu, args.master)
