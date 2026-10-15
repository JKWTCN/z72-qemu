# SPDX-License-Identifier: GPL-2.0-or-later
"""Check random data readiness, consumption, interrupt masking and rejected accesses."""
import argparse
from test_controller_gpio import run
from analyze.decode_z72 import require


def checks(completion):
    def check(remote, access):
        base = 0x50060800
        pending, clear, bit = 0xe000e208, 0xe000e288, 1 << 16

        def read(address):
            return access(address, opcode=0x104)

        def ready():
            for _ in range(1000 if completion else 30):
                if read(base + 4) & 1:
                    break
            require(bool(read(base + 4) & 1) == completion,
                    'Random data completion differs from the requested mode')

        require(read(base) == 0 and read(base + 4) == 0 and read(base + 8) == 0,
                'Random source did not start disabled and empty')
        access(base + 4, 0xffffffff)
        require(read(base + 4) == 0, 'Status write fabricated random data')
        access(base, 4)
        ready()
        require(not read(pending) & bit, 'Random interrupt bypassed its mask')
        if completion:
            access(base + 4, 0)
            require(read(base + 4) == 1, 'Status write acknowledged read-only readiness')
            access(base, 12)
            require(read(pending) & bit, 'Ready data did not assert the enabled interrupt')
            access(base, 8)
            require(read(base + 4) == 1, 'Disabling generation discarded unread data')
            first = read(base + 8)
            require(read(base + 4) == 0 and read(base + 8) == first,
                    'Consumed data remained ready or changed while generation was disabled')
            access(clear, bit)
            require(not read(pending) & bit, 'Consumed data left its interrupt asserted')
            access(base, 4)
            values = []
            for _ in range(16):
                ready()
                values.append(read(base + 8))
            require(len(set(values)) > 1, 'Random source returned a constant word')
        else:
            access(base, 12)
            ready()
            require(read(base + 8) == 0 and not read(pending) & bit,
                    'Disabled completion produced data or an interrupt')
        require(remote.command('qRcmd,' + 'system_reset'.encode().hex()) == 'OK',
                'Random source reset failed')
        require(read(base) == 0 and read(base + 4) == 0 and read(base + 8) == 0,
                'Reset retained random control or data')
        for address, opcode, value in ((base + 8, 0x100, 1), (base + 12, 0x104, 0),
                                       (base, 0x108, 4), (base, 0x10c, 4),
                                       (base, 0x100, 0x10)):
            access(address, value, opcode, fault=True)
            require(remote.command('qRcmd,' + 'system_reset'.encode().hex()) == 'OK',
                    'Reset after invalid random source access failed')
        print('PASS controller random source: readiness, data, interrupt, reset and access bounds')
    return check


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    args = parser.parse_args()
    run(args.qemu, checks(True))
    run(args.qemu, checks(False),
        ('-global', 'nikon-z72-controller-rng.completion=off'))
