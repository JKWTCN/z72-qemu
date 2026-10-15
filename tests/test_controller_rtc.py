# SPDX-License-Identifier: GPL-2.0-or-later
"""Check controller clock configuration with the synthetic Thumb harness."""
import argparse
from test_controller_gpio import run
from analyze.decode_z72 import require


def check_clock(remote, access):
    base = 0x40002800

    def read(offset):
        return access(base + offset, opcode=0x104)

    def write(offset, value):
        access(base + offset, value)

    write(0, 0x123456)
    write(0xc, 0x80)
    require(read(0) == 0 and not read(0xc) & 0x80,
            'Locked clock accepted protected configuration')
    write(0x24, 0x53)
    write(0, 0x123456)
    require(read(0) == 0, 'Second key alone unlocked the clock')
    write(0x24, 0xca)
    write(0x24, 0x53)
    write(0xc, 0x80)
    require(read(0xc) & 0xc0 == 0xc0 and not read(0xc) & 0x20,
            'Initialization request did not enter configuration mode')
    write(0, 0x123456)
    write(4, 0x250101)
    write(0x10, 0x7f00ff)
    require(read(0) == 0x123456 and read(4) == 0x250101 and read(0x10) == 0x7f00ff,
            'Unlocked calendar configuration differed')
    write(0xc, 0)
    require(read(0xc) & 0x60 == 0x20,
            'Configuration exit did not clear initialization and synchronize')
    write(8, 0x700)
    require(read(0xc) & 7 == 0, 'Enabled alarms retained write-ready status')
    write(8, 0)
    require(read(0xc) & 7 == 7, 'Disabled alarms did not become write-ready')
    write(0x24, 0xff)
    write(0, 0)
    require(read(0) == 0x123456, 'Clock relock did not protect calendar state')
    for index in range(20):
        write(0x50 + index * 4, 0xa5a50000 | index)
    require(all(read(0x50 + index * 4) == 0xa5a50000 | index for index in range(20)),
            'Backup words were not independent or exceeded their bounds')
    access(0x40023870, 1)
    access(0x40023874, 1)
    require(access(0x40023870, opcode=0x104) == 3 and
            access(0x40023874, opcode=0x104) == 3,
            'Low-frequency clock enable did not reflect completion')
    require(remote.command('qRcmd,' + 'system_reset'.encode().hex()) == 'OK',
            'Controller reset failed')
    require(all(read(offset) == 0 for offset in (0, 4, 8, 16, *range(0x50, 0xa0, 4))) and
            read(0xc) == 0x27, 'Laboratory reset retained clock state')
    for address, opcode in ((base, 0x108), (base + 0x28, 0x100),
                             (base + 0x4c, 0x104), (base + 0xa0, 0x100)):
        access(address, 0xffffffff, opcode, fault=True)
        require(remote.command('qRcmd,' + 'system_reset'.encode().hex()) == 'OK',
                'Controller reset after clock fault failed')
    print('PASS controller clock: protection, initialization, status, backup words and faults')


def check_disabled(remote, access):
    base = 0x40002800
    access(base + 0x24, 0xca)
    access(base + 0x24, 0x53)
    access(base + 0xc, 0x80)
    require(access(base + 0xc, opcode=0x104) == 0x87,
            'Disabled clock completion unexpectedly initialized')
    access(base + 0xc, 0)
    require(access(base + 0xc, opcode=0x104) == 7,
            'Disabled clock completion unexpectedly synchronized')
    print('PASS disabled controller clock completion')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    qemu = parser.parse_args().qemu
    run(qemu, check_clock)
    run(qemu, check_disabled, ('-global', 'nikon-z72-controller-rtc.completion=off'))
