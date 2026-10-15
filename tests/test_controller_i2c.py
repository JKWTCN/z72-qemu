# SPDX-License-Identifier: GPL-2.0-or-later
"""Check disconnected controller buses with synthetic Thumb instructions."""
import argparse
from test_controller_gpio import run
from analyze.decode_z72 import require


def check_bus(remote, access):
    for port in range(2):
        base = 0x40005400 + port * 0x400
        access(base + 4, 0x700 | 25)
        access(base + 0x1c, 0x8008)
        for address in (0, 0xa0, 0xff):
            access(base, 0x101)
            require(access(base + 0x14, opcode=0x104) == 1 and
                    access(base + 0x18, opcode=0x104) == 3,
                    'Controller START did not enter the address phase')
            event_irq, error_irq = 31 + port * 2, 32 + port * 2
            event_pending = 0xe000e200 + 4 * (event_irq // 32)
            error_pending = 0xe000e200 + 4 * (error_irq // 32)
            require(access(event_pending, opcode=0x104) & (1 << (event_irq % 32)),
                    'Controller START did not raise its mapped event interrupt')
            access(base + 0x10, address)
            require(access(base + 0x14, opcode=0x104) == 0x400 and
                    access(base, opcode=0x104) == 1,
                    'Disconnected target did not NACK the address')
            require(access(error_pending, opcode=0x104) & (1 << (error_irq % 32)),
                    'Controller NACK did not raise its mapped error interrupt')
            access(base, 0x201)
            require(access(base + 0x18, opcode=0x104) == 0,
                    'STOP did not release the controller bus')
            access(base + 0x14, 0xfffffbff)
            require(access(base + 0x14, opcode=0x104) == 0,
                    'Acknowledge failure did not clear on a zero write')
            access(event_pending + 0x80, 1 << (event_irq % 32))
            access(error_pending + 0x80, 1 << (error_irq % 32))
            require(not access(event_pending, opcode=0x104) & (1 << (event_irq % 32)) and
                    not access(error_pending, opcode=0x104) & (1 << (error_irq % 32)),
                    'Controller bus interrupt remained asserted after acknowledgement')
        access(base, 0x101)
        access(base, 0x8000)
        require(access(base, opcode=0x104) == 0x8000 and
                all(access(base + offset, opcode=0x104) == 0
                    for offset in (4, 8, 12, 20, 24, 28, 32, 36)),
                'Software reset retained bus configuration or phase')
        access(base, 0)
    for address, opcode in ((0x40005410, 0x104), (0x40005410, 0x100),
                             (0x40005418, 0x100), (0x40005400, 0x108),
                             (0x40005428, 0x104)):
        access(address, 0, opcode, fault=True)
        require(remote.command('qRcmd,' + 'system_reset'.encode().hex()) == 'OK',
                'Controller reset after bus fault failed')
    print('PASS controller buses: START, disconnected NACK, mapped interrupts, STOP, reset and access faults')


def check_disabled(remote, access):
    for base in (0x40005400, 0x40005800):
        access(base, 0x101)
        require(access(base + 0x14, opcode=0x104) == 0 and
                access(base, opcode=0x104) & 0x100,
                'Disabled START completion did not preserve its request')
        access(base, 0x201)
        require(access(base + 0x18, opcode=0x104) == 0,
                'STOP could not cancel an incomplete START')
    print('PASS disabled controller bus START completion')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    qemu = parser.parse_args().qemu
    run(qemu, check_bus)
    run(qemu, check_disabled, ('-global', 'nikon-z72-controller-i2c.start-completion=off'))
