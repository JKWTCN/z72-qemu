# SPDX-License-Identifier: GPL-2.0-or-later
"""Check the external switch signal independently of firmware execution."""
import argparse
from test_controller_gpio import run
from analyze.decode_z72 import require


def check_switch(remote, access):
    base = 0x40021800
    def read(offset):
        return access(base + offset, opcode=0x104)
    def level(high):
        command = 'qom-set /machine power-switch ' + ('true' if high else 'false')
        require(remote.command('qRcmd,' + command.encode().hex()) == 'OK',
                'External switch configuration failed')
    access(base, 0)
    access(base + 12, 1 << 10)
    level(False)
    require(read(16) == 0, 'Driven low input did not override its pull-up')
    level(True)
    require(read(16) == 32, 'External switch did not reach pin G5')
    require(remote.command('qRcmd,' + 'system_reset'.encode().hex()) == 'OK',
            'Switch reset failed')
    require(read(16) == 32 and read(20) == 0,
            'Reset changed the external level or retained the output latch')
    access(base, 1 << 10)
    require(read(16) == 0, 'Output mode did not use its own output latch')
    access(base + 20, 32)
    level(False)
    require(read(16) == 32, 'External input replaced a driven output')
    access(base, 0)
    require(read(16) == 0, 'Input mode did not restore the external switch level')
    contact = 0x40020800
    access(contact, 0)
    access(contact + 12, 1 << 10)
    for high in (False, True, False):
        command = 'qom-set /machine battery-contact ' + ('true' if high else 'false')
        require(remote.command('qRcmd,' + command.encode().hex()) == 'OK',
                'Battery contact configuration failed')
        require(access(contact + 16, opcode=0x104) == (32 if high else 0),
                'Battery contact did not reach pin C5 or override its pull-up')
        if high:
            require(remote.command('qRcmd,' + 'system_reset'.encode().hex()) == 'OK',
                    'Battery contact reset failed')
            require(access(contact + 16, opcode=0x104) == 32 and
                    access(contact, opcode=0x104) == 0,
                    'Reset changed the contact level or retained pin configuration')
    supply = 0x40020c00
    access(supply, 0)
    access(supply + 12, 1 << 26)
    for high in (False, True, False):
        command = 'qom-set /machine supply-input ' + ('true' if high else 'false')
        require(remote.command('qRcmd,' + command.encode().hex()) == 'OK',
                'Supply input configuration failed')
        require(access(supply + 16, opcode=0x104) == (8192 if high else 0),
                'Supply input did not reach pin D13 or override its pull-up')
        if high:
            require(remote.command('qRcmd,' + 'system_reset'.encode().hex()) == 'OK',
                    'Supply input reset failed')
            require(access(supply + 16, opcode=0x104) == 8192 and
                    access(supply, opcode=0x104) == 0,
                    'Reset changed the supply level or retained pin configuration')
    auxiliary = 0x40021000
    access(auxiliary, 0)
    access(auxiliary + 12, 1 << 18)
    for high in (False, True, False):
        command = 'qom-set /machine auxiliary-input ' + ('true' if high else 'false')
        require(remote.command('qRcmd,' + command.encode().hex()) == 'OK',
                'Auxiliary input configuration failed')
        require(access(auxiliary + 16, opcode=0x104) == (512 if high else 0),
                'Auxiliary input did not reach pin E9 or override its pull-up')
        if high:
            require(remote.command('qRcmd,' + 'system_reset'.encode().hex()) == 'OK',
                    'Auxiliary input reset failed')
            require(access(auxiliary + 16, opcode=0x104) == 512 and
                    access(auxiliary, opcode=0x104) == 0,
                    'Reset changed the auxiliary level or retained pin configuration')
    print('PASS controller switch: levels, pull override, reset and output isolation')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    run(parser.parse_args().qemu, check_switch)
