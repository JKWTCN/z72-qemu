# SPDX-License-Identifier: GPL-2.0-or-later
"""Check optional PWM-driven position feedback with synthetic instructions."""
import argparse
from test_controller_gpio import run
from analyze.decode_z72 import require


def checks(enabled):
    def check(remote, access):
        def read(address):
            return access(address, opcode=0x104)
        def advance(ns):
            remote.set(pc=0x20002000, r0=ns // 2)
            remote.breakpoint(0x20002004)
            remote.command('c')
            remote.breakpoint(0x20002004, False)
            require(remote.get(remote.regs(), 'pc') == 0x20002004,
                    'Synthetic actuator clock loop did not return')
        def position():
            return (read(0x40020810) >> 6) & 3
        # SUBS r0,#1; BNE .-2; NOP, under one-nanosecond instruction counting.
        remote.write(0x20002000, bytes.fromhex('0138fdd100bf'))
        drive, capture = 0x40000000, 0x40000400
        access(0x40020800, 2 << 12 | 2 << 14)
        access(0x40020820, 2 << 24 | 2 << 28)
        access(capture + 0x18, 0x101)
        access(capture + 0x20, 0x11)
        access(capture + 0x28, 0xffff)
        access(capture, 1)
        access(drive + 0x18, 0x60)
        access(drive + 0x1c, 0x60)
        access(drive + 0x20, 0x101)
        access(drive + 0x2c, 999)
        access(drive + 0x34, 1000)
        access(drive, 1)
        access(0x40020000, 2 << 30)
        advance(2200000)
        require(position() == 0, 'Wrong pin alternate function generated motion')
        access(0x40020024, 1 << 28)
        advance(1100000)
        require(position() == (1 if enabled else 0), 'First PWM-driven position edge differs')
        if enabled:
            require(read(capture + 0x10) & 6 == 2, 'Motor feedback did not reach C6 capture')
            read(capture + 0x34)
        advance(1100000)
        require(position() == (3 if enabled else 0), 'Second PWM-driven position edge differs')
        if enabled:
            require(read(capture + 0x10) & 6 == 4, 'Motor feedback did not reach C7 capture')
            read(capture + 0x38)
        access(drive, 0)
        stopped = position()
        advance(3000000)
        require(position() == stopped, 'Disabled counter retained motor drive')
        access(0x40020400, 2 << 20)
        access(0x40020424, 1 << 8)
        access(drive + 0x34, 0)
        access(drive + 0x3c, 1000)
        access(drive, 1)
        advance(1100000)
        require(position() == (1 if enabled else 0), 'Reverse PWM did not reverse position')
        advance(1100000)
        require(position() == 0, 'Reverse PWM did not return to the starting position')
        access(drive + 0x34, 1000)
        advance(3000000)
        require(position() == 0, 'Equal bridge drive did not stop motion')
        access(drive + 0x3c, 0)
        access(0x40020000, 0)
        advance(3000000)
        require(position() == 0, 'Disconnected PWM pin retained drive')
        access(0x40020000, 2 << 30)
        access(drive + 0x20, 0)
        advance(3000000)
        require(position() == 0, 'Disabled PWM channel retained drive')
        access(drive + 0x20, 0x101)
        advance(1100000)
        require(position() == (1 if enabled else 0), 'PWM restart did not resume motion')
        require(remote.command('qRcmd,' + 'system_reset'.encode().hex()) == 'OK',
                'Actuator board reset failed')
        advance(3000000)
        require(position() == 0, 'Board reset retained actuator motion or position')
        print('PASS actuator: pin gating, both PWM directions, capture feedback, stop and brake; enabled=' + str(enabled))
    return check


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    args = parser.parse_args()
    for enabled in (False, True):
        run(args.qemu, checks(enabled), ('-icount', 'shift=0,sleep=off',
            '-global', 'nikon-z72-controller-actuator.enabled=' + ('on' if enabled else 'off')))
