# SPDX-License-Identifier: GPL-2.0-or-later
"""Check C6/C7 alternate-function capture and simultaneous external interrupts."""
import argparse
import socket

from test_controller_gpio import run
from analyze.decode_z72 import require


def checks(port):
    def check(remote, access):
        wire = socket.create_connection(('127.0.0.1', port), timeout=5)
        stream = wire.makefile('rb')
        def level(pin, value):
            wire.sendall((f'set_irq_in /machine/position-gpio unnamed-gpio-in {pin} {value}\n').encode())
            reply = stream.readline().decode().strip()
            require(reply.startswith('OK'), 'Position input command failed: ' + reply)
        def read(address):
            return access(address, opcode=0x104)
        gpio, timer = 0x40020800, 0x40000400
        def clear():
            access(timer + 0x10, 0)
            access(0x40013c14, 0xc0)
            access(0xe000e280, 0xffffffff)
        try:
            level(6, 0)
            level(7, 0)
            access(timer + 0x18, 0x101)
            access(timer + 0x20, 0x11)
            access(timer + 0x0c, 6)
            access(timer + 0x28, 0xffff)
            access(timer, 1)
            access(gpio, 2 << 12 | 2 << 14)
            access(gpio + 0x20, 1 << 24 | 1 << 28)
            clear()
            level(6, 1)
            level(7, 1)
            require(read(timer + 0x10) == 0, 'Wrong alternate function reached input capture')
            access(gpio + 0x20, 2 << 24 | 1 << 28)
            require(read(timer + 0x10) == 0, 'Selecting AF2 fabricated an input edge')
            access(0x4001380c, 0x2200)
            access(0x40013c00, 0xc0)
            access(0x40013c08, 0xc0)
            clear()
            level(6, 0)
            level(6, 1)
            require(read(timer + 0x10) == 2 and read(0xe000e200) & (1 << 29),
                    'C6 did not reach TIM3 channel 1 and its interrupt')
            require(read(0x40013c14) == 0x40, 'Timer route replaced C6 external interrupt routing')
            read(timer + 0x34)
            require(read(timer + 0x10) == 0, 'Native captured-value read did not acknowledge C6')
            clear()
            level(7, 0)
            level(7, 1)
            require(read(timer + 0x10) == 0 and read(0x40013c14) == 0x80,
                    'C7 wrong function reached capture or lost its external interrupt')
            access(gpio + 0x20, 2 << 24 | 2 << 28)
            clear()
            level(7, 0)
            level(7, 1)
            require(read(timer + 0x10) == 4, 'C7 did not reach TIM3 channel 2 independently')
            clear()
            access(timer + 0x20, 0x13)
            level(6, 0)
            require(read(timer + 0x10) == 2, 'C6 falling capture polarity was not respected')
            read(timer + 0x34)
            level(6, 0)
            require(read(timer + 0x10) == 0, 'Held C6 input repeated its capture')
            access(gpio, 0)
            level(6, 1)
            level(6, 0)
            require(read(timer + 0x10) == 0, 'GPIO input mode still drove alternate-function capture')
            require(remote.command('qRcmd,' + 'system_reset'.encode().hex()) == 'OK',
                    'Position routing reset failed')
            access(timer + 0x18, 0x101)
            access(timer + 0x20, 0x11)
            access(timer + 0x28, 0xffff)
            access(timer, 1)
            level(6, 1)
            level(7, 0)
            level(7, 1)
            require(read(timer + 0x10) == 0, 'Reset retained alternate-function routing')
            print('PASS position routing: AF2 selection, both pins, capture IRQ, EXTI fanout and reset')
        finally:
            stream.close()
            wire.close()
    return check


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    args = parser.parse_args()
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    run(args.qemu, checks(port), ('-qtest', f'tcp:127.0.0.1:{port},server=on,wait=off',
                                 '-qtest-log', '/dev/null'))
