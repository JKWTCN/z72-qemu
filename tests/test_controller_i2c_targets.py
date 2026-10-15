# SPDX-License-Identifier: GPL-2.0-or-later
"""Exercise attached register targets and receive pipelines with synthetic code."""
import argparse
from test_controller_gpio import run
from analyze.decode_z72 import require


def check_targets(remote, access):
    def read(address):
        return access(address, opcode=0x104)
    for port in range(2):
        base = 0x40005400 + port * 0x400
        def address(receiving=False, ack=True, pos=False):
            access(base, 0x101 | (0x400 if ack else 0) | (0x800 if pos else 0))
            require(read(base + 20) & 1, 'Attached START did not complete')
            access(base + 16, 0xa0 | receiving)
            # SR2 alone must not consume ADDR.
            read(base + 24)
            require(read(base + 20) & 2, 'Address acknowledgement cleared too early')
            require(read(base + 24) == (3 if receiving else 7),
                    'Address direction or bus ownership differs')
            require(not read(base + 20) & 2, 'SR1/SR2 did not acknowledge ADDR')
        def stop(control=1):
            access(base, 0x200 | control)
            require(read(base + 24) == 0, 'STOP retained bus ownership')
        def pointer(value):
            address()
            access(base + 16, value)
        access(base + 4, 0x700 | 25)
        pointer(0xfe)
        payload = (0x81 + port, 0x92 + port, 0xa3 + port)
        for value in payload:
            access(base + 16, value)
            require(read(base + 20) & 0x84 == 0x84,
                    'Transmitted data did not publish TXE/BTF')
        stop()
        pointer(0xfe)
        address(True)
        require(read(base + 20) & 0x44 == 0x44,
                'Receive pipeline did not publish two available bytes')
        # Three-byte tail: clear ACK, consume one, STOP, consume the remaining two.
        access(base, 1)
        values = [read(base + 16)]
        stop()
        values += [read(base + 16), read(base + 16)]
        require(tuple(values) == payload and not read(base + 20) & 0x44,
                'Receive tail, wrapping pointer or buffered STOP differs')
        pointer(0xfe)
        address(True)
        values = [read(base + 16)]
        access(base, 1)
        values += [read(base + 16)]
        stop()
        values += [read(base + 16), read(base + 16)]
        require(values == list(payload) + [0] and not read(base + 20) & 0x44,
                'Four-byte receive did not transition to its final three-byte tail')
        pointer(0xff)
        address(True, ack=False, pos=True)
        stop(0x801)
        require([read(base + 16), read(base + 16)] == list(payload[1:]),
                'POS two-byte receive tail differs')
        pointer(0xfe)
        address(True, ack=False)
        stop()
        require(read(base + 16) == payload[0] and not read(base + 20) & 0x44,
                'One-byte read or STOP acknowledgement differs')
        # Buffer status is gated separately from address/transfer status.
        access(base + 4, 0)
        pointer(0)
        access(base + 20, 0xfffffbff)
        access(base + 4, 0x200)
        irq = 31 + 2 * port
        pending = 0xe000e200 + 4 * (irq // 32)
        access(pending + 0x80, 1 << (irq % 32))
        require(read(pending) & (1 << (irq % 32)),
                'BTF was incorrectly gated by the buffer interrupt mask')
        stop()
        address()
        access(base + 4, 0x200)
        access(pending + 0x80, 1 << (irq % 32))
        require(not read(pending) & (1 << (irq % 32)),
                'TXE ignored its buffer interrupt mask')
        access(base + 4, 0x600)
        require(read(pending) & (1 << (irq % 32)),
                'Unmasking TXE did not assert its event interrupt')
        stop()
        access(base + 4, 0)
        access(base, 0x101)
        access(base + 16, 0xa2)
        require(read(base + 20) & 0x400, 'Unattached address did not retain NACK')
        stop()
        access(base, 0x8000)
        access(base, 0)
    require(remote.command('qRcmd,' + 'system_reset'.encode().hex()) == 'OK',
            'Target reset failed')
    for base in (0x40005400, 0x40005800):
        access(base, 0x101)
        access(base + 16, 0xa0)
        read(base + 20)
        read(base + 24)
        access(base + 16, 0xfe)
        access(base, 0x101)
        access(base + 16, 0xa1)
        read(base + 20)
        read(base + 24)
        access(base, 0x201)
        require(read(base + 16) == 0, 'Target reset retained register writes')
    print('PASS attached controller buses: targets, address acknowledgement, receive tails, IRQ masks and reset')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    args = parser.parse_args()
    run(args.qemu, check_targets,
        ('-device', 'nikon-z72-controller-register-bank,bus=controller-i2c0,address=80',
         '-device', 'nikon-z72-controller-register-bank,bus=controller-i2c1,address=80'))
