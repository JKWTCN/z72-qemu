# SPDX-License-Identifier: GPL-2.0-or-later
"""Check regular conversion data, bounds and shared interrupts using synthetic code."""
import argparse
import subprocess
from test_controller_gpio import run
from analyze.decode_z72 import require


def checks(completion):
    def check(remote, access):
        def read(address):
            return access(address, opcode=0x104)
        def reset():
            require(remote.command('qRcmd,' + 'system_reset'.encode().hex()) == 'OK',
                    'Converter reset failed')
        def finish(base):
            for _ in range(1000 if completion else 50):
                if read(base) & 2:
                    break
            require(bool(read(base) & 2) == completion,
                    'Conversion completion differs from the requested mode')
        for bank in range(3):
            base = 0x40012000 + bank * 0x100
            require(read(base + 0x24) == 4095 and read(base) == 0,
                    'Converter reset state differs')
            for channel, sample in ((0, 1733), (1, 3001), (18, 4095), (2, 0)):
                for resolution in range(4):
                    for left in (False, True):
                        access(base + 4, (resolution << 24) | 32)
                        access(base + 0x34, channel)
                        access(base + 8, 0x40000001 | (0x800 if left else 0))
                        require(not read(base + 8) & (1 << 30),
                                'Software start did not self-clear')
                        finish(base)
                        bits = 12 - 2 * resolution
                        expected = sample >> (12 - bits)
                        if left:
                            expected <<= 16 - bits
                        require(read(base + 0x4c) == (expected if completion else 0),
                                'Selected channel, resolution or alignment differs')
                        require(not read(base) & 2,
                                'Data read did not acknowledge completion')
                        access(0xe000e280, 1 << 18)
                        require(not read(0xe000e200) & (1 << 18),
                                'Acknowledged conversion left an interrupt asserted')
                        access(base + 8, 0)
            require(read(0x40012300) >> (8 * bank) & 0x3f == read(base),
                    'Common status does not reflect the selected converter')
        if completion:
            # Two converters hold the same IRQ until both EOC flags are consumed.
            for base in (0x40012000, 0x40012100):
                access(base + 4, 32 | (1 << 26))
                access(base + 0x34, 1)
                access(base + 8, 0x40000001)
                finish(base)
            read(0x4001204c)
            access(0xe000e280, 1 << 18)
            require(read(0xe000e200) & (1 << 18),
                    'Consuming one bank removed the other bank interrupt')
            access(0x40012108, 0x40000001)
            for _ in range(1000):
                if read(0x40012100) & 32:
                    break
            require(read(0x40012100) & 32, 'Unread data did not cause overrun')
            read(0x4001214c)
            access(0x40012100, 0xffffffdf)
            access(0xe000e280, 1 << 18)
            require(not read(0xe000e200) & (1 << 18),
                    'Acknowledged overrun retained the shared interrupt')
        reset()
        require(read(0x40012304) == 0 and read(0x4001204c) == 0,
                'Reset retained converter data or common configuration')
        # Pending work must be canceled on disable, including completion=off.
        access(0x40012008, 0x40000001)
        access(0x40012008, 0)
        previous = read(0x4001204c)
        access(0x40012000, 0)
        for _ in range(1000):
            read(0x40012000)
        require(read(0x4001204c) == previous and not read(0x40012000) & 2,
                'Disabled converter completed its canceled request')
        reset()
        for address, value, opcode in ((0x40012050, 0, 0x104),
                                      (0x40012308, 0, 0x104),
                                      (0x4001204c, 1, 0x100),
                                      (0x40012300, 1, 0x100),
                                      (0x40012000, 0, 0x108),
                                      (0x40012008, 1 << 22, 0x100)):
            access(address, value, opcode, fault=True)
            reset()
        for setup, value in ((0x34, 19), (0x2c, 1 << 20), (4, 0x100)):
            access(0x40012000 + setup, value)
            access(0x40012008, 0x40000001, fault=True)
            reset()
        for mode in (2, 0x100, 0x10000000):
            access(0x40012008, 0x40000001 | mode, fault=True)
            reset()
        print('PASS controller ADC: channels, resolution, acknowledgement, IRQ, reset and bounds',
              'completion=' + str(completion))
    return check


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    args = parser.parse_args()
    inputs = ('-global', 'nikon-z72-controller-adc.channel0=1733',
              '-global', 'nikon-z72-controller-adc.channel1=3001',
              '-global', 'nikon-z72-controller-adc.channel18=4095')
    run(args.qemu, checks(True), inputs)
    run(args.qemu, checks(False), inputs +
        ('-global', 'nikon-z72-controller-adc.completion=off'))
    invalid = subprocess.run([args.qemu, '-M', 'nikon-z72-controller-lab',
        '-display', 'none', '-S', '-global', 'nikon-z72-controller-adc.channel1=4096'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
    require(invalid.returncode != 0 and b'exceeds twelve bits' in invalid.stderr,
            'Out-of-range analog input was not rejected at realization')
