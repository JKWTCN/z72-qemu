# SPDX-License-Identifier: GPL-2.0-or-later
"""Check controller DMA using synthetic Thumb execution and bounded buffers."""
import argparse
from test_controller_gpio import run
from analyze.decode_z72 import require

IRQS = ((11, 12, 13, 14, 15, 16, 17, 47), (56, 57, 58, 59, 60, 68, 69, 70))
SHIFTS = (0, 6, 16, 22)
SOURCE, TARGET = 0x20003000, 0x20004000


def check_dma(remote, access):
    for bank in range(2):
        base = 0x40026000 + bank * 0x400
        for stream in range(8):
            registers = base + 0x10 + stream * 0x18
            status = base + (4 if stream >= 4 else 0)
            shift = SHIFTS[stream % 4]

            def flags():
                return (access(status, opcode=0x104) >> shift) & 0x3d

            def start(count, control, source=SOURCE, target=TARGET):
                access(registers, 0)
                access(status + 8, 0x3d << shift)
                access(registers + 4, count)
                access(registers + 8, source)
                access(registers + 12, target)
                access(registers, control | 1)

            for width_code in range(3):
                width = 1 << width_code
                data = bytes((i * 37 + stream + 17 * bank) & 255 for i in range(17 * width))
                remote.write(SOURCE, data)
                remote.write(TARGET - 4, b'HEAD' + bytes(len(data)) + b'TAIL')
                control = 0x80 | 0x600 | 0x18 | (width_code << 11) | (width_code << 13)
                start(17, control)
                for _ in range(1000):
                    if flags() & 0x20:
                        break
                require(flags() == 0x30 and access(registers + 4, opcode=0x104) == 0 and
                        not access(registers, opcode=0x104) & 1 and
                        remote.read(TARGET - 4, len(data) + 8) == b'HEAD' + data + b'TAIL',
                        'DMA copy, count, completion or buffer guards differ')
                irq = IRQS[bank][stream]
                pending = 0xe000e200 + (irq // 32) * 4
                require(access(pending, opcode=0x104) & (1 << (irq % 32)),
                        'DMA completion did not reach its mapped stream interrupt')
                access(status + 8, 0x3d << shift)
                access(pending + 0x80, 1 << (irq % 32))
                require(flags() == 0 and
                        not access(pending, opcode=0x104) & (1 << (irq % 32)),
                        'DMA acknowledgement left the stream interrupt asserted')
            remote.write(SOURCE, b'abcdefghijklmnopq')
            remote.write(TARGET, bytes(17))
            start(17, 0x80 | 0x400)
            for _ in range(1000):
                if flags() & 0x20:
                    break
            require(remote.read(TARGET, 17) == b'a' * 17,
                    'Fixed source DMA did not repeat the selected byte')
            for count, control, source, target in (
                (0, 0x680, SOURCE, TARGET),
                (0x10000, 0x680, SOURCE, TARGET),
                (17, 0x780, SOURCE, TARGET),
                (17, 0x680 | (3 << 13), SOURCE, TARGET),
                (17, 0x680, 0x2003fff8, TARGET),
                (17, 0x680, SOURCE, 0x08000100),
                (17, 0x680, SOURCE, 0xfffffff8),
            ):
                remote.write(TARGET, b'unchanged buffer!')
                start(count, control | 4, source, target)
                require(flags() == 8 and not access(registers, opcode=0x104) & 1 and
                        remote.read(TARGET, 17) == b'unchanged buffer!',
                        'Unsupported DMA changed guest buffers or reported completion')
                irq = IRQS[bank][stream]
                pending = 0xe000e200 + (irq // 32) * 4
                require(access(pending, opcode=0x104) & (1 << (irq % 32)),
                        'DMA transfer error did not reach its mapped stream interrupt')
                access(status + 8, 0x3d << shift)
                access(pending + 0x80, 1 << (irq % 32))
                require(not access(pending, opcode=0x104) & (1 << (irq % 32)),
                        'DMA error acknowledgement left its interrupt asserted')
            # A peripheral-to-memory stream stays enabled without a request.
            start(17, 0x400 | (7 << 25), 0x40005810)
            for _ in range(20):
                require(flags() == 0 and access(registers + 4, opcode=0x104) == 17,
                        'Disconnected peripheral DMA completed without a request')
            access(registers + 20, 0xa1)
            require(access(registers + 20, opcode=0x104) == 0xa1 and
                    access(registers, opcode=0x104) & 1 and flags() == 0,
                    'Active FIFO error mask changed stream progress or configuration')
            access(registers + 20, 0x21)
            access(registers, 0)
    require(remote.command('qRcmd,' + 'system_reset'.encode().hex()) == 'OK',
            'Controller reset failed')
    for base in (0x40026000, 0x40026400):
        require(access(base, opcode=0x104) == 0 and access(base + 4, opcode=0x104) == 0,
                'DMA reset retained status')
        for stream in range(8):
            registers = base + 0x10 + stream * 0x18
            require(all(access(registers + offset, opcode=0x104) == 0
                        for offset in (0, 4, 8, 12, 16)) and
                    access(registers + 20, opcode=0x104) == 0x21,
                    'DMA reset retained stream configuration')
    for address, opcode in ((0x40026000, 0x100), (0x40026010, 0x108),
                             (0x400260d0, 0x104)):
        access(address, 0, opcode, fault=True)
        require(remote.command('qRcmd,' + 'system_reset'.encode().hex()) == 'OK',
                'Controller reset after DMA access fault failed')
    for address, value in ((0x40026014, 8), (0x40026024, 0x22)):
        for offset, initial in ((0x14, 4), (0x18, 0x40005810), (0x1c, TARGET),
                                (0x10, 0x0e000401)):
            access(0x40026000 + offset, initial)
        access(address, value, fault=True)
        require(remote.command('qRcmd,' + 'system_reset'.encode().hex()) == 'OK',
                'Controller reset after active DMA configuration fault failed')
    print('PASS controller DMA: sixteen streams, three widths, IRQs, guards, errors and request waits')


def check_disabled(remote, access):
    remote.write(SOURCE, b'source')
    remote.write(TARGET, b'target')
    for base in (0x40026000, 0x40026400):
        for offset, value in ((0x14, 6), (0x18, SOURCE), (0x1c, TARGET), (0x10, 0x681)):
            access(base + offset, value)
        for _ in range(20):
            require(access(base, opcode=0x104) == 0 and
                    access(base + 0x14, opcode=0x104) == 6 and
                    remote.read(TARGET, 6) == b'target',
                    'Disabled DMA completion changed the target or count')
        access(base + 0x10, 0)
    print('PASS disabled controller DMA completion')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    qemu = parser.parse_args().qemu
    run(qemu, check_dma)
    run(qemu, check_disabled, ('-global', 'nikon-z72-controller-dma.completion=off'))
