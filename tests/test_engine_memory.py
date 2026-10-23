# SPDX-License-Identifier: GPL-2.0-or-later
"""Check row transfers, completion interrupts, stop and rejected memory ranges."""
import argparse
from pathlib import Path
import struct
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import BASE, require
from tools.boot_probe import reset_machine
from tools.smp_boot_probe import reach


def check(qemu):
    image = struct.pack('<11I', 0xe5810000, 0xe5912000, 0xe5c10000,
                        0, 0, 0, 0, 0, 0xe2500001, 0x1afffffd, 0xeafffffe)
    with tempfile.TemporaryDirectory() as folder:
        directory = Path(folder)
        for role in ('master', 'slave'):
            with reset_machine(qemu, directory / role, image, role,
                               icount='shift=4,sleep=off') as remote:
                def access(address, value=0, read=False, byte=False):
                    instruction = 2 if byte else 1 if read else 0
                    remote.set(pc=BASE + instruction * 4, cpsr=0xd3,
                               r0=value, r1=address)
                    remote.command('s')
                    regs = remote.regs()
                    if byte:
                        require(remote.get(regs, 'pc') == 16 and
                                remote.get(regs, 'cpsr') & 31 == 0x17,
                                'Non-word memory transfer access did not abort')
                    else:
                        require(remote.get(regs, 'pc') == BASE + instruction * 4 + 4,
                                'Memory transfer register access failed')
                    return remote.get(regs, 'r2') if read else None

                def advance():
                    remote.set(pc=BASE + 32, cpsr=0xd3, r0=16384)
                    reach(remote, BASE + 40)

                source = 0xb1900000 if role == 'master' else 0xc1000000
                destination = source + 0x1000
                original = bytes(range(32))
                for channel in range(2):
                    remote.write(source, original)
                    base = 0x20070000 + channel * 0x40
                    irq_bit = 1 << (7 + channel)
                    require(access(base + 0x0c, read=True) == 0,
                            'Memory error detail word is not readable')
                    remote.set(pc=BASE, cpsr=0xd3, r0=0xffffffff, r1=base + 0x0c)
                    remote.command('s')
                    regs = remote.regs()
                    require(remote.get(regs, 'pc') == 16 and
                            remote.get(regs, 'cpsr') & 31 == 0x17 and
                            access(base + 0x0c, read=True) == 0,
                            'Software changed read-only memory error details')

                    def submit(mode, target=destination, input_address=source):
                        for offset, value in ((4, 0x10), (0x14, mode), (0x18, 0x5a),
                                              (0x1c, 8), (0x20, 9), (0x24, 5),
                                              (0x28, 3), (0x2c, input_address),
                                              (0x30, target)):
                            access(base + offset, value)
                        access(base + 8, 0x11)
                        access(base + 0x10, 1)

                    remote.write(destination, b'\xa5' * 32)
                    submit(1)
                    advance()
                    expected = bytearray(b'\xa5' * 32)
                    for row in range(3):
                        expected[row * 9:row * 9 + 5] = b'\x5a' * 5
                    require(remote.read(destination, 32) == expected and
                            access(base + 8, read=True) == 1,
                            'Strided byte fill or completion differs')
                    require(not access(0x0400120c, read=True) & irq_bit,
                            'Masked completion raised an interrupt')
                    access(base + 4, 0x11)
                    require(access(0x0400120c, read=True) & irq_bit,
                            'Memory completion interrupt was not routed')
                    access(base + 8, 0x10)
                    require(access(base + 8, read=True) == 1,
                            'Wrong-bit acknowledgement cleared completion')
                    access(base + 8, 1)
                    access(0x0400128c, irq_bit)
                    require(not access(0x0400120c, read=True) & irq_bit,
                            'Acknowledged memory interrupt remained pending')
                    access(base + 0x10, 0)
                    require(access(base + 0x10, read=True) & 3 == 2,
                            'Memory stop did not acknowledge idle state')

                    for mode in (0, 0x10):
                        remote.write(destination, b'\xa5' * 32)
                        submit(mode)
                        advance()
                        for row in range(3):
                            expected[row * 9:row * 9 + 5] = original[row * 8:row * 8 + 5]
                        copied = remote.read(destination, 32)
                        require(copied == expected and access(base + 8, read=True) == 1,
                                f'Strided copy mode {mode:#x} differs: {copied.hex()}, status='
                                f'{access(base + 8, read=True):#x}')
                    remote.write(destination, b'keep')
                    submit(0x20)
                    advance()
                    require(access(base + 8, read=True) == 0x10 and
                            remote.read(destination, 4) == b'keep',
                            'Unsupported memory format copied data or reported success')

                    boundary = 0xb1900000 if role == 'master' else 0xc1a00000
                    remote.write(boundary - 4, b'HEAD' + b'\xa5' * 16 + b'TAIL')
                    for offset, value in ((4, 0x11), (0x14, 1), (0x18, 0),
                                          (0x20, 16), (0x24, 16), (0x28, 1),
                                          (0x30, boundary - 2)):
                        access(base + offset, value)
                    access(base + 8, 0x11)
                    access(base + 0x10, 1)
                    advance()
                    require(remote.read(boundary - 4, 24) ==
                            b'HE' + bytes(16) + b'\xa5\xa5TAIL',
                            'Transfer rejected adjacent RAM or changed its guards')

                    for target, input_address in ((destination, 0x20070000),
                                                  (0x13fffff8, source)):
                        remote.write(destination, b'keep')
                        remote.write(0x13fffff8, b'boundary')
                        submit(0, target, input_address)
                        advance()
                        require(access(base + 8, read=True) == 0x10 and
                                remote.read(destination, 4) == b'keep' and
                                remote.read(0x13fffff8, 8) == b'boundary',
                                'Rejected transfer modified memory or reported success')
                        access(base + 8, 0x10)
                        access(0x0400128c, irq_bit)
                    access(base, 1, byte=True)
                remote.write(destination, b'\xa5' * 32)
                submit(1)
                require(remote.command('qRcmd,' + 'system_reset'.encode().hex()) == 'OK',
                        'Memory transfer board reset failed')
                advance()
                require(remote.read(destination, 32) == b'\xa5' * 32,
                        'Reset allowed a pending transfer to change memory')
                require(all(access(0x20070000 + channel * 0x40 + offset, read=True) == 0
                            for channel in range(2) for offset in (4, 8, 0x10, 0x14, 0x30)),
                        'Reset retained memory transfer state')
            print('PASS ' + role + ' engine memory: row fill/copy, padding, IRQ, stop, bounds and reset',
                  flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    check(parser.parse_args().qemu)
