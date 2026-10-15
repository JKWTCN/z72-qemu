# SPDX-License-Identifier: GPL-2.0-or-later
"""Check engine two-wire interrupts, register transfers, FIFO pacing and reset."""
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
            target = f'nikon-z72-controller-register-bank,bus={role}-i2c0,address=104'
            with reset_machine(qemu, directory / role, image, role,
                               icount='shift=4,sleep=off', devices=(target,)) as remote:
                def access(address, value=0, read=False, byte=False):
                    instruction = 2 if byte else 1 if read else 0
                    remote.set(pc=BASE + instruction * 4, cpsr=0xd3, r0=value, r1=address)
                    remote.command('s')
                    regs = remote.regs()
                    if byte:
                        require(remote.get(regs, 'pc') == 16 and
                                remote.get(regs, 'cpsr') & 31 == 0x17,
                                'Non-word engine bus access did not abort')
                    else:
                        require(remote.get(regs, 'pc') == BASE + instruction * 4 + 4,
                                'Engine bus access failed')
                    return remote.get(regs, 'r2') if read else None

                def advance():
                    remote.set(pc=BASE + 32, cpsr=0xd3, r0=16384)
                    reach(remote, BASE + 40)

                for channel in range(4):
                    bus = 0x2c018000 + channel * 0x1000
                    require(access(bus + 32, read=True) == 0x2ff,
                            'Engine bus reset mask differs')
                    access(bus, 0x2b)
                    access(bus + 20, 6)
                    access(bus + 8, 0x69)
                    require(access(bus + 16, read=True) == 4,
                            'Disconnected engine target did not NACK')
                    irq_bit = 1 << (214 + channel - 192)
                    require(not access(0x04001218, read=True) & irq_bit,
                            'Masked engine NACK raised an interrupt')
                    access(bus + 36, 7)
                    require(access(0x04001218, read=True) & irq_bit,
                            'Engine NACK interrupt was not routed')
                    access(bus + 16, 4)
                    access(0x04001298, irq_bit)
                    require(not access(0x04001218, read=True) & irq_bit,
                            'Engine NACK acknowledgement did not clear the interrupt')

                bus = 0x2c018000
                access(bus, 0x62)
                for value in (0x20, *range(1, 16)):
                    access(bus + 12, value)
                access(bus, 0x3a)
                access(bus + 8, 0x68)
                advance()
                require(access(bus + 16, read=True) == 2,
                        'Full held FIFO reported premature transfer completion')
                access(bus + 16, 2)
                for value in range(16, 25):
                    access(bus + 12, value)
                access(bus, 0x2a)
                advance()
                require(access(bus + 16, read=True) == 3,
                        'Final write FIFO did not complete')

                access(bus, 0x62)
                access(bus + 12, 0x20)
                access(bus, 0x2a)
                access(bus + 8, 0x68)
                advance()
                access(bus, 0x63)
                access(bus + 20, 16)
                access(bus, 0x3b)
                access(bus + 8, 0x68)
                advance()
                require(access(bus + 16, read=True) == 2,
                        'Full held read FIFO reported premature transfer completion')
                require(access(bus + 4, read=True) == 0x120,
                        'Held read did not expose available bytes and bus ownership')
                require([access(bus + 12, read=True) for _ in range(16)] == list(range(1, 17)),
                        'First read FIFO differs from target registers')
                access(bus + 16, 3)
                access(bus + 20, 8)
                access(bus, 0x2b)
                advance()
                require([access(bus + 12, read=True) for _ in range(8)] == list(range(17, 25)),
                        'Continued read lost the target register position')
                require(access(bus + 4, read=True) == 0,
                        'Final read retained FIFO data or bus ownership')
                access(bus, 0, byte=True)
                require(remote.command('qRcmd,' + 'system_reset'.encode().hex()) == 'OK',
                        'Engine bus reset failed')
                for channel in range(4):
                    base = 0x2c018000 + channel * 0x1000
                    require(access(base, read=True) == 0 and
                            access(base + 16, read=True) == 0 and
                            access(base + 32, read=True) == 0x2ff,
                            'Reset retained engine bus state')
            print('PASS ' + role + ' engine I2C: NACK, IRQs, register transfer, FIFO pacing and reset',
                  flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    check(parser.parse_args().qemu)
