#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Check graphics upload completion, command errors, cancellation and reset."""
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
from tools.graphics_boot_probe import graphics_observation


def check(qemu):
    image = struct.pack('<11I', 0xe5810000, 0xe5912000, 0xe5c10000,
                        0, 0, 0, 0, 0, 0xe2500001, 0x1afffffd, 0xeafffffe)
    with tempfile.TemporaryDirectory(prefix='z72-graphics-') as directory:
        with reset_machine(qemu, Path(directory) / 'machine', image, 'master',
                           icount='shift=4,sleep=off') as remote:
            def access(address, value=0, read=False, byte=False, fault=False):
                index = 2 if byte else 1 if read else 0
                remote.set(pc=BASE + index * 4, cpsr=0xd3, r0=value, r1=address)
                remote.command('s')
                regs = remote.regs()
                if fault:
                    require(remote.get(regs, 'pc') == 16, 'Invalid graphics access did not abort')
                    return
                require(remote.get(regs, 'pc') == BASE + index * 4 + 4,
                        'Graphics register access failed')
                return remote.get(regs, 'r2') if read else None

            def advance():
                remote.set(pc=BASE + 32, cpsr=0xd3, r0=10000)
                reach(remote, BASE + 40)

            source = 0xb2000800
            remote.write(source, struct.pack('<2I', 0x0040f004, 0x3f800000))
            for channel in range(2):
                base = 0x201810d0 + channel * 16
                access(0x20181020, 0)
                access(base + 4, source)
                access(base + 12, 1)
                access(base, 1)
                require(access(0x20180058, read=True) == 1 << 26,
                        'Queued graphics upload did not report busy')
                advance()
                require(access(base, read=True) == 0 and
                        access(0x20181020, read=True) == 1 and
                        access(0x20180c18, read=True) == 0,
                        'Valid graphics command did not complete')
                require(access(0x20180058, read=True) == 0,
                        'Completed upload retained busy state')
                require(access(0x04001210, read=True) & 2,
                        'Upload completion did not reach interrupt 129')
            access(0x20181020, 0)
            state = graphics_observation(remote)
            require(state['successful_uploads'] == 2 and state['rendered_commands'] == 0 and
                    state['failed_requests'] == 0, 'Graphics observation did not reflect actual uploads')
            remote.write(source, struct.pack('<2I', 7, 0))
            access(0x201810d0, 1)
            advance()
            require(access(0x20180c18, read=True) == 1 and
                    access(0x20181020, read=True) == 0 and
                    access(0x04001210, read=True) & 8,
                    'Malformed graphics command did not report an error on interrupt 131')
            access(0x20180c18, 0)
            access(0x201810d4, 0x04001000)
            access(0x201810d0, 1)
            advance()
            require(access(0x20180c18, read=True) == 1,
                    'Graphics upload read an interrupt-controller region as command memory')
            state = graphics_observation(remote)
            require(state['failed_requests'] == 2 and state['unsupported_commands'] == 1,
                    'Graphics observation lost rejected or malformed requests')
            access(0x20180c18, 0)
            access(0x201810d0, 1)
            access(0x201810d0, 0)
            advance()
            require(access(0x20180c18, read=True) == 0 and
                    access(0x20181020, read=True) == 0,
                    'Cancelled upload performed work')
            access(0x201810d0, 1)
            require(remote.command('qRcmd,' + 'system_reset'.encode().hex()) == 'OK', 'Graphics reset failed')
            advance()
            require(access(0x201810d0, read=True) == 0 and
                    access(0x20181020, read=True) == 0 and
                    access(0x20180c18, read=True) == 0,
                    'Reset retained queued graphics work or completion state')
            require(not any(graphics_observation(remote).values()),
                    'Reset retained graphics observation state')
            access(0x20181020, 0, byte=True, fault=True)
    print('PASS graphics: two upload channels, IRQs, malformed input, memory bounds, cancellation and reset')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    check(parser.parse_args().qemu)
