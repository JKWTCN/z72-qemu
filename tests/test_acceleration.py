# SPDX-License-Identifier: GPL-2.0-or-later
"""Check optional raw acceleration input through timed engine I2C transfers."""
import argparse
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import BASE, require
from tools.boot_probe import reset_machine
from tools.smp_boot_probe import reach


def check(qemu):
    image = struct.pack('<6I', 0xe5810000, 0xe5912000, 0xeafffffe,
                        0xe2500001, 0x1afffffd, 0xeafffffe)
    target = 'nikon-z72-acceleration,bus=master-i2c2,address=29'
    with tempfile.TemporaryDirectory() as folder:
        for present in (False, True):
            device = target + (',sample-present=on,sample-x=-2048,sample-y=2047,sample-z=-1'
                               if present else '')
            with reset_machine(qemu, Path(folder) / str(present), image, 'master',
                               icount='shift=4,sleep=off', devices=(device,)) as remote:
                def access(offset, value=0, read=False):
                    pc = BASE + (4 if read else 0)
                    remote.set(pc=pc, cpsr=0xd3, r0=value, r1=0x2c01a000 + offset)
                    remote.command('s')
                    regs = remote.regs()
                    require(remote.get(regs, 'pc') == pc + 4, 'I2C access aborted')
                    return remote.get(regs, 'r2')

                def transfer(values=(), count=0, accepted=True, hold=False, restart=False):
                    if restart:
                        access(16, 0x2ff)
                    else:
                        access(0, 0x63 if count else 0x62)
                    if count:
                        access(20, count)
                    else:
                        for value in values:
                            access(12, value)
                    access(0, (0x2b if count else 0x2a) | (0x10 if hold else 0))
                    access(8, 0x1d)
                    remote.set(pc=BASE + 12, cpsr=0xd3, r0=16384)
                    reach(remote, BASE + 20)
                    status = access(16, read=True)
                    require(bool(status & 4) != accepted, 'Unexpected acceleration ACK/NACK')
                    if count and accepted:
                        return [access(12, read=True) for _ in range(count)]

                def read(reg, count=1, accepted=True):
                    transfer((reg,))
                    return transfer(count=count, accepted=accepted)

                require(read(0) == [0], 'Reset produced a ready sample')
                read(1, 6, accepted=False)
                for reg, count in ((0x0e, 2), (0x11, 1), (0x15, 1), (0x17, 2), (0x1d, 4)):
                    transfer([reg] + [0] * count)
                transfer([0x23] + [0] * 7 + [0x2c, 2] + [0] * 6)
                transfer((0x2a,))  # Incomplete control cannot activate.
                require(read(0) == [0], 'Partial write activated input')
                transfer((0x2a, 1, 0), accepted=False)
                require(read(0) == [0], 'Oversized write activated input')
                transfer((0x2a, 0xff), accepted=False)
                transfer((0xff,), accepted=False)
                transfer((0x2a, 0x2d))
                require(read(0) == [8 if present else 0], 'Activation/presence gate differs')
                transfer((0x11, 0), accepted=False)
                if present:
                    require(read(1, 6) == [0x80, 0, 0x7f, 0xf0, 0xff, 0xf0],
                            'Signed 12-bit wire encoding differs')
                    require(read(1, 7)[-1] == 0xff, 'Overread fabricated another sample')
                    require(read(0, 2) == [8, 0xff], 'Status overread differs')
                else:
                    read(1, 6, accepted=False)
                transfer((0x2a, 0))
                require(read(0) == [0], 'Standby retained ready state')
                read(1, 6, accepted=False)
                # A repeated START is not STOP: discard the staged control.
                transfer((0x2a, 1), hold=True)
                require(access(4, read=True) == 0x100, 'HOLD released the bus')
                transfer((0,), hold=True, restart=True)
                require(transfer(count=1, hold=True, restart=True) == [0],
                        'Repeated START committed a control write without STOP')
                access(0, 0x2b)
                require(access(4, read=True) == 0, 'HOLD release retained bus ownership')
                # Restart before the TX deadline. The receive address NACKs
                # because no selector was sent; the old timer must not finish RX.
                access(0, 0x62)
                access(12, 0x2a)
                access(12, 1)
                access(0, 0x3a)
                access(8, 0x1d)
                access(20, 1)
                access(0, 0x3b)
                access(8, 0x1d)
                remote.set(pc=BASE + 12, cpsr=0xd3, r0=16384)
                reach(remote, BASE + 20)
                require(access(16, read=True) == 4 and access(4, read=True) == 0,
                        'Rejected restart retained a timer or fabricated receive completion')
                require(read(0) == [0], 'Cancelled write activated input')
                transfer((0x2a, 1))
                require(remote.command('qRcmd,' + 'system_reset'.encode().hex()) == 'OK',
                        'System reset failed')
                require(read(0) == [0], 'System reset retained activation')
                transfer((0x2a, 1))
                require(read(0) == [8 if present else 0], 'Reset lost configured external input')
    for axis in ('x', 'y', 'z'):
        for value in (-2049, 2048):
            result = subprocess.run([qemu, '-M', 'nikon-z72-lab', '-display', 'none',
                '-serial', 'none', '-device', target + f',sample-{axis}={value}'],
                capture_output=True, timeout=10)
            require(result.returncode != 0 and b'signed 12 bits' in result.stderr,
                    'Out-of-range acceleration axis accepted')
    print('PASS acceleration: default absence, programming, signed axes, bounds, NACK and reset')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    check(parser.parse_args().qemu)
