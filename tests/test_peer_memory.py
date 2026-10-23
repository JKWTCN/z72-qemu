# SPDX-License-Identifier: GPL-2.0-or-later
"""Check peer RAM ownership with synthetic ARM loads and stores."""
import argparse
from pathlib import Path
import struct
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import require
from tools.dual_boot_probe import dual_machine


def run(qemu):
    with tempfile.TemporaryDirectory() as folder:
        work = Path(folder)
        stub = struct.pack('<2I', 0xe51ff004, 0x40100000)
        process = remote = None
        try:
            process, remote = dual_machine(qemu, work, stub, stub,
                                           work/'console.txt', icount=None)
            remote.select_thread(1)
            remote.write(0x40100000, struct.pack('<2I', 0xe1c200d0, 0xe1c200f0))
            master_guard = b'ownerRAM'
            remote.write(0xc5b9f300, master_guard)
            for source in (0xc1000010, 0xc144d5c0, 0xc3f00000,
                           0xc5b9f300, 0xc60f0000):
                bus = source - 0x80000000
                words = (source ^ 0x12345678, source ^ 0x87654321)
                remote.select_thread(3)
                remote.write(source, struct.pack('<2I', *words))
                remote.select_thread(1)
                remote.set(pc=0x40100000, cpsr=0xd3, r2=bus)
                remote.command('vCont;s:1')
                regs = remote.regs()
                require((remote.get(regs, 'r0'), remote.get(regs, 'r1')) == words,
                        'Master did not load the slave backing through its bus alias')
                replacement = (words[1], words[0])
                remote.set(pc=0x40100004, r0=replacement[0], r1=replacement[1])
                remote.command('vCont;s:1')
                require(remote.read(0xc5b9f300, 8) == master_guard,
                        'Slave bus alias replaced the master local frame pool')
                remote.select_thread(3)
                require(remote.read(source, 8) == struct.pack('<2I', *replacement),
                        'Master peer store did not update the slave backing')
            remote.select_thread(1)
            remote.set(pc=0x40100000, cpsr=0xd3, r2=0x40800000)
            remote.command('vCont;s:1')
            regs = remote.regs()
            require(remote.get(regs, 'pc') == 0x10 and
                    remote.get(regs, 'cpsr') & 0x1f == 0x17,
                    'Slave bus alias filled an unmapped RAM gap')
            remote.select_thread(3)
            remote.write(0x40100000, struct.pack('<2I', 0xe1c200d0, 0xe1c200f0))
            guard = b'localRAM'
            remote.write(0xc2920f40, guard)
            for source in (0xb1800010, 0xb2920f40, 0xb2c00008,
                           0xb6000010, 0xb7cf0000, 0xbb300008):
                bus = source - 0x70000000
                words = (source ^ 0x12345678, source ^ 0x87654321)
                remote.select_thread(1)
                remote.write(source, struct.pack('<2I', *words))
                remote.select_thread(3)
                remote.set(pc=0x40100000, cpsr=0xd3, r2=bus)
                remote.command('vCont;s:3')
                regs = remote.regs()
                require((remote.get(regs, 'r0'), remote.get(regs, 'r1')) == words,
                        f'Peer load at {bus:#x} differs: '
                        f'{remote.get(regs, "r0"):#x}, {remote.get(regs, "r1"):#x}; '
                        f'PC {remote.get(regs, "pc"):#x}')
                replacement = (words[1], words[0])
                remote.set(pc=0x40100004, r0=replacement[0], r1=replacement[1])
                remote.command('vCont;s:3')
                require(remote.read(0xc2920f40, 8) == guard,
                        'Peer store changed local RAM')
                remote.select_thread(1)
                require(remote.read(source, 8) == struct.pack('<2I', *replacement),
                        'Peer store did not update the master backing')
            remote.select_thread(3)
            remote.set(pc=0x40100000, cpsr=0xd3, r2=0x41300000)
            remote.command('vCont;s:3')
            regs = remote.regs()
            require(remote.get(regs, 'pc') == 0x10 and
                    remote.get(regs, 'cpsr') & 0x1f == 0x17,
                    'Peer alias filled an unmapped RAM gap')
            print('PASS bidirectional peer loads, stores, owner backing, local isolation and RAM gaps')
        finally:
            if remote is not None:
                remote.sock.close()
            if process is not None and process.poll() is None:
                process.terminate()
                process.wait(timeout=5)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    run(parser.parse_args().qemu)
