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
            remote.write(0xc6313cc0, master_guard)
            for source in (0xc1000010, 0xc144d5c0, 0xc3f00000,
                           0xc5b9f300, 0xc60f0000, 0xc6100000,
                           0xc6313cc0, 0xc81ffff8, 0xc8200000, 0xc88ffff8):
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
                require(remote.read(0xc6313cc0, 8) == master_guard,
                        'Slave runtime arena replaced the master local frame pool')
                remote.select_thread(3)
                require(remote.read(source, 8) == struct.pack('<2I', *replacement),
                        'Master peer store did not update the slave backing')
                if 0xc6100000 <= source < 0xc8200000:
                    uncached = source - 0xb1000000
                    require(remote.read(uncached, 8) == struct.pack('<2I', *replacement),
                            'Slave runtime arena bus window has independent storage')
                    remote.write(uncached, master_guard)
                    require(remote.read(source, 8) == master_guard,
                            'Slave runtime arena bus store did not update local storage')
            require(remote.command('m17200000,4').startswith('E') and
                    remote.command('mc8900000,4').startswith('E'),
                    'Slave arena bus alias or code cache extends beyond its boundary')
            # The native compute initializer saves code through channel 0.
            # Verify real bytes and guards in the separate cache, then reject
            # a transfer to the still-unmapped arena bus endpoint.
            source, target = 0x10021000, 0xc8201000
            data = bytes((i * 37 + 11) & 255 for i in range(8193))
            remote.write(source, data)
            remote.write(target - 4, b'HEAD' + bytes(len(data)) + b'TAIL')
            remote.write(0x40100008, struct.pack('<I', 0xe5810000))

            def sequencer_word(offset, value):
                remote.set(pc=0x40100008, cpsr=0xd3, r0=value, r1=0x04251010 + offset)
                remote.command('vCont;s:3')

            for offset, value in ((0, len(data) - 1), (4, source), (8, target),
                                  (12, 0x30f00), (16, 0x30f00)):
                sequencer_word(offset, value)
            sequencer_word(24, 0x11109003)
            require(remote.read(target, len(data)) == data and
                    remote.read(target - 4, 4) == b'HEAD' and
                    remote.read(target + len(data), 4) == b'TAIL' and
                    remote.read(0x04251030, 4) == struct.pack('<I', 8),
                    'Slave sequencer did not copy code bytes into its cache')
            sequencer_word(32, 0)
            sequencer_word(8, 0x17200000)
            sequencer_word(24, 0x11109003)
            require(remote.read(0x04251030, 4) == struct.pack('<I', 1) and
                    remote.read(target, len(data)) == data,
                    'Slave sequencer accepted an unmapped target or changed the cache')
            for address in (0x80300000, 0x803277f8):
                remote.write(address, master_guard)
                require(remote.read(address, 8) == master_guard,
                        'Slave compute program storage boundary differs')
            require(remote.command('m802ffffc,4').startswith('E') and
                    remote.command('m80327800,4').startswith('E'),
                    'Slave compute program storage exceeds the observed upload span')
            target = 0x80301000
            remote.write(target - 4, b'HEAD' + bytes(len(data)) + b'TAIL')
            sequencer_word(32, 0)
            sequencer_word(8, target)
            sequencer_word(24, 0x11109003)
            require(remote.read(target, len(data)) == data and
                    remote.read(target - 4, 4) == b'HEAD' and
                    remote.read(target + len(data), 4) == b'TAIL' and
                    remote.read(0x04251030, 4) == struct.pack('<I', 8),
                    'Slave compute program upload or guards differ')
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
            print('PASS peer ownership, RAM gaps, slave code-cache and compute program uploads')
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
