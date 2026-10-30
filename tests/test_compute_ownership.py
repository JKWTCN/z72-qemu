# SPDX-License-Identifier: GPL-2.0-or-later
"""Check compute-channel claims, occupancy, reset and engine isolation."""
import argparse
from pathlib import Path
import struct
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import BASE, require
from tools.dual_boot_probe import dual_machine


def check(qemu):
    image = struct.pack('<3I', 0xe5810000, 0xe5912000, 0xeafffffe)
    with tempfile.TemporaryDirectory(prefix='compute-ownership-') as folder:
        directory = Path(folder)
        process = remote = None
        try:
            process, remote = dual_machine(qemu, directory, image, image,
                directory / 'console.txt', icount=None, trace=None)

            def write(thread, address, value):
                remote.select_thread(thread)
                remote.set(pc=BASE, cpsr=0xd3, r0=value, r1=address)
                remote.command(f'vCont;s:{thread:x}')
                require(remote.get(remote.regs(), 'pc') == BASE + 4, 'Store faulted')

            def read(thread, address):
                remote.select_thread(thread)
                remote.set(pc=BASE + 4, cpsr=0xd3, r1=address)
                remote.command(f'vCont;s:{thread:x}')
                regs = remote.regs()
                require(remote.get(regs, 'pc') == BASE + 8, 'Read faulted')
                return remote.get(regs, 'r2')

            for thread, peer in ((1, 3), (3, 1)):
                require(read(thread, 0x24061900) == 0, 'Initial occupancy is nonzero')
                for channel in range(8):
                    owner = 0x24061100 + channel * 0x80
                    write(thread, owner + 0x44, 0x12340000 + channel)
                    write(thread, owner, 1 << channel)
                    require(read(thread, owner) == 1 << channel, 'Claim failed')
                    require(read(thread, 0x24061900) == (1 << (channel + 1)) - 1,
                            'Occupied bitmap differs from claims')
                    write(thread, owner, 0x8000)
                    require(read(thread, owner) == 1 << channel, 'Contender stole channel')
                    require(read(peer, owner) == 0, 'Ownership leaked to peer engine')
                    require(read(thread, owner + 0x44) == 0x12340000 + channel,
                            'Claim changed payload')
                write(thread, 0x24061900, 0)
                require(read(thread, 0x24061900) == 255, 'Bitmap accepted a software clear')
                for channel in (3, 0, 7, 1, 6, 2, 5, 4):
                    owner = 0x24061100 + channel * 0x80
                    write(thread, owner, 0)
                    require(read(thread, owner) == 0 and
                            not read(thread, 0x24061900) & (1 << channel), 'Release failed')
                require(read(thread, 0x24061900) == 0, 'Release left occupied channels')
                for address in (0x24061080, 0x24061084, 0x24061138):
                    require(read(thread, address) == 0, 'Ownership generated a reply')
            for thread in (1, 3):
                write(thread, 0x24061100, 0xffff)
                write(thread, 0x24061480, 0x80)
            require(remote.command('qRcmd,' + 'system_reset'.encode().hex()) == 'OK',
                    'Reset failed')
            for thread in (1, 3):
                require(read(thread, 0x24061100) == 0 and read(thread, 0x24061480) == 0 and
                        read(thread, 0x24061900) == 0, 'Reset retained ownership')
            print('PASS compute ownership: eight channels, contention, bitmap, release, '
                  'payload guards, no replies, reset and engine isolation')
        finally:
            if remote is not None:
                remote.sock.close()
            if process is not None and process.poll() is None:
                process.terminate()
                process.wait(timeout=5)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    check(parser.parse_args().qemu)
