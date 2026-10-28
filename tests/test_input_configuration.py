# SPDX-License-Identifier: GPL-2.0-or-later
"""Check input configuration bounds, parameter storage and engine isolation."""
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
    image = struct.pack('<4I', 0xE5810000, 0xE5912000, 0xE5C10000, 0xEAFFFFFE)
    with tempfile.TemporaryDirectory(prefix='input-configuration-') as folder:
        directory = Path(folder)
        process = remote = None
        try:
            process, remote = dual_machine(qemu, directory, image, image,
                directory / 'console.txt', icount=None, trace=None)

            def access(thread, address, value=None, byte=False, valid=True):
                remote.select_thread(thread)
                instruction = 2 if byte else 0 if value is not None else 1
                remote.set(pc=BASE + instruction * 4, cpsr=0xD3,
                           r0=value or 0, r1=address)
                remote.command(f'vCont;s:{thread:x}')
                regs = remote.regs()
                if valid:
                    require(remote.get(regs, 'pc') == BASE + (instruction + 1) * 4,
                            f'Configuration access faulted at {address:#x}')
                else:
                    require(remote.get(regs, 'pc') == 0x10 and
                            remote.get(regs, 'cpsr') & 0x1f == 0x17,
                            f'Unsupported configuration access survived at {address:#x}')
                return remote.get(regs, 'r2')

            # Format/crop fields, table boundaries, processing address sets,
            # and multi-plane versus single-plane image channels.
            fields = (0x20068500, 0x20068508, 0x2006881c, 0x20068a00,
                      0x20068e3c, 0x2006900c, 0x2006917c, 0x2006952c,
                      0x200697fc, 0x20069814, 0x20069850, 0x20069950,
                      0x20069a24, 0x20069a80, 0x20069b80, 0x20069efc,
                      0x20069f00, 0x2006b000, 0x2006b200, 0x2006b310, 0x2006b334,
                      0x2006a000, 0x2006a024, 0x2006a040,
                      0x2006a200, 0x2006a27c, 0x2006a370,
                      0x2006be00, 0x2006be24, 0x2006be40,
                      0x2006a414, 0x2006a450, 0x2006a654, 0x2006ad6c,
                      0x2006b318, 0x2006b3bc, 0x2006b3fc,
                      0x2006b800, 0x2006b820, 0x2006b87c, 0x2006b880, 0x2006b980,
                      0x2006b984,
                      0x2006ba00, 0x2006ba14, 0x2006ba34, 0x2006bab8, 0x2006bd80)
            values = {1: {}, 3: {}}
            for thread, peer in ((1, 3), (3, 1)):
                for address in fields:
                    value = (address ^ thread * 0x12345) & 0xffff
                    if address == 0x20068500:
                        value &= 0x3fff
                    access(thread, address, value)
                    values[thread][address] = value
                    require(access(thread, address) == value,
                            'Packed configuration value was changed')
                    require(access(peer, address) == values[peer].get(address, 0),
                            'Configuration leaked into the other engine')

                target = 0x40110000
                remote.select_thread(thread)
                remote.write(target, b'keep-data')
                access(thread, 0x20069850, target)
                access(thread, 0x20069814, 3)
                access(thread, 0x20069840, 1)
                values[thread][0x20069850] = target
                values[thread][0x20069814] = 3
                access(thread, 0x2006b318, 0x89abcdef)
                values[thread][0x2006b318] = 0x89abcdef
                require(access(thread, 0x2006b318) == 0x89abcdef,
                        'Packed configuration field was truncated')
                require(remote.read(target, 9) == b'keep-data',
                        'Configuration fabricated a pixel transfer')
                for address in (0x20068504, 0x20068900, 0x20069914,
                                0x2006a454, 0x2006a028, 0x2006a374, 0x2006b204,
                                0x2006b98c, 0x2006babc, 0x2006be28, 0x2006bf30):
                    access(thread, address, 1, valid=False)
                    access(thread, address, valid=False)
                for address in (0x2006a044, 0x2006a100, 0x2006a12c,
                                0x2006a3e0, 0x2006a3ec, 0x2006b988,
                                0x2006bb70, 0x2006bb78, 0x2006bb7c,
                                0x2006bc78, 0x2006bd7c, 0x2006be44,
                                0x2006bf00, 0x2006bf2c):
                    require(access(thread, address) == 0,
                            'Passive result register manufactured output')
                    access(thread, address, 1, valid=False)
                    require(access(thread, address) == 0,
                            'Rejected result write changed the register')
                access(thread, 0x20068500, 0x4000, valid=False)
                access(thread, 0x20068500, 1, byte=True, valid=False)
                access(thread, 0x20068501, 1, valid=False)
                # The neighboring input event banks keep their existing W1C
                # behavior; parameter writes must not create input events.
                require(access(thread, 0x20068210) == 0 and
                        access(thread, 0x2006807c) == 0,
                        'Configuration manufactured samples or events')

            require(remote.command('qRcmd,' + 'system_reset'.encode().hex()) == 'OK',
                    'Input configuration reset failed')
            for thread in (1, 3):
                require(all(access(thread, address) == 0 for address in fields),
                        'Reset retained input configuration')
            print('PASS input configuration: bounds, packing, isolation, reset and no DMA')
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
