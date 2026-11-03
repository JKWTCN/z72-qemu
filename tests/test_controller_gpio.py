# SPDX-License-Identifier: GPL-2.0-or-later
"""Exercise controller pins with synthetic Thumb loads and stores."""
import argparse
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import require
from analyze.qemu_display import Remote


def run(qemu, additional_checks=None, device_properties=()):
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        image = bytearray(0x200)
        struct.pack_into('<2I', image, 0, 0x20001000, 0x08000101)
        for vector in (3, 4, 5, 6):
            struct.pack_into('<I', image, vector * 4, 0x08000121)
        # STR r1,[r0]; LDR r2,[r0]; STRB r1,[r0]; STRH r1,[r0].
        for offset, opcode in ((0x100, 0x6001), (0x104, 0x6802),
                               (0x108, 0x7001), (0x10c, 0x8001), (0x120, 0xe7fe),
                               (0x140, 0x2301), (0x142, 0x6001), (0x144, 0xe7fe)):
            struct.pack_into('<H', image, offset, opcode)
        (root/'synthetic.bin').write_bytes(image)
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        remote = process = None
        try:
            with (root/'qemu.log').open('wb') as log:
                process = subprocess.Popen([qemu, '-M', 'nikon-z72-controller-lab,power-switch=off',
                    '-kernel', str(root/'synthetic.bin'), '-display', 'none',
                    '-serial', 'none', '-monitor', 'none', '-nic', 'none',
                    '-S', '-gdb', f'tcp:127.0.0.1:{port}',
                    '-trace', 'enable=z72_controller_gpio_transition', *device_properties],
                    stdout=subprocess.DEVNULL, stderr=log,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
            deadline = time.monotonic() + 10
            while remote is None:
                try:
                    remote = Remote(port)
                except ConnectionRefusedError:
                    require(process.poll() is None and time.monotonic() < deadline,
                            'Synthetic controller startup failed')
                    time.sleep(.05)

            def access(address, value=0, opcode=0x100, fault=False):
                remote.set(r0=address, r1=value, pc=0x08000000 + opcode)
                remote.command('s')
                regs = remote.regs()
                if fault:
                    require(remote.get(regs, 'pc') == 0x08000120 and
                            int.from_bytes(remote.read(0xE000ED28, 4), 'little') & 0x8200 == 0x8200,
                            'Unsupported pin access did not produce a precise fault')
                else:
                    require(remote.get(regs, 'pc') == 0x08000002 + opcode,
                            'Synthetic pin access faulted')
                return remote.get(regs, 'r2')

            for port in range(8):
                base = 0x40020000 + port * 0x400
                bit = 1 << port
                access(base, 1 << (2 * port))
                access(base + 0x18, bit)
                require(access(base + 0x14, opcode=0x104) == bit and
                        access(base + 0x10, opcode=0x104) == bit,
                        'Pin output latch or output readback differs')
                access(base + 0x18, bit << 16)
                require(access(base + 0x10, opcode=0x104) == 0,
                        'Pin reset mask did not clear the output')
                access(base + 0x14, 0xffff0000 | bit)
                require(access(base + 0x14, opcode=0x104) == bit,
                        'Output latch exceeded sixteen pins')
                access(base, 0)
                access(base + 0xc, 1 << (2 * port))
                require(access(base + 0x10, opcode=0x104) == bit,
                        'Disconnected input did not reflect its pull-up')
                access(base + 0xc, 2 << (2 * port))
                require(access(base + 0x10, opcode=0x104) == 0,
                        'Disconnected input did not reflect its pull-down')
                access(base + 0x20, 0x12345678 ^ port)
            require(remote.command('qRcmd,' + 'system_reset'.encode().hex()) == 'OK',
                    'Controller reset failed')
            for port in range(8):
                base = 0x40020000 + port * 0x400
                for offset in (0, 4, 8, 12, 16, 20, 24, 32, 36):
                    require(access(base + offset, opcode=0x104) == 0,
                            'Reset retained pin configuration or latch state')
            # Writer context is passive. Exercise both a single instruction
            # and a store inside a two-instruction translation block.
            base = 0x40021c00
            access(base, 0x50000000)
            remote.set(lr=0x08000161)
            access(base + 0x18, 0x8000)
            access(base + 0x18, 0x8000)
            access(base + 0x18, 0x80000000)
            remote.breakpoint(0x08000144)
            try:
                remote.set(r0=base + 0x18, r1=0x4000, pc=0x08000140, lr=0x08000171)
                remote.command('c')
                require(remote.get(remote.regs(), 'pc') == 0x08000144,
                        'Traced store did not reach its original continuation')
            finally:
                remote.breakpoint(0x08000144, False)
            access(base + 0x18, 0x40000000)
            access(base, 0)
            contexts = []
            for line in (root / 'qemu.log').read_text().splitlines():
                if 'z72_controller_gpio_transition ' in line:
                    contexts.append({key: int(value, 0) for key, value in re.findall(
                        r'(\w+)=(0x[0-9a-f]+|\d+)', line)})
            for value, expected_lr, valid_pc in ((0x8000, 0x08000161, (0x08000100,)),
                                                 (0x4000, 0x08000171, (0x08000140, 0x08000142))):
                matches = [item for item in contexts if item['base'] == base and item['value'] == value]
                require(len(matches) == 1 and matches[0].get('lr') == expected_lr and
                        matches[0].get('pc') in valid_pc,
                        'GPIO writer context missing, repeated, or outside its instruction block')
            if additional_checks is not None:
                additional_checks(remote, access)
            for address, opcode in ((0x40020010, 0x100), (0x40020000, 0x108),
                                    (0x40020000, 0x10c), (0x4002001c, 0x104),
                                    (0x40020028, 0x100)):
                access(address, 0xffffffff, opcode, fault=True)
                require(remote.command('qRcmd,' + 'system_reset'.encode().hex()) == 'OK',
                        'Controller reset after access fault failed')
            print('PASS controller pins: eight ports, latches, pulls, reset, access faults and writer context')
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
