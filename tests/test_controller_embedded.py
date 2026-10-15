# SPDX-License-Identifier: GPL-2.0-or-later
"""Check embedded controller execution, reset aliases and private DMA memory."""
import argparse
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import require
from analyze.qemu_display import Remote


def check(qemu, auto_link=False):
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        image = bytearray(0x200)
        struct.pack_into('<2I', image, 0, 0x20001000, 0x08000101)
        for vector in (3, 4, 5, 6):
            struct.pack_into('<I', image, vector * 4, 0x08000181)
        for offset, instruction in ((0x100, 0x6001), (0x104, 0x6802), (0x180, 0xe7fe)):
            struct.pack_into('<H', image, offset, instruction)
        firmware = root / 'controller.bin'
        firmware.write_bytes(image)
        engine = root / 'engine.bin'
        engine_bytes = struct.pack('<7I', 0xe3a0002a, 0xeafffffe, 0xe5801000,
                                   0xe5902000, 0xe2533001, 0x1afffffd, 0xeafffffe)
        engine.write_bytes(engine_bytes)
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        machine = 'nikon-z72-dual-lab,controller-firmware=' + str(firmware)
        if auto_link:
            machine += ',controller-link=on'
        command = [qemu, '-M', machine,
                   '-device', f'loader,file={engine},addr=0,cpu-num=0,force-raw=on',
                   '-global', 'nikon-z72-spi.peer-low-byte-first=' + ('on' if auto_link else 'off'),
                   '-display', 'none', '-serial', 'none', '-monitor', 'none', '-nic', 'none',
                   '-S', '-gdb', f'tcp:127.0.0.1:{port}', '-icount', 'shift=4,sleep=off']
        if not auto_link:
            for serial_port in (0, 1):
                command += ['-device', f'nikon-z72-controller-spi-peer,bus=master-spi{serial_port},controller=/machine/controller/spi{serial_port}']
        remote = process = None
        try:
            with (root / 'qemu.log').open('wb') as log:
                process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=log,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
            deadline = time.monotonic() + 10
            while remote is None:
                try:
                    remote = Remote(port)
                except ConnectionRefusedError:
                    require(process.poll() is None and time.monotonic() < deadline,
                            'Embedded controller startup failed: ' +
                            (root / 'qemu.log').read_text(errors='replace'))
                    time.sleep(.05)
            threads = []
            response = remote.command('qfThreadInfo')
            while response != 'l':
                require(response.startswith('m'), 'Thread enumeration failed')
                threads += [int(value, 16) for value in response[1:].split(',')]
                response = remote.command('qsThreadInfo')
            require(threads == [1, 2, 3, 4, 5], 'Embedded machine did not create five execution cores')
            remote.select_thread(1)
            require(remote.read(0, len(engine_bytes)) == engine_bytes, 'Controller flash replaced engine local memory')
            # Initialize the round-robin execution thread through its first core.
            remote.command('vCont;s:1')
            require(remote.get(remote.regs(), 'r0') == 42, 'Engine core did not execute its own image')
            remote.select_thread(5)
            require(remote.get(remote.regs(), 'pc') == 0x08000100 and
                    remote.get(remote.regs(), 'sp') == 0x20001000 and
                    remote.read(0, 8) == image[:8], 'Embedded controller vectors or private alias differ')

            def access(address, value=None):
                remote.set(r0=address, r1=0 if value is None else value,
                           pc=0x08000104 if value is None else 0x08000100)
                remote.command('vCont;s:5')
                regs = remote.regs()
                require(remote.get(regs, 'pc') == (0x08000106 if value is None else 0x08000102),
                        'Embedded controller memory instruction faulted')
                return remote.get(regs, 'r2')

            remote.write(0x20002000, bytes((0x18, 0x27, 0x36, 0x45)))
            access(0x40026014, 4)
            access(0x40026018, 0x20002000)
            access(0x4002601c, 0x20002100)
            access(0x40026010, 0x681)
            for _ in range(1000):
                if access(0x40026000) & 0x20:
                    break
            require(remote.read(0x20002100, 4) == bytes((0x18, 0x27, 0x36, 0x45)) and
                    access(0x40026014) == 0, 'Embedded DMA used the wrong address space')

            def engine_access(address, value=None):
                remote.select_thread(1)
                remote.set(r0=address, r1=0 if value is None else value, pc=12 if value is None else 8)
                remote.command('vCont;s:1')
                regs = remote.regs()
                require(remote.get(regs, 'pc') == (16 if value is None else 12), 'Engine serial access faulted')
                return remote.get(regs, 'r2')

            def advance():
                remote.select_thread(1)
                remote.set(pc=16, r3=1024)
                remote.breakpoint(24)
                try:
                    remote.command('vCont;c:1')
                finally:
                    remote.breakpoint(24, False)
                require(remote.get(remote.regs(), 'pc') == 24, 'Engine timing loop did not complete')

            # Clock actual controller requests between serial bytes, including packed halfwords.
            for bits, words, payload in ((8, (0x31, 0x62, 0x93, 0xc4), bytes((0x31, 0x62, 0x93, 0xc4))),
                                         (16, (0x1b72, 0xd4a6), bytes((0x72, 0x1b, 0xa6, 0xd4)) if auto_link
                                          else bytes((0x1b, 0x72, 0xd4, 0xa6)))):
                remote.select_thread(5)
                access(0x40013000, 0x240)
                access(0x4001300c, 0x59)
                access(0x40026414, 4)
                access(0x40026418, 0x4001300c)
                access(0x4002641c, 0x20002200)
                access(0x40026410, 0x06000401)
                access(0x40013004, 1)
                bus = 0x2c0a0000
                engine_access(bus + 0x3c, 0)
                engine_access(bus + 0x10, (bits - 1) << 8)
                engine_access(bus + 0x3c, 1)
                for value in words:
                    engine_access(bus, value)
                advance()
                received = [engine_access(bus + 4) for _ in words]
                require(received == ([0x59, 0xff, 0xff, 0xff] if bits == 8 else
                                     [0xff59 if auto_link else 0x59ff, 0xffff]),
                        'Controller slave words did not return through the engine FIFO')
                remote.select_thread(5)
                require(remote.read(0x20002200, 4) == payload and access(0x40026414) == 0 and
                        not access(0x40013008) & 0x40, 'Paced engine clocks lost controller receive DMA bytes')
            remote.select_thread(5)
            remote.write(0x20002400, bytes((0x11, 0x22, 0x33, 0x44)))
            access(0x40013400, 0x240)
            access(0x4002642c, 4)
            access(0x40026430, 0x4001340c)
            access(0x40026434, 0x20002400)
            access(0x40026428, 0x08000441)
            access(0x40013404, 2)
            bus = 0x2c0a0100
            engine_access(bus + 0x10, 15 << 8)
            engine_access(bus + 0x3c, 1)
            engine_access(bus, 0xffff)
            engine_access(bus, 0xffff)
            advance()
            require([engine_access(bus + 4), engine_access(bus + 4)] ==
                    ([0x2211, 0x4433] if auto_link else [0x1122, 0x3344]),
                    'Controller transmit DMA did not reach packed engine receive words')
            if auto_link:
                engine_access(0x0426f014, 0xc)
                engine_access(0x0426f000, 0xc)
                remote.select_thread(5)
                for base, pin in ((0x40020400, 14), (0x40021000, 3), (0x40020c00, 12)):
                    access(base, 1 << (pin * 2))
                    access(base + 0x18, 1 << pin)
                require(engine_access(0x04282014) & 0x600 == 0x600 and
                        engine_access(0x04282018) & 0x8000,
                        'Controller ready or acknowledgement outputs did not reach engine inputs')
                require(engine_access(0x0426f008) & 0xc == 0xc and
                        not engine_access(0x04001208) & 0x18,
                        'Masked controller edges were lost or reached the interrupt controller')
                engine_access(0x0426f000, 0)
                require(engine_access(0x04001208) & 0x18 == 0x18,
                        'Controller ready edges did not reach interrupts 67 and 68')
                engine_access(0x0426f008, 0)
                require(engine_access(0x0426f008) & 0xc == 0xc,
                        'Writing status fabricated an interrupt acknowledgement')
                engine_access(0x0426f010, 4)
                engine_access(0x04001288, 8)
                require(engine_access(0x0426f008) & 0xc == 8 and
                        engine_access(0x04001208) & 0x18 == 0x10,
                        'Acknowledging transmit readiness cleared receive readiness')
                engine_access(0x0426f010, 8)
                engine_access(0x04001288, 0x10)
                engine_access(0x04282018, 0x10001000)
                remote.select_thread(5)
                require(access(0x40021810) & 0x40,
                        'Engine receive acknowledgement did not reach controller G6')
                engine_access(0x04282018, 0x00080000)
                remote.select_thread(5)
                require(access(0x40021810) & 0x40,
                        'An unrelated output write cleared controller acknowledgement')
                engine_access(0x04282018, 0x10000000)
                remote.select_thread(5)
                require(not access(0x40021810) & 0x40,
                        'Clearing engine acknowledgement did not release controller G6')
                for base, pin in ((0x40020400, 14), (0x40021000, 3), (0x40020c00, 12)):
                    access(base + 0x18, 1 << (pin + 16))
                engine_access(0x04282014, 0x06000600)
                require(not engine_access(0x04282014) & 0x600 and
                        not engine_access(0x04282018) & 0x8000,
                        'Engine writes fabricated controller input levels')
                engine_access(0x04282018, 0x10001000)
            remote.select_thread(1)
            require(remote.read(0, len(engine_bytes)) == engine_bytes, 'Controller execution changed engine local memory')
            engine_serial = engine_access(0x2c0a0018)
            for thread in range(1, 5):
                remote.select_thread(thread)
                remote.set(r4=0x13570000 + thread)
            remote.select_thread(5)
            access(0x40026010, 0x680)
            access(0x40000400, 1)
            access(0xe000e100, 1 << 18)
            access(0xe000e010, 5)
            access(0x40002850, 0x24681357)
            remote.write(0x20002200, b'keep')
            remote.set(r0=0xe000ed0c, r1=0x05fa0004, pc=0x08000100)
            remote.command('vCont;s:5')
            regs = remote.regs()
            require(remote.get(regs, 'pc') == 0x08000100 and
                    remote.get(regs, 'sp') == 0x20001000,
                    'Controller system reset did not restore its CPU vectors')
            require(access(0x40026010) == 0 and access(0x40000400) == 0 and
                    access(0xe000e100) == 0 and access(0xe000e010) & 7 == 0,
                    'Controller system reset retained peripheral or interrupt state')
            require(access(0x40002850) == 0x24681357 and
                    remote.read(0x20002200, 4) == b'keep',
                    'Controller system reset cleared its backup domain or SRAM')
            for thread in range(1, 5):
                remote.select_thread(thread)
                require(remote.get(remote.regs(), 'r4') == 0x13570000 + thread,
                        'Controller system reset changed an engine CPU')
            require(engine_access(0x2c0a0018) == engine_serial,
                    'Controller system reset changed engine serial state')
            require(remote.command('qRcmd,' + 'system_reset'.encode().hex()) == 'OK', 'Embedded reset failed')
            remote.select_thread(5)
            require(remote.get(remote.regs(), 'pc') == 0x08000100 and remote.read(0, 8) == image[:8] and
                    access(0x40026010) == 0, 'Embedded reset did not restore vectors and DMA state')
            if auto_link:
                require(not access(0x40021810) & 0x40 and engine_access(0x0426f008) & 0xc == 0,
                        'Reset retained controller acknowledgement or edge state')
            require(firmware.read_bytes() == image, 'Embedded test modified its input image')
            print('PASS embedded controller: five cores, private DMA, paced serial bytes/halfwords, local and board reset',
                  'board-link=' + str(auto_link))
        finally:
            if remote is not None:
                remote.sock.close()
            if process is not None and process.poll() is None:
                process.terminate()
                process.wait(timeout=5)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    args = parser.parse_args()
    check(args.qemu)
    check(args.qemu, True)
