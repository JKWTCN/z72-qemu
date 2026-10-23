# SPDX-License-Identifier: GPL-2.0-or-later
"""Smoke-test the compiled Z72 board using synthetic ARM instructions only."""
import argparse
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time
import os

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.qemu_display import Remote
from analyze.decode_z72 import require
from analyze.system_configuration import SLAVE_BRANCH_WORDS
from analyze.platform_configuration import (PLATFORM_WORDS, ALL_STATUS_WORDS,
    RESULT_WORDS, COMPLETION_PAIRS)
from analyze.boot_continuation import CONTINUATION_WORDS

CONFIG_WORDS = (0x04264000, 0x04264020, 0x04281028, 0x0428102C,
                0x2B20003C, 0x2B20004C, 0x2B200050, 0x2B200054,
                0x2B200300,
                0x20068008, 0x20068018,
                0x20068200, 0x200682E0,
                0x20061000, 0x20061004, 0x20061024,
                0x200610E8, 0x200610F4, 0x20061134,
                0x2006128C, 0x20061400, 0x20061470, 0x200614B0,
                0x2A900078,
                *SLAVE_BRANCH_WORDS, *PLATFORM_WORDS, *CONTINUATION_WORDS, 0x20070008)
SPECIAL_WORDS = (*ALL_STATUS_WORDS, *RESULT_WORDS, 0x20070008)

def smoke(qemu, machine, addresses):
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        image = root / 'synthetic.bin'
        # ARM MOV r0,#42; B .; STR r0,[r1]; LDR r2,[r1]; STRB r0,[r1]
        image.write_bytes(struct.pack('<5I', 0xE3A0002A, 0xEAFFFFFE,
                                     0xE5810000, 0xE5912000, 0xE5C10000))
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0))
            port = sock.getsockname()[1]
        with (root/'qemu.log').open('wb') as log:
            process = subprocess.Popen([qemu,'-M',machine,'-display','none',
                '-serial','none','-monitor','none','-nic','none','-S','-gdb',f'tcp:127.0.0.1:{port}',
                '-device',f'loader,file={image},addr=0x40100000,cpu-num=0,force-raw=on'],
                stdout=subprocess.DEVNULL,stderr=log,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
            remote = None
            try:
                deadline = time.monotonic()+10
                while remote is None:
                    try:
                        remote = Remote(port)
                    except ConnectionRefusedError:
                        require(process.poll() is None,'QEMU exited: '+(root/'qemu.log').read_text())
                        require(time.monotonic()<deadline,'QEMU startup timeout')
                        time.sleep(0.05)
                for address in addresses:
                    data = struct.pack('<I',address ^ 0x12345678)
                    remote.write(address,data)
                    require(remote.read(address,4)==data,'RAM window mismatch')
                remote.command('s')
                regs = remote.regs()
                require(remote.get(regs,'r0')==42,'Synthetic ARM execution failed')
                require(remote.get(regs,'pc')==0x40100004,'Unexpected next PC')
                if machine == 'nikon-z72-lab':
                    for cached, bus in ((0x50560000, 0x30260000),
                                        (0x62059800, 0x36D59800)):
                        remote.write(cached, b'RAM!keep')
                        require(remote.read(bus, 8) == b'RAM!keep',
                                'Buffer bus alias does not share cached storage')
                        remote.set(r0=0x12345678, r1=bus, pc=0x40100008)
                        remote.command('s')
                        require(remote.read(cached, 8) ==
                                struct.pack('<I', 0x12345678) + b'keep',
                                'CPU buffer alias store or guard differs')
                    # Exercise a real RAM copy across internal chunk boundaries,
                    # including high addresses and untouched destination guards.
                    source, target = 0x40101000, 0xBAA01000
                    data = bytes((i * 37 + 11) & 255 for i in range(8193))
                    remote.write(source, data)
                    remote.write(target - 4, b'HEAD' + bytes(len(data)) + b'TAIL')

                    def sequencer_word(offset, value):
                        remote.set(r0=value, r1=0x04251010 + offset,
                                   pc=0x40100008)
                        remote.command('s')

                    for offset, value in ((0, len(data) - 1), (4, source),
                                          (8, target), (12, 0x30F00),
                                          (16, 0x30F00)):
                        sequencer_word(offset, value)
                    sequencer_word(24, 0x10000003)
                    require(remote.read(target, len(data)) == data and
                            remote.read(target - 4, 4) == b'HEAD' and
                            remote.read(target + len(data), 4) == b'TAIL' and
                            remote.read(0x04251030, 4) == struct.pack('<I', 8),
                            'Incrementing memory transfer or guards differ')
                    # Invalid spans, peripheral addresses and unsupported modes
                    # report errors without turning device reads into DMA data.
                    for offset, bad, good in ((0, 0x1000000, len(data) - 1),
                            (4, 0x14000000, source), (8, 0x2C090000, target),
                            (12, 0x30F01, 0x30F00),
                            (16, 0x30F01, 0x30F00)):
                        sequencer_word(32, 0)
                        sequencer_word(offset, bad)
                        sequencer_word(24, 0x10000003)
                        require(remote.read(0x04251030, 4) == struct.pack('<I', 1)
                                and remote.read(target, len(data)) == data,
                                'Unsupported transfer changed data or reported success')
                        sequencer_word(offset, good)
                    sequencer_word(32, 0)
                # Check every reset value first: the CPU read/write test
                # below writes side-effect words (the input enable word, for
                # example, latches event bits into its event bank), and
                # those latches are not reset-state failures.
                for address in CONFIG_WORDS:
                    require(remote.read(address, 4) == bytes(4), 'Configuration reset value mismatch')
                for address in CONFIG_WORDS:
                    if address in SPECIAL_WORDS:
                        continue
                    value = address ^ 0xA5A55A5A
                    remote.set(r0=value, r1=address, pc=0x40100008)
                    remote.command('s')
                    remote.command('s')
                    require(remote.get(remote.regs(), 'r2') == value,
                            'CPU configuration register read/write mismatch')
                # Completion must follow a supported command and clear when
                # acknowledged. Software cannot manufacture a completion bit.
                for control, status, command, maximum_phase in COMPLETION_PAIRS:
                    commands = tuple(command | (phase << 16) for phase in range(maximum_phase + 1))
                    remote.set(r0=0, r1=control, pc=0x40100008)
                    remote.command('s')
                    require(remote.read(status, 4) == bytes(4), 'Idle command completed')
                    remote.set(r0=1, r1=status, pc=0x40100008)
                    remote.command('s')
                    require(remote.read(status, 4) == bytes(4), 'Software created completion')
                    for value in commands:
                        remote.set(r0=value, r1=control, pc=0x40100008)
                        remote.command('s')
                        require(remote.read(status, 4) == struct.pack('<I', 1),
                                'Supported command did not complete')
                        remote.set(r0=2, r1=status, pc=0x40100008)
                        remote.command('s')
                        require(remote.read(status, 4) == struct.pack('<I', 1),
                                'Acknowledging another bit cleared completion')
                        remote.set(r0=1, r1=status, pc=0x40100008)
                        remote.command('s')
                        require(remote.read(status, 4) == bytes(4),
                                'Acknowledgement did not clear completion')
                for result in RESULT_WORDS:
                    remote.set(r0=42, r1=result, pc=0x40100008)
                    remote.command('s')
                    require(remote.read(result, 4) == bytes(4),
                            'Software changed the read-only command result')
                remote.set(r0=1, r1=0x20023118, pc=0x40100008)
                remote.command('s')
                require(remote.read(0x20023318, 4) == struct.pack('<I', 1),
                        'Reset control did not start with pending completion')
                require(remote.command('qRcmd,' + 'system_reset'.encode().hex()) == 'OK',
                        'Machine reset failed')
                for address in CONFIG_WORDS:
                    require(remote.read(address, 4) == bytes(4),
                            'Machine reset did not clear configuration state')
                # Unsupported byte stores and neighboring words must abort,
                # rather than behave like an unrestricted MMIO RAM bank.
                for address, pc in ((0x04264000, 0x40100010),
                                    (0x04264004, 0x40100008),
                                    (0x04281038, 0x40100008),
                                    (0x20023000, 0x40100010),
                                    (0x20023004, 0x40100008),
                                    (0x20023001, 0x40100008),
                                    (0x20030028, 0x40100008),
                                    (0x20016004, 0x40100008),
                                    (0x20016020, 0x40100010),
                                    (0x2007000C, 0x40100008),
                                    (0x20070031, 0x40100008),
                                    (0x2B20003C, 0x40100010),
                                    (0x2B20003D, 0x40100008),
                                    (0x2A900904, 0x40100010),
                                    (0x2A900920, 0x40100008),
                                    (0x2006801C, 0x40100008),
                                    (0x20068001, 0x40100008),
                                    (0x20068000, 0x40100010),
                                    (0x20061004, 0x40100010),
                                    (0x20061005, 0x40100008),
                                    (0x20061008, 0x40100008),
                                    (0x20061301, 0x40100008),
                                    (0x20061480, 0x40100008),
                                    (0x04282030, 0x40100008)):
                    remote.set(r1=address, pc=pc, cpsr=0xD3)
                    remote.command('s')
                    regs = remote.regs()
                    require(remote.get(regs, 'pc') == 0x10 and
                            remote.get(regs, 'cpsr') & 0x1F == 0x17,
                            'Unsupported configuration access did not abort')
                # Exercise the bounded fill using CPU-issued commands. Invalid
                # destinations must fail without touching RAM or other devices.
                destination = 0xC1000000 if 'slave' in machine else 0xB1900000
                def store(address, value):
                    remote.set(r0=value, r1=address, pc=0x40100008, cpsr=0xD3)
                    remote.command('s')
                for status in (0x2B200058, 0x2B20005C):
                    store(status, 0xffffffff)
                    require(remote.read(status, 4) == bytes(4),
                            'Software manufactured PCIe link or PHY status')
                for status in (0x2006807C, 0x20068084, 0x20068140, 0x20068144,
                               *range(0x20068210, 0x20068300, 0x20)):
                    store(status, 0xffffffff)
                    require(remote.read(status, 4) == bytes(4),
                            'Software manufactured input-path data or events')
                for set_address, clear_address in ((0x20068004, 0x20068000),
                                                   (0x20068010, 0x20068014)):
                    store(set_address, 0xf)
                    store(clear_address, 6)
                    require(remote.read(set_address, 4) == struct.pack('<I', 9) and
                            remote.read(clear_address, 4) == struct.pack('<I', 9),
                            'Input-path set/clear words did not preserve unrelated bits')
                remote.write(destination, b'keep')
                for viewport, base in ((0, 0x11110000), (1, 0x22220000),
                                       (0x80000000, 0x33330000),
                                       (0x8000000f, 0x44440000)):
                    store(0x2A900900, viewport)
                    require(remote.read(0x2A90090C, 4) == bytes(4),
                            'PCIe translation configuration leaked between regions')
                    store(0x2A90090C, base)
                    store(0x2A900908, 0x80000000)
                require(remote.read(destination, 4) == b'keep',
                        'PCIe configuration manufactured a memory transfer')
                for viewport, base in ((0, 0x11110000), (1, 0x22220000),
                                       (0x80000000, 0x33330000),
                                       (0x8000000f, 0x44440000)):
                    store(0x2A900900, viewport)
                    require(remote.read(0x2A90090C, 4) == struct.pack('<I', base),
                            'PCIe translation region readback differs')
                store(0x2A900900, 0xffffffff)
                require(remote.read(0x2A900900, 4) == struct.pack('<I', 0x8000000f),
                        'PCIe viewport retained unsupported selection bits')
                store(0x20100004, 0)
                require(remote.read(0x20100018, 4) == struct.pack('<I', 1),
                        'Transfer reset did not latch completion')
                require(int.from_bytes(remote.read(0x0400120c, 4), 'little') & 0x40,
                        'Transfer reset did not assert interrupt 102')
                store(0x20100018, 2)
                require(remote.read(0x20100018, 4) == struct.pack('<I', 1),
                        'Unrelated acknowledgement cleared transfer reset')
                store(0x20100018, 1)
                require(remote.read(0x20100018, 4) == bytes(4),
                        'Transfer reset acknowledgement failed')
                store(0x20100018, 1)
                require(remote.read(0x20100018, 4) == bytes(4),
                        'Software manufactured transfer completion')
                for offset, value in ((0, 0), (4, 0), (0x14, 1), (0x18, 0),
                                      (0x20, 0x4000), (0x24, 0x4000), (0x28, 2),
                                      (0x30, destination)):
                    store(0x20070000 + offset, value)
                remote.write(destination, b'\xA5' * 512)
                remote.write(destination + 0x7E00, b'\x5A' * 512 + b'Z72!')
                store(0x20070010, 1)
                require(remote.read(destination, 0x8000) == bytes(0x8000) and
                        remote.read(destination + 0x8000, 4) == b'Z72!', 'Bounded fill or guard mismatch')
                require(remote.read(0x20070008, 4) == struct.pack('<I', 1), 'Fill did not complete')
                store(0x20070008, 0x10)
                require(remote.read(0x20070008, 4) == struct.pack('<I', 1), 'Wrong-bit fill acknowledgement')
                store(0x20070008, 1)
                store(0x20070008, 0x11)
                require(remote.read(0x20070008, 4) == bytes(4), 'Software manufactured fill status')
                for offset, bad, good in ((0x30, 0x20016020, destination),
                    (0x30, destination + 1, destination), (0x28, 0, 2),
                    (0x28, 0x4000, 2), (0x20, 0x8000, 0x4000)):
                    remote.write(destination, b'Z72!')
                    store(0x20070000 + offset, bad)
                    store(0x20070010, 1)
                    require(remote.read(0x20070008, 4) == struct.pack('<I', 0x10) and
                            remote.read(destination, 4) == b'Z72!', 'Invalid fill changed RAM or status')
                    store(0x20070008, 0x10)
                    store(0x20070000 + offset, good)
                store(0x20070010, 1)
                store(0x20100004, 0)
                require(remote.command('qRcmd,' + 'system_reset'.encode().hex()) == 'OK',
                        'Memory status reset failed')
                require(all(remote.read(a, 4) == bytes(4) for a in CONFIG_WORDS),
                        'Reset retained memory initialization status or configuration')
                require(remote.read(0x20100018, 12) == bytes(12),
                        'Reset retained transfer completion status')
                require(remote.read(0x20068000, 8) == bytes(8) and
                        remote.read(0x20068010, 8) == bytes(8),
                        'Reset retained input-path set/clear state')
                require(remote.read(0x2A900900, 4) == bytes(4),
                        'Reset retained PCIe viewport selection')
                for viewport in (0, 1, 0x80000000, 0x8000000f):
                    store(0x2A900900, viewport)
                    require(remote.read(0x2A900904, 28) == bytes(28),
                            'Reset retained PCIe translation region configuration')
                print('PASS', machine, 'RAM, ARM execution, configuration registers, bounded fill and access faults')
            finally:
                if remote:
                    remote.sock.close()
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--qemu', required=True)
    args = p.parse_args()
    smoke(args.qemu, 'nikon-z72-lab',
          (0x04008000, 0x04008EFC, 0x04008FFC,
           0x10020000, 0x12497B78, 0xB1800000, 0xB202C00E, 0xB2BB1080,
           0xB2C00000, 0xB4000000, 0xB5EFFFFC,
           0xB5F00000, 0xB7CF0000, 0xB7CFC614,
           0x50300000, 0x50560000, 0x548FFFFC,
           0x5F900000, 0x62059800, 0x626FFFFC, 0x34600000, 0x373FFFFC))
    smoke(args.qemu, 'nikon-z72-slave-lab',
          (0x04008000, 0x04008EFC, 0x04008FFC,
           0x10020000, 0x1088CD3C, 0xC1000000, 0xC18F7FFC, 0xC1920B00,
           0xC1A00000, 0xC3000000, 0xC4FFFFFC,
           0xC5000000, 0xC5100000, 0xC5307240, 0xC5FC313C,
           0xC60F0000, 0xC60FC614))

if __name__ == '__main__':
    main()
