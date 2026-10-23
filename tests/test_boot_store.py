# SPDX-License-Identifier: GPL-2.0-or-later
"""Check the engine boot store reprogram-and-reset contract with synthetic code.

Two tiny ARM images write distinguishable markers into state RAM and spin.
The board starts on the first image, the store is reprogrammed with the
second through its image property, and a whole-machine reset must make the
core restart at the image entry so the second marker lands — the same
image-property reset path used by the experimental console, without any
firmware. A decoded RAM container must not replace that image unless the
laboratory window fixture is explicitly enabled.
"""
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
from analyze.decode_z72 import crc, require
from analyze.qemu_display import Remote

MARKER_ADDRESS = 0xB2000100
WINDOW = 0x52000000


def image(marker):
    """LDR r0,=marker; LDR r1,=address; STR r0,[r1]; B . with literals."""
    return struct.pack('<6I',
                       0xE59F0008, 0xE59F1008, 0xE5810000, 0xEAFFFFFE,
                       marker, MARKER_ADDRESS)


def decoded_window(marker):
    """Synthetic CRC-valid container with no authenticated header digest."""
    member = image(marker)
    member += struct.pack('>H', crc(member))
    body = b' ' * 0x20 + struct.pack('>4I', 1, 0x50, 0, 0)
    body += struct.pack('>16s4I', b'eg1840_mas_test', 0x50, len(member), 0, 0) + member
    body += struct.pack('>H', crc(body)) + bytes(14)
    return bytes(0x20) + body


class Monitor:
    def __init__(self, port):
        self.sock = socket.create_connection(('127.0.0.1', port), timeout=5)
        self.file = self.sock.makefile('rwb')
        self.read()

    def read(self):
        while True:
            line = self.file.readline()
            if not line:
                raise ConnectionError('Machine monitor disconnected')
            message = __import__('json').loads(line)
            if 'event' not in message:
                return message

    def command(self, name, arguments=None):
        request = dict(execute=name)
        if arguments is not None:
            request['arguments'] = arguments
        self.file.write((__import__('json').dumps(request) + '\n').encode())
        self.file.flush()
        reply = self.read()
        if 'error' in reply:
            raise RuntimeError(reply['error'].get('desc', 'Machine monitor error'))
        return reply['return']


def run(qemu):
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        first, second = root / 'first.bin', root / 'second.bin'
        first.write_bytes(image(0x11223344))
        second.write_bytes(image(0x55667788))
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            gdb_port = listener.getsockname()[1]
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            qmp_port = listener.getsockname()[1]
        machine = ('nikon-z72-dual-lab,master-boot-image=' + str(first) +
                   ',slave-boot-image=' + str(first))
        with (root / 'qemu.log').open('wb') as log:
            process = subprocess.Popen([qemu, '-M', machine, '-smp', '4',
                '-display', 'none', '-serial', 'none', '-monitor', 'none',
                '-nic', 'none', '-S', '-gdb', f'tcp:127.0.0.1:{gdb_port}',
                '-qmp', f'tcp:127.0.0.1:{qmp_port},server=on,wait=off'],
                stdout=subprocess.DEVNULL, stderr=log,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
            try:
                remote = None
                deadline = time.monotonic() + 30
                while remote is None:
                    try:
                        remote = Remote(gdb_port)
                    except (ConnectionRefusedError, OSError):
                        require(process.poll() is None,
                                'Machine exited during startup: ' +
                                (root / 'qemu.log').read_text(errors='replace'))
                        require(time.monotonic() < deadline, 'Machine startup timed out')
                        time.sleep(0.05)
                monitor = None
                while monitor is None:
                    try:
                        monitor = Monitor(qmp_port)
                    except (ConnectionRefusedError, OSError):
                        require(time.monotonic() < deadline, 'Monitor startup timed out')
                        time.sleep(0.05)
                require(monitor.command('qmp_capabilities') == {}, 'Capabilities failed')

                def marker():
                    return struct.unpack('<I', remote.read(MARKER_ADDRESS, 4))[0]

                def program_counter():
                    registers = remote.regs()
                    return remote.get(registers, 'pc')

                def run_and_halt():
                    remote.sock.sendall(b'$vCont;c#' + f'{sum(b"vCont;c") & 255:02x}'.encode())
                    time.sleep(0.3)
                    remote.sock.sendall(b'\x03')
                    remote.receive()
                    # Read through a master-engine core; the state window
                    # belongs to the master view.
                    remote.command('Hg1')

                run_and_halt()
                require(marker() == 0x11223344, 'The stored first image did not run')

                monitor.command('stop')
                monitor.command('qom-set', {'path': '/machine/master-boot-store',
                                           'property': 'image', 'value': str(second)})
                monitor.command('system_reset')
                program = None
                deadline = time.monotonic() + 10
                while program != 0x10020000 and time.monotonic() < deadline:
                    time.sleep(0.05)
                    program = program_counter()
                require(program == 0x10020000, 'The core did not restart at the entry')
                run_and_halt()
                require(marker() == 0x55667788,
                        'The reset did not boot the reprogrammed image')

                candidate = decoded_window(0x99AABBCC)
                remote.write(WINDOW, candidate)
                monitor.command('system_reset')
                run_and_halt()
                require(marker() == 0x55667788,
                        'A decoded RAM fixture replaced the stored image without opt-in')
                require(monitor.command('qom-get', {'path': '/machine/master-boot-store',
                        'property': 'harvest-update'}) is False, 'Window harvesting defaults to enabled')

                monitor.command('qom-set', {'path': '/machine/master-boot-store',
                        'property': 'harvest-update', 'value': True})
                monitor.command('system_reset')
                run_and_halt()
                require(marker() == 0x99AABBCC, 'Explicit decoded-window fixture did not boot')

                damaged = bytearray(candidate)
                damaged[0x20 + 0x50 + 16] ^= 1
                remote.write(WINDOW, damaged)
                monitor.command('system_reset')
                run_and_halt()
                require(marker() == 0x55667788, 'Damaged window replaced the stored image')

                remote.write(WINDOW, candidate)
                monitor.command('qom-set', {'path': '/machine/master-boot-store',
                        'property': 'harvest-update', 'value': False})
                monitor.command('system_reset')
                run_and_halt()
                require(marker() == 0x55667788, 'Disabled fixture still replaced the stored image')
                remote.sock.close()
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
    print('PASS stored image reset, explicit decoded-window fixture and damaged-window rejection')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    arguments = parser.parse_args()
    run(arguments.qemu)


if __name__ == '__main__':
    main()
