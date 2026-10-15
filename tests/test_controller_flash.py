# SPDX-License-Identifier: GPL-2.0-or-later
"""Check explicit resident flash data, aliases, reset and rejected input windows."""
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


def check(qemu, embedded=False):
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        firmware = bytearray(0x10020)
        struct.pack_into('<2I', firmware, 0, 0x20001000, 0x08000101)
        struct.pack_into('<H', firmware, 0x100, 0xe7fe)
        firmware[0x3ff0:0x4000] = bytes(range(16))
        firmware[0x10000:] = bytes(range(32))
        data = bytes((i * 29 + 7) & 255 for i in range(0xc000))
        image = root / 'synthetic.bin'
        initial = root / 'flash-data.bin'
        image.write_bytes(firmware)
        initial.write_bytes(data)
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        command = [qemu, '-M', 'nikon-z72-controller-lab,flash-data=' + str(initial),
                   '-kernel', str(image), '-display', 'none', '-serial', 'none',
                   '-monitor', 'none', '-nic', 'none', '-S', '-gdb', f'tcp:127.0.0.1:{port}']
        if embedded:
            command = [qemu, '-M', 'nikon-z72-dual-lab,controller-firmware=' + str(image) +
                       ',controller-flash-data=' + str(initial), '-smp', '4,maxcpus=5',
                       '-display', 'none', '-serial', 'none', '-monitor', 'none',
                       '-nic', 'none', '-S', '-gdb', f'tcp:127.0.0.1:{port}']
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
                            'Resident flash test could not connect')
                    time.sleep(.05)
            for reset in (False, True):
                if reset:
                    require(remote.command('qRcmd,' + 'system_reset'.encode().hex()) == 'OK',
                            'Resident flash reset failed')
                if embedded:
                    remote.select_thread(5)
                regs = remote.regs()
                require(remote.get(regs, 'pc') == 0x08000100 and
                        remote.get(regs, 'sp') == 0x20001000,
                        'Resident data changed the synthetic reset vectors')
                for alias in (0, 0x08000000):
                    for offset in range(0, len(data), 1024):
                        require(remote.read(alias + 0x4000 + offset, 1024) == data[offset:offset + 1024],
                                'Resident data or flash alias differs')
                    require(remote.read(alias + 0x3ff0, 16) == bytes(range(16)) and
                            remote.read(alias + 0x10000, 32) == bytes(range(32)),
                            'Resident data crossed its reserved window')
            require(image.read_bytes() == firmware and initial.read_bytes() == data,
                    'Resident loading modified an input file')
        finally:
            if remote is not None:
                remote.sock.close()
            if process is not None and process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
        command = command[:-2]
        for contents, image_data, message in (
            (data[:-1], firmware, 'exactly 49152 bytes'),
            (data + bytes(1), firmware, 'exactly 49152 bytes'),
            (data, firmware[:0x200], '64 KiB..1 MiB'),
            (data, firmware[:0x4000] + b'\x01' + firmware[0x4001:], 'empty firmware data window')):
            initial.write_bytes(contents)
            image.write_bytes(image_data)
            completed = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                timeout=10, creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
            require(completed.returncode != 0 and message.encode() in completed.stderr,
                    'Invalid resident flash input was not rejected')
        print('PASS ' + ('embedded' if embedded else 'isolated') +
              ' controller flash: bounded data, aliases, reset, unchanged inputs and rejection')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    args = parser.parse_args()
    check(args.qemu)
    check(args.qemu, embedded=True)
