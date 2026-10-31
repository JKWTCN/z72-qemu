# SPDX-License-Identifier: GPL-2.0-or-later
"""Check body contacts reach independent engine GPIOs only with the board link."""
import argparse
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.web_console import QmpClient, free_port


def check(qemu):
    with tempfile.TemporaryDirectory() as directory:
        firmware = Path(directory) / 'controller.bin'
        firmware.write_bytes(struct.pack('<2I', 0x20001000, 0x08000009) + b'\xfe\xe7')
        for linked in (False, True):
            port, monitor = free_port(), free_port()
            process = subprocess.Popen([qemu, '-M',
                f'nikon-z72-dual-lab,controller-firmware={firmware},controller-link={"on" if linked else "off"}',
                '-accel', 'qtest', '-display', 'none', '-serial', 'none', '-nic', 'none',
                '-qmp', f'tcp:127.0.0.1:{monitor},server=on,wait=off',
                '-qtest', f'tcp:127.0.0.1:{port},server=on,wait=off', '-qtest-log', '/dev/null'],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            wire = stream = qmp = None
            try:
                deadline = time.monotonic() + 10
                while wire is None:
                    try:
                        wire = socket.create_connection(('127.0.0.1', port), timeout=2)
                    except ConnectionRefusedError:
                        assert process.poll() is None, process.stderr.read().decode()
                        assert time.monotonic() < deadline, 'Contact test startup timed out'
                        time.sleep(.05)
                stream = wire.makefile('rwb')
                qmp = QmpClient(monitor)

                def command(text):
                    stream.write(text.encode() + b'\n')
                    stream.flush()
                    reply = stream.readline().decode().split()
                    assert reply and reply[0] == 'OK', reply
                    return int(reply[1], 0) if len(reply) > 1 else None

                def read(address):
                    return command(f'readl {address:#x}')

                def write(address, value):
                    command(f'writel {address:#x} {value:#x}')

                def contact(pin, level):
                    command(f'set_irq_in /machine/controller/keys-gpio unnamed-gpio-in {pin} {level}')

                assert read(0x04282014) & 0x1800 == 0, 'Undriven contacts closed'
                for pin, line in ((1, 4), (13, 5)):
                    bit, physical = 1 << line, 1 << (line + 7)
                    contact(pin, 1)
                    write(0x0426f010, 0xffff)
                    write(0x0426f000, 0xffff)
                    write(0x0426f014, bit)
                    contact(pin, 0)
                    assert bool(read(0x04282014) & physical) == linked
                    assert read(0x0426f008) == (bit if linked else 0), 'Closure edge missing'
                    write(0x0426f010, bit)
                    contact(pin, 0)
                    assert read(0x0426f008) == 0, 'Held contact retriggered'
                    write(0x0426f014, 0)
                    contact(pin, 1)
                    assert not read(0x04282014) & physical
                    assert read(0x0426f008) == (bit if linked else 0), 'Release edge missing'
                    write(0x0426f010, bit)
                contact(1, 0)
                contact(13, 0)
                assert read(0x04282014) & 0x1800 == (0x1800 if linked else 0)
                qmp.command('system_reset')
                assert read(0x0426f008) == 0, 'Reset fabricated a contact interrupt'
                assert read(0x04282014) & 0x1800 == (0x1800 if linked else 0), 'Reset lost held contacts'
                contact(1, 1)
                assert read(0x04282014) & 0x1800 == (0x1000 if linked else 0), 'Half release changed full'
                contact(13, 1)
                assert read(0x04282014) & 0x1800 == 0
            finally:
                if qmp is not None:
                    qmp.close()
                if stream is not None:
                    stream.close()
                if wire is not None:
                    wire.close()
                if process.poll() is None:
                    process.terminate()
                process.wait(timeout=10)
                process.stderr.close()
    print('PASS body contacts: link gating, engine levels, both edges, held inputs and reset')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    check(parser.parse_args().qemu)
