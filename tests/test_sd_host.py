# SPDX-License-Identifier: GPL-2.0-or-later
"""Read a synthetic sector through the optional SDHCI window, without firmware."""
import argparse
import json
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import time


def run(qemu):
    with tempfile.TemporaryDirectory(prefix='z72-sd-') as folder:
        image = Path(folder) / 'card.raw'
        marker = bytes((index * 17 + 3) & 255 for index in range(512))
        with image.open('wb') as output:
            output.write(marker)
            output.truncate(1024 * 1024)
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        process = subprocess.Popen([
            qemu, '-M', 'nikon-z72-lab', '-accel', 'qtest',
            '-display', 'none', '-serial', 'none', '-monitor', 'none',
            '-qmp', 'stdio',
            '-global', 'nikon-z72-boot-config.sd-host=on',
            '-drive', f'if=none,id=card,file={image},format=raw,snapshot=on',
            '-device', 'sd-card,drive=card',
            '-qtest', f'tcp:127.0.0.1:{port},server=on,wait=off',
            '-qtest-log', '/dev/null'], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        wire = stream = None
        passed = False
        try:
            deadline = time.monotonic() + 10
            while wire is None:
                try:
                    wire = socket.create_connection(('127.0.0.1', port), timeout=2)
                except OSError:
                    if process.poll() is not None:
                        raise RuntimeError(process.stderr.read().decode())
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(.05)
            stream = wire.makefile('rwb')
            assert 'QMP' in json.loads(process.stdout.readline())

            def monitor(name, arguments=None):
                message = dict(execute=name)
                if arguments is not None:
                    message['arguments'] = arguments
                process.stdin.write(json.dumps(message).encode() + b'\n')
                process.stdin.flush()
                while True:
                    reply = json.loads(process.stdout.readline())
                    if 'event' not in reply:
                        assert 'return' in reply, reply
                        return reply['return']

            monitor('qmp_capabilities')
            devices = monitor('qom-list', dict(path='/machine/unattached'))
            gic = next(item['name'] for item in devices if item['type'] == 'child<arm_gic>')
            irq_levels = {}

            def command(text):
                stream.write(text.encode() + b'\n')
                stream.flush()
                reply = stream.readline().decode().split()
                while reply and reply[0] == 'IRQ':
                    irq_levels[int(reply[2])] = reply[1] == 'raise'
                    reply = stream.readline().decode().split()
                assert reply and reply[0] == 'OK', reply
                return int(reply[1], 0) if len(reply) > 1 else None

            command('irq_intercept_in /machine/unattached/' + gic)

            def read(offset, width='l'):
                return command(f'read{width} {0x2A810000 + offset:#x}')

            def write(offset, value, width='l'):
                command(f'write{width} {0x2A810000 + offset:#x} {value:#x}')

            def sd_command(index, argument=0, flags=0, block=False):
                write(4, 512 if block else 0, 'w')
                write(6, 1 if block else 0, 'w')
                write(8, argument)
                write(0xC, 0x12 if block else 0, 'w')
                write(0xE, index << 8 | flags, 'w')

            assert command('readl 0x2b200058') & 0x3F0000 == 0x110000
            assert command('readl 0x2a900098') & 15 == 2
            assert command('readl 0x2b000010') & 0x400
            command('writel 0x2b000004 4')
            assert command('readl 0x2b000010') & 0x400 == 0
            command('writel 0x2b000004 0')
            assert command('readl 0x2b000010') & 0x400
            write(0x2F, 1, 'b')
            assert read(0x2F, 'b') == 0
            assert command('readl 0x2a800064') & 4 == 0
            command('writel 0x2a800064 4')
            assert command('readl 0x2a800064') & 4 == 0
            write(0x29, 0xF, 'b')
            write(0x2C, 7, 'w')
            assert command('readl 0x2a800064') & 4
            write(0x34, 0xFFFFFFFF)
            sd_command(55)
            sd_command(41, 0x41200000)
            sd_command(2)
            sd_command(3, flags=3)
            rca = read(0x10) & 0xFFFF0000
            assert rca, 'The card did not assign an address'
            sd_command(7, rca)
            write(0x30, 0xFFFFFFFF)
            command('writel 0x2b200024 0x10000000')
            assert command('readl 0x2b200024') & (1 << 28) == 0
            write(0x38, 1)
            sd_command(17, flags=0x20, block=True)
            assert read(0x24) & 0x800, 'The host has no readable block'
            assert command('readl 0x2b200024') & (1 << 28)
            assert irq_levels.get(243 - 32), 'IRQ 243 did not assert at the GIC input'
            command('writel 0x2b200024 0x10000000')
            assert command('readl 0x2b200024') & (1 << 28), 'Acknowledgement hid an active source'
            write(0x30, 1)
            assert command('readl 0x2b200024') & (1 << 28) == 0
            assert not irq_levels[243 - 32], 'IRQ 243 remained high after source acknowledgement'
            sector = b''.join(struct.pack('<I', read(0x20)) for _ in range(128))
            assert sector == marker, 'SDHCI sector differs from the backing image'
            write(0x2F, 1, 'b')
            assert read(0x2F, 'b') == 0
            assert command('readl 0x2a800064') & 4 == 0
            assert read(0x24) & 0x800 == 0, 'Reset retained unread transfer state'
            passed = True
        finally:
            if stream is not None:
                stream.close()
            if wire is not None:
                wire.close()
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            if not passed:
                print('QEMU exit:', process.returncode,
                      process.stderr.read().decode(), flush=True)
            process.stderr.close()
            process.stdin.close()
            process.stdout.close()
    print('PASS SD host clock gate, reset, card commands, IRQ 243 and sector read')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    run(parser.parse_args().qemu)
