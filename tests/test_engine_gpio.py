# SPDX-License-Identifier: GPL-2.0-or-later
"""Check recovered engine GPIO inputs and interrupt routing without firmware."""
import argparse
import json
import socket
import subprocess
import time


def check(qemu):
    for machine in ('nikon-z72-lab', 'nikon-z72-slave-lab'):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        process = subprocess.Popen([qemu, '-M', machine, '-accel', 'qtest',
            '-display', 'none', '-serial', 'none', '-qmp', 'stdio',
            '-qtest', f'tcp:127.0.0.1:{port},server=on,wait=off', '-qtest-log', '/dev/null'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        wire = stream = None
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
            names = [item['name'] for item in devices
                     if item['type'] == 'child<nikon-z72-boot-config>']
            assert len(names) == 1, names
            path = '/machine/unattached/' + names[0]
            gic = next(item['name'] for item in devices if item['type'] == 'child<arm_gic>')
            irq_levels = {}

            def command(text):
                stream.write(text.encode() + b'\n')
                stream.flush()
                reply = stream.readline().decode().strip().split()
                while reply and reply[0] == 'IRQ':
                    irq_levels[int(reply[2])] = reply[1] == 'raise'
                    reply = stream.readline().decode().strip().split()
                assert reply and reply[0] == 'OK', reply
                return int(reply[1], 0) if len(reply) > 1 else None

            def read(address):
                return command(f'readl {address:#x}')

            def write(address, value):
                command(f'writel {address:#x} {value:#x}')

            def pin(line, level):
                command(f'set_irq_in {path} gpio-input {line} {level}')

            command('irq_intercept_in /machine/unattached/' + gic)
            write(0x0426f008, 0xffff)
            assert read(0x0426f008) == 0
            for line in range(16):
                bit = 1 << line
                irq = 65 + line - 32
                address = 0x04282014 if line < 9 else 0x04282018
                physical_bit = 1 << (line + 7 if line < 9 else line - 9)
                write(0x0426f000, 0xffff)
                write(0x0426f014, 0xffff)
                pin(line, 0)
                pin(line, 1)
                assert read(address) & physical_bit
                assert read(0x0426f008) == bit
                assert not irq_levels.get(irq, False)
                write(0x0426f000, 0xffff ^ bit)
                assert irq_levels.get(irq, False)
                write(0x0426f008, 0)
                assert read(0x0426f008) == bit
                write(0x0426f010, bit)
                assert read(0x0426f008) == 0
                assert not irq_levels.get(irq, False)
                pin(line, 1)
                pin(line, 0)
                assert read(0x0426f008) == 0
                assert not read(address) & physical_bit
                write(0x0426f014, 0xffff ^ bit)
                pin(line, 1)
                assert read(0x0426f008) == 0
                pin(line, 0)
                assert read(0x0426f008) == bit
                write(0x0426f010, bit)
            # Reset clears pending causes while an external held pin stays high.
            write(0x0426f014, 1)
            pin(0, 1)
            assert read(0x0426f008) == 1
            monitor('system_reset')
            assert read(0x0426f008) == 0
            assert read(0x04282014) & 0x80
            pin(0, 1)
            assert read(0x0426f008) == 0
        finally:
            if stream is not None:
                stream.close()
            if wire is not None:
                wire.close()
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=10)
            process.stdin.close()
            process.stdout.close()
            process.stderr.close()
    print('PASS engine GPIO: 16 pins, both edges, mask retention, IRQ mapping, acknowledgement and reset, both roles')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    check(parser.parse_args().qemu)
