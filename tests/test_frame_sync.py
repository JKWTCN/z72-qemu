# SPDX-License-Identifier: GPL-2.0-or-later
"""Check the optional periodic synchronization source without firmware."""
import argparse
import json
import socket
import subprocess
import time


def check(qemu):
    for role, enabled, sampling, automatic in (
            ('master', False, False, True), ('master', True, False, True),
            ('master', True, True, True), ('master', True, True, False),
            ('slave', True, True, True)):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        machine = 'nikon-z72-lab' if role == 'master' else 'nikon-z72-slave-lab'
        process = subprocess.Popen([qemu, '-M', machine, '-accel', 'qtest',
            '-display', 'none', '-serial', 'none',
            '-qmp', 'stdio',
            '-global', f'nikon-z72-boot-config.frame-sync={"on" if enabled else "off"}',
            '-global', f'nikon-z72-boot-config.sensor-sample={"on" if sampling else "off"}',
            '-global', f'nikon-z72-boot-config.auto-complete={"on" if automatic else "off"}',
            '-global', 'nikon-z72-boot-config.sample-lines=0x1234',
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
            clock_path = '/machine/unattached/' + names[0]

            def command(text):
                stream.write(text.encode() + b'\n')
                stream.flush()
                reply = stream.readline().decode().strip().split()
                assert reply and reply[0] == 'OK', reply
                return int(reply[1], 0) if len(reply) > 1 else None

            def read(address):
                return command(f'readl {address:#x}')

            def write(address, value):
                command(f'writel {address:#x} {value:#x}')

            active = enabled and role == 'master'
            read(0x20068060)
            assert monitor('qom-get', dict(path=clock_path, property='sample-lines')) == 0x1234
            assert monitor('qom-get', dict(path=clock_path, property='input-last-read')) == 0x20068060
            assert monitor('qom-get', dict(path=clock_path, property='frame-count')) == 1
            command('clock_step 100000000')
            assert read(0x20060044) == 0
            command(f'set_irq_in {clock_path} frame-sync-enable 0 1')
            command('clock_step 33333332')
            assert read(0x20060044) == 0
            command('clock_step 1')
            assert read(0x20060044) == (0x10 if active else 0)
            assert read(0x20060038) == 0
            for index in range(5):
                assert read(0x20061300 + index * 4) == (0x1234 if active and sampling else 0)
            if active:
                write(0x20060040, 0x10)
                write(0x20060044, 1)
                assert read(0x20060044) == 0x10
                write(0x20060044, 0x10)
                assert read(0x20060044) == 0
                command('clock_step 33333333')
                assert read(0x20060044) == 0x10
                assert monitor('qom-get', dict(path=clock_path, property='frame-sync-count')) == 2
                command(f'set_irq_in {clock_path} frame-sync-enable 0 0')
                write(0x20060044, 0x10)
                command('clock_step 100000000')
                assert read(0x20060044) == 0
                command(f'set_irq_in {clock_path} frame-sync-enable 0 1')
                command('clock_step 33333333')
                assert read(0x20060044) == 0x10
                monitor('system_reset')
                assert read(0x20060044) == 0
                assert monitor('qom-get', dict(path=clock_path, property='frame-sync-count')) == 0
                command('clock_step 100000000')
                assert read(0x20060044) == 0
            for request, completion in ((0x107, 1 << 10), (0x101, 1 << 18)):
                write(0x200632e0, request | 8)
                write(0x200632e4, 0)
                assert read(0x20060044) == 0
                write(0x200632e4, 1)
                completes = sampling and automatic and role == 'master'
                assert read(0x20060044) == (completion if completes else 0)
                assert read(0x200632e0) == (8 if completes else request | 8)
                write(0x20060044, completion)
                assert read(0x20060044) == 0
                write(0x200632e0, 8)
                write(0x200632e4, 1)
                assert read(0x20060044) == 0
                assert read(0x200632e0) == 8
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
    print('PASS frame synchronization: control batches, acknowledgement, source gating and role isolation')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    check(parser.parse_args().qemu)
