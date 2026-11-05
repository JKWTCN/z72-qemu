# SPDX-License-Identifier: GPL-2.0-or-later
"""Check selected RAW configuration commits and isolation from staged writes."""
import argparse
import json
import socket
import subprocess
import time


def check(qemu):
    for role in ('master', 'slave'):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        machine = 'nikon-z72-lab' if role == 'master' else 'nikon-z72-slave-lab'
        process = subprocess.Popen([qemu, '-M', machine, '-accel', 'qtest',
            '-display', 'none', '-serial', 'none', '-qmp', 'stdio',
            '-global', 'nikon-z72-boot-config.frame-generate=on',
            '-global', 'nikon-z72-boot-config.frame-notify=on',
            '-global', 'nikon-z72-boot-config.sensor-sample=on',
            '-global', 'nikon-z72-boot-config.frame-sync=on',
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

            def command(value):
                stream.write(value.encode() + b'\n')
                stream.flush()
                reply = stream.readline().decode().strip().split()
                assert reply and reply[0] == 'OK', reply
                return reply[1] if len(reply) > 1 else None

            def write(address, value):
                command(f'writel {address:#x} {value:#x}')

            def read(address):
                return int(command(f'readl {address:#x}'), 0)

            monitor('qmp_capabilities')
            path = '/machine/unattached/' + next(item['name'] for item in
                monitor('qom-list', dict(path='/machine/unattached'))
                if item['type'] == 'child<nikon-z72-boot-config>')

            def prop(name):
                return monitor('qom-get', dict(path=path, property=name))

            def tick():
                command('clock_step 33333333')

            def stage(target):
                for address, value in ((0x20069514, 6), (0x20069518, 130 << 16),
                        (0x2006951c, 2 << 16), (0x20069a08, 208)):
                    write(address, value)
                for slot in range(4):
                    write(0x20069a50 + slot * 4, target)

            first = 0xb0101000 if role == 'master' else 0xc1019000
            second = first + 0x1000
            for target in (first, second):
                command(f'memset {target:#x} 0x1a0 0xa5')
                write(target - 4, 0x12345678)
                write(target + 416, 0x87654321)
            stage(first)
            write(0x20068004, 0x200)
            write(0x20068010, 0x200)
            write(0x20068008, 0x200)
            command(f'set_irq_in {path} frame-sync-enable 0 1')
            tick()
            assert prop('input-dma-count') == 0, 'Uncommitted configuration generated RAW'
            for mask in (0, 1, 0x100):
                write(0x20068100, mask)
                tick()
                assert prop('input-dma-count') == 0, 'Unrelated commit admitted preview'
            assert prop('preview-input-config-commits') == 0
            write(0x20068100, 0x80)
            assert prop('input-dma-count') == 0 and read(0x20068210) == 0
            tick()
            active = int(role == 'master')
            assert prop('input-dma-count') == active
            assert prop('preview-input-config-commits') == 1
            stage(second)
            write(0x20069514, 7)
            assert read(0x20069a50) == second and read(0x20069514) == 7
            for mask in (None, 1, 0x100):
                if mask is not None:
                    write(0x20068104, mask)
                tick()
            assert prop('input-dma-count') == 4 * active, 'Staging or unrelated commit replaced preview'
            assert read(second) == 0xa5a5a5a5, 'Uncommitted destination received pixels'
            write(0x20068210, 0xffffffff)
            previous = command(f'read {first:#x} 0x1a0')
            write(0x20068104, 0x80)
            tick()
            assert prop('input-dma-count') == 4 * active and read(0x20068210) == 0
            assert command(f'read {first:#x} 0x1a0') == previous
            write(0x20069514, 6)
            tick()
            assert prop('input-dma-count') == 4 * active, 'Uncommitted repair replaced an invalid commit'
            write(0x20068100, 0x80)
            tick()
            assert prop('input-dma-count') == 5 * active
            assert read(second) != 0xa5a5a5a5 if active else read(second) == 0xa5a5a5a5
            write(0x20069a08, 192)
            write(0x20068104, 0x180)
            assert prop('preview-input-config-commits') == 4 and prop('primary-input-config-commits') == 3
            tick()
            assert prop('input-dma-count') == 5 * active
            write(0x20069a08, 208)
            write(0x20068000, 0x200)
            write(0x20068004, 0x200)
            write(0x20068008, 0x200)
            tick()
            assert prop('input-dma-count') == 5 * active, 'Unit reset promoted staged repair'
            for target in (first, second):
                assert read(target - 4) == 0x12345678 and read(target + 416) == 0x87654321
            monitor('system_reset')
            assert prop('preview-input-config-commits') == prop('primary-input-config-commits') == 0
            stage(first)
            write(0x20068004, 0x200)
            write(0x20068010, 0x200)
            write(0x20068008, 0x200)
            command(f'set_irq_in {path} frame-sync-enable 0 1')
            tick()
            assert prop('input-dma-count') == 0, 'Machine reset retained committed input'
            write(0x20068104, 0x80)
            tick()
            assert prop('input-dma-count') == active
            monitor('quit')
            process.wait(timeout=5)
        finally:
            if stream is not None:
                stream.close()
            if wire is not None:
                wire.close()
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
            for pipe in (process.stdin, process.stdout, process.stderr):
                pipe.close()
    print('PASS selected RAW commits, staging isolation, invalid snapshots and reset')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    check(parser.parse_args().qemu)
