# SPDX-License-Identifier: GPL-2.0-or-later
"""Check capture run admission and selective reset/disable cancellation."""
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
            '-global', 'nikon-z72-boot-config.input-stop-complete=on',
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

            def read(address):
                return int(command(f'readl {address:#x}'), 0)

            def write(address, value):
                command(f'writel {address:#x} {value:#x}')

            monitor('qmp_capabilities')
            path = '/machine/unattached/' + next(item['name'] for item in
                monitor('qom-list', dict(path='/machine/unattached'))
                if item['type'] == 'child<nikon-z72-boot-config>')

            def prop(name):
                return monitor('qom-get', dict(path=path, property=name))

            def tick():
                command('clock_step 33333333')

            units = (1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80, 0x200, 0x400, 0x800)
            for unit in units:
                write(0x20068008, unit)
                assert prop('input-running') == 0, 'Reset/disabled input accepted run'
                write(0x20068010, unit)
                write(0x20068008, unit)
                assert prop('input-running') == 0, 'Input ran before reset release'
                write(0x20068004, unit)
                assert prop('input-running') == 0, 'Reset release replayed a blocked run'
                write(0x20068008, unit)
                assert prop('input-running') == unit
                write(0x20068000, unit)
                assert prop('input-running') == 0, 'Reset retained a running input'
                write(0x20068004, unit)
                write(0x20068014, unit)
                write(0x20068008, unit)
                assert prop('input-running') == 0, 'Disabled input accepted run'
                write(0x20068010, unit)
                assert prop('input-running') == 0, 'Enable replayed a blocked run'
                write(0x20068008, unit)
                write(0x20068014, unit)
                assert prop('input-running') == 0, 'Disable retained a running input'
                write(0x2006800c, unit)
                assert all(read(0x20068210 + bank * 32) == 0 for bank in range(8)), \
                    'Cancellation fabricated stop or data completion'

            target = 0xb0101000 if role == 'master' else 0xc1019000
            for address, value in ((0x20069514, 6), (0x20069518, 130 << 16),
                    (0x2006951c, 2 << 16), (0x20069a08, 208),
                    (target - 4, 0x12345678), (target + 416, 0x87654321)):
                write(address, value)
            for slot in range(4):
                write(0x20069a50 + slot * 4, target)
            command(f'set_irq_in {path} frame-sync-enable 0 1')
            write(0x20068010, 0x200)
            write(0x20068008, 0x200)
            tick()
            expected = int(role == 'master')
            assert prop('input-dma-count') == expected
            for cancel, restore in ((0x20068014, 0x20068010), (0x20068000, 0x20068004)):
                pending = read(0x20068210)
                write(cancel, 0x400)
                assert prop('input-running') == 0x200, 'Sibling cancellation stopped preview'
                tick()
                expected += int(role == 'master')
                assert prop('input-dma-count') == expected
                original = command(f'read {target:#x} 0x1a0')
                write(cancel, 0x200)
                assert prop('input-running') == 0
                tick()
                assert prop('input-dma-count') == expected
                assert read(0x20068210) == pending, 'Cancellation cleared latched data'
                assert command(f'read {target:#x} 0x1a0') == original, 'Cancelled DMA changed RAM'
                write(0x2006800c, 0x200)
                assert read(0x20068230) == 0, 'Cancelled input generated a later stop ACK'
                write(restore, 0x200)
                tick()
                assert prop('input-dma-count') == expected, 'Restore implicitly resumed DMA'
                write(0x20068008, 0x200)
                tick()
                expected += int(role == 'master')
                assert prop('input-dma-count') == expected
            assert read(target - 4) == 0x12345678 and read(target + 416) == 0x87654321
            write(0x20068000, 0x200)
            write(0x20068004, 0x400)
            write(0x20068010, 0x600)
            write(0x20068008, 0x600)
            assert prop('input-running') == 0x400, 'Combined run ignored per-unit admission'
            write(0x20068004, 0x200)
            assert prop('input-running') == 0x400
            write(0x20068008, 0x200)
            assert prop('input-running') == 0x600
            monitor('system_reset')
            assert prop('input-running') == prop('input-dma-count') == 0
            write(0x20068008, 0x600)
            assert prop('input-running') == 0, 'Machine reset retained admission gates'
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
    print('PASS input reset/enable admission, selective cancellation, DMA preservation and fresh restart')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    check(parser.parse_args().qemu)
