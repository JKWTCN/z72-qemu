# SPDX-License-Identifier: GPL-2.0-or-later
"""Check bounded RAW12 input DMA, frame rotation and stop requests."""
import argparse
import json
import socket
import subprocess
import time


def check(qemu):
    for role, enabled, sampling in (
            ('master', True, True), ('master', False, True),
            ('master', True, False), ('slave', True, True)):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        machine = 'nikon-z72-lab' if role == 'master' else 'nikon-z72-slave-lab'
        process = subprocess.Popen([qemu, '-M', machine, '-accel', 'qtest',
            '-display', 'none', '-serial', 'none', '-qmp', 'stdio',
            '-global', f'nikon-z72-boot-config.frame-generate={"on" if enabled else "off"}',
            '-global', f'nikon-z72-boot-config.sensor-sample={"on" if sampling else "off"}',
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

            monitor('qmp_capabilities')
            active = role == 'master' and enabled and sampling
            devices = monitor('qom-list', dict(path='/machine/unattached'))
            names = [item['name'] for item in devices
                     if item['type'] == 'child<nikon-z72-boot-config>']
            assert len(names) == 1
            path = '/machine/unattached/' + names[0]

            def count():
                return monitor('qom-get', dict(path=path, property='input-dma-count'))

            def tick():
                command('clock_step 33333333')

            def start():
                write(0x20068008, 0x200)

            def planes(targets):
                for index, target in enumerate(targets):
                    write(0x20069a50 + index * 4, target)

            targets = [0xb0101000 + index * 0x1000 for index in range(4)] if role == 'master' else [0xc1019000 + index * 0x1000 for index in range(4)]
            write(0x20069514, 6)
            write(0x20069518, 130 << 16)
            write(0x2006951c, 2 << 16)
            write(0x20069a08, 208)
            planes(targets)
            for target in targets:
                write(target - 4, 0x12345678)
                write(target + 416, 0x87654321)
            command(f'set_irq_in {path} frame-sync-enable 0 1')
            tick()
            assert count() == 0, 'DMA ran before the input enable request'
            start()
            tick()
            assert count() == int(active)
            if active:
                assert read(targets[0]) == 0
                assert read(targets[0] + 96) == 0xffffffff
                assert read(targets[0] + 192) == 0
                assert read(targets[0] + 204) == 0
                assert read(targets[0] + 208 + 96) == 0xffffffff
                tick()
                assert count() == 2 and read(targets[1]) == 0xffffffff
                assert read(targets[1] + 96) == 0
                for expected in (3, 4, 5):
                    tick()
                    assert count() == expected
                    assert monitor('qom-get', dict(path=path, property='input-dma-address')) == targets[(expected - 1) % 4]
                for target in targets:
                    assert read(target - 4) == 0x12345678
                    assert read(target + 416) == 0x87654321
                assert all(read(0x20068210 + bank * 32) == 0 for bank in range(8)), 'DMA manufactured a completion'
                write(0x20068060, 3)
                tick()
                assert count() == 5, 'Stop request left input DMA active'
                start()
                tick()
                assert count() == 6
                for address, invalid, valid in ((0x20069514, 7, 6),
                        (0x20069518, 131 << 16, 130 << 16),
                        (0x20069518, (130 << 16) | 1, 130 << 16),
                        (0x20069a08, 192, 208)):
                    write(address, invalid)
                    tick()
                    assert count() == 6, 'Unsupported input configuration wrote a frame'
                    write(address, valid)
                for target in (0, 0x20068500, 0xb08fff00, 0xb0900000):
                    if target == 0xb08fff00:
                        write(target, 0x11223344)
                    planes([target] * 4)
                    tick()
                    assert count() == 6, 'Invalid destination accepted'
                    assert read(0x20068500) == 0
                    if target == 0xb08fff00:
                        assert read(target) == 0x11223344, 'Rejected frame partially wrote RAM'
            monitor('system_reset')
            assert count() == 0
            command(f'set_irq_in {path} frame-sync-enable 0 1')
            tick()
            assert count() == 0, 'Reset retained an enabled DMA channel'
            monitor('quit')
            process.wait(timeout=5)
        finally:
            if stream:
                stream.close()
            if wire:
                wire.close()
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
            for pipe in (process.stdin, process.stdout, process.stderr):
                pipe.close()
    print('PASS RAW12 input DMA profiles')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    check(parser.parse_args().qemu)
