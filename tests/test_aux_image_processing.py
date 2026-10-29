# SPDX-License-Identifier: GPL-2.0-or-later
"""Check image-derived auxiliary cells, bounded DMA and reference lifetime."""
import argparse
import json
import random
import socket
import struct
import subprocess
import time


def check(qemu):
    for enabled in (False, True):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        process = subprocess.Popen([qemu, '-M', 'nikon-z72-lab', '-accel', 'qtest',
            '-display', 'none', '-serial', 'none', '-qmp', 'stdio',
            '-global', 'nikon-z72-boot-config.release-config=on',
            '-global', f'nikon-z72-boot-config.aux-image-process={"on" if enabled else "off"}',
            '-qtest', f'tcp:127.0.0.1:{port},server=on,wait=off', '-qtest-log', '/dev/null'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        wire = stream = monitor = None
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

            def load(address, data):
                command(f'write {address:#x} {len(data):#x} 0x{data.hex()}')

            def data_at(address, size):
                return bytes.fromhex(command(f'read {address:#x} {size:#x}')[2:])

            monitor('qmp_capabilities')
            names = [item['name'] for item in monitor('qom-list', dict(path='/machine/unattached'))
                     if item['type'] == 'child<nikon-z72-boot-config>']
            assert len(names) == 1
            path = '/machine/unattached/' + names[0]
            aux, source, target, key = 0x20201000, 0x50301000, 0x50401000, 0xb1820000
            width, height, columns, rows = 320, 224, 10, 7
            stride = width + 16
            length = columns * rows * 16
            completed = 0

            def count():
                return monitor('qom-get', dict(path=path, property='aux-image-process-count'))

            def configure():
                for offset, value in ((0x4c, 1), (0x50, columns), (0x54, rows),
                        (0x5c, key), (0x104, 0), (0x110, 3), (0x11c, 1),
                        (0x12c, stride), (0x130, source), (0x160, 0),
                        (0x164, 1), (0x178, target)):
                    write(aux + offset, value)

            def frame(value):
                load(source, b''.join(value[y * width:(y + 1) * width] + b'\xa5' * 16
                                     for y in range(height)))

            def run_frame(value):
                nonlocal completed
                frame(value)
                write(aux + 0x2c, 0xff)
                write(aux, 1)
                write(aux, 0)
                write(aux + 4, 1)
                completed += 1
                assert count() == completed and read(aux + 0x2c) == 2
                assert read(aux + 4) == 0, 'Completed job retained its run request'
                assert read(target - 4) == 0x12345678 and read(target + length) == 0x87654321
                assert read(source - 4) == 0x10203040
                assert read(source + stride * height) == 0x50607080
                assert data_at(source + width, 16) == b'\xa5' * 16
                assert read(read(aux + 0x5c)) == 0x13579bdf, \
                    'Model rewrote opaque firmware workspace storage'
                return data_at(target, length)

            configure()
            load(target, b'\xa5' * length)
            for address, value in ((target - 4, 0x12345678), (target + length, 0x87654321),
                    (source - 4, 0x10203040), (source + stride * height, 0x50607080),
                    (key, 0x13579bdf)):
                write(address, value)
            base = random.Random(0x72).randbytes(width * height)
            if not enabled:
                frame(base)
                write(aux + 4, 1)
                assert count() == 0 and read(aux + 0x2c) == 0
                assert data_at(target, length) == b'\xa5' * length
                continue
            first = run_frame(base)
            assert all(struct.unpack_from('<hhH', first, index * 16) == (512, 512, 65535)
                       for index in range(columns * rows))
            # CPU-context IRQ delivery is covered by test_input_events.py.
            write(aux + 0x20, 2)
            second = run_frame(base)
            assert second == bytes(length), 'Identical source frames did not produce zero motion'
            shifted = bytes(base[min(max(y + 2, 0), height - 1) * width +
                                 min(max(x - 1, 0), width - 1)]
                            for y in range(height) for x in range(width))
            third = run_frame(shifted)
            center = (3 * columns + 3) * 16
            assert struct.unpack_from('<hhH', third, center) == (32, -64, 0), \
                'Image translation did not produce the recovered coordinate units'
            write(aux + 0x2c, 0xff)
            retained = data_at(target, length)
            source_before = data_at(source, stride * height)
            write(0x54effff0, 0x11223344)
            for offset, invalid, valid in ((0x130, aux, source), (0x178, aux, target),
                    (0x130, 0x54effff0, source), (0x178, 0x54effff0, target),
                    (0x178, source, target),
                    (0x12c, width - 1, stride), (0x104, 1, 0), (0x54, 33, rows)):
                write(aux + offset, invalid)
                write(aux + 4, 1)
                assert count() == completed and read(aux + 0x2c) == 0
                assert data_at(target, length) == retained, 'Rejected job partially wrote results'
                assert data_at(source, stride * height) == source_before
                assert read(0x54effff0) == 0x11223344
                write(aux + offset, valid)
            recovered = run_frame(base)
            assert struct.unpack_from('<hhH', recovered, center) == (-32, 64, 0), \
                'Rejected job changed the reference image'
            saturated = run_frame(bytes([255]) * (width * height))
            assert struct.unpack_from('<hhH', saturated, center) == (0, 0, 65535)
            second_key = key + 0x20000
            write(second_key, 0x13579bdf)
            write(aux + 0x5c, second_key)
            other = run_frame(shifted)
            assert struct.unpack_from('<hhH', other, center) == (512, 512, 65535)
            write(aux + 0x5c, key)
            independent = run_frame(bytes([255]) * (width * height))
            assert independent == bytes(length), 'Workspace streams shared reference history'
            monitor('system_reset')
            completed = 0
            assert count() == 0 and read(aux + 0x2c) == 0 and read(aux + 0x20) == 0
            configure()
            reset = run_frame(base)
            assert struct.unpack_from('<hhH', reset, center) == (512, 512, 65535), \
                'Reset retained a reference image'
        finally:
            if stream is not None:
                stream.close()
            if wire is not None:
                wire.close()
            if process.poll() is None:
                try:
                    if monitor is None:
                        process.terminate()
                    else:
                        monitor('quit')
                except (OSError, ValueError):
                    process.terminate()
                process.wait(timeout=10)
    print('PASS auxiliary image processing: pixel-derived cells, translation, metric saturation, '
          'bounded DMA, independent references, reset and default-off behavior')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    check(parser.parse_args().qemu)
