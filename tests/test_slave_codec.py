# SPDX-License-Identifier: GPL-2.0-or-later
"""Check bounded slave JPEG output, decoded pixels and native IRQ register semantics."""
import argparse
import io
import json
import socket
import subprocess
import time

from PIL import Image


def check(qemu):
    base, output, capacity = 0x24072000, 0xdf52e800, 0x100000
    quantizers = [[1 + index % 8 for index in range(64)],
                  [2 + index * 3 % 11 for index in range(64)]]
    for role, enabled in (('slave', True), ('slave', False), ('master', True)):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        machine = 'nikon-z72-slave-lab' if role == 'slave' else 'nikon-z72-lab'
        process = subprocess.Popen([qemu, '-M', machine, '-accel', 'qtest',
            '-display', 'none', '-serial', 'none', '-qmp', 'stdio',
            '-global', 'nikon-z72-boot-config.release-config=on',
            '-global', f'nikon-z72-boot-config.frame-process={"on" if enabled else "off"}',
            '-qtest', f'tcp:127.0.0.1:{port},server=on,wait=off', '-qtest-log', '/dev/null'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        wire = stream = None
        try:
            deadline = time.monotonic() + 10
            while wire is None:
                try:
                    wire = socket.create_connection(('127.0.0.1', port), timeout=3)
                except OSError:
                    if process.poll() is not None:
                        raise RuntimeError(process.stderr.read().decode())
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(.05)
            wire.settimeout(30)
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

            levels = {}

            def command(value):
                stream.write(value.encode() + b'\n')
                stream.flush()
                reply = stream.readline().decode().strip().split()
                while reply and reply[0] == 'IRQ':
                    levels[int(reply[2])] = reply[1] == 'raise'
                    reply = stream.readline().decode().strip().split()
                assert reply and reply[0] == 'OK', reply
                return reply[1] if len(reply) > 1 else None

            def read(address):
                return int(command(f'readl {address:#x}'), 0)

            def write(address, value):
                command(f'writel {address:#x} {value:#x}')

            def data_at(address, length):
                return bytes.fromhex(command(f'read {address:#x} {length:#x}')[2:])

            monitor('qmp_capabilities')
            devices = monitor('qom-list', dict(path='/machine/unattached'))
            config = next(d['name'] for d in devices if d['type'] == 'child<nikon-z72-boot-config>')
            gic = next(d['name'] for d in devices if d['type'] == 'child<arm_gic>')
            command('irq_intercept_in /machine/unattached/' + gic)

            def count():
                return monitor('qom-get', dict(path='/machine/unattached/' + config, property='codec-dma-count'))

            def configure(width=640, height=424, source=0xc8900000, size=capacity):
                write(base + 4, 0x80000000)
                values = {0: 0x31, 0x18: height, 0x1c: width, 0x28: 0x70f,
                    0x400: 8, 0x404: 9, 0x408: 0x10000, 0x410: width, 0x414: width,
                    0x418: width, 0x41c: height, 0x430: source,
                    0x434: source + width * height, 0x440: output, 0x458: size // 512,
                    0x484: 0, 0x490: 0x300000, 0x494: 0x300000}
                for offset, value in values.items():
                    write(base + offset, value)
                for index in range(32):
                    table, offset = index // 16, index % 16 * 4
                    write(base + 0x100 + index * 4,
                          int.from_bytes(bytes(quantizers[table][offset:offset + 4]), 'big'))

            def start():
                write(base + 4, 1)
                write(base + 0x400, 0x4008)
                write(base + 0x404, 0x4009)

            def verify(width, height, maximum):
                length = read(base + 0x20)
                assert 128 < length <= maximum
                encoded = data_at(output, length)
                assert encoded[:2] == b'\xff\xd8' and encoded[-2:] == b'\xff\xd9'
                image = Image.open(io.BytesIO(encoded))
                assert image.size == (width, height) and image.mode == 'RGB'
                assert image.quantization[0] == quantizers[0] and image.quantization[1] == quantizers[1]
                assert not image.info.get('progressive', False)
                for point, expected in (((8, 8), 255), ((width // 2, height // 2), 0), ((width - 8, height - 8), 0)):
                    assert all(abs(value - expected) <= 3 for value in image.getpixel(point)), (point, image.getpixel(point))
                image.close()
                return length

            configure()
            if role != 'slave' or not enabled:
                start()
                assert count() == 0 and read(base + 0x480) == 0 and not levels.get(105 - 32, False)
                continue
            source, plane = 0xc8900000, 640 * 424
            command(f'memset {source:#x} {plane:#x} 0')
            command(f'memset {source + plane:#x} {plane:#x} 0x80')
            for y in range(32):
                command(f'memset {source + y * 640:#x} 0x20 0xff')
            write(output, 0xa5a5a5a5)
            write(output - 4, 0x12345678)
            write(output + capacity, 0x87654321)
            for address, value in ((base, 0), (base + 0x418, 16),
                                   (base + 0x430, 0xca7121f0), (base + 0x434, source + 16),
                                   (base + 0x440, 0xffe667f0), (base + 0x440, source),
                                   (base + 0x100, 0), (base + 0x458, 1)):
                configure()
                write(address, value)
                start()
                assert count() == 0 and read(base + 0x480) == 0 and read(output) == 0xa5a5a5a5
            configure()
            command(f'memset {source + 2 * plane - 1:#x} 1 0x7f')
            start()
            assert count() == 0 and read(output) == 0xa5a5a5a5
            command(f'memset {source + 2 * plane - 1:#x} 1 0x80')
            start()
            assert count() == 1 and read(base + 0x480) == 0x08001000
            assert read(base + 0x2c) == 0x80000000 and not levels.get(105 - 32, False)
            verify(640, 424, capacity)
            assert read(output - 4) == 0x12345678 and read(output + capacity) == 0x87654321
            start()
            assert count() == 1
            write(base + 0x484, 0x1000)
            assert levels[105 - 32]
            write(base + 0x480, 0x08000000)
            assert read(base + 0x480) == 0x1000 and levels[105 - 32]
            write(base + 0x2c, 0x7fffffff)
            assert read(base + 0x2c) == 0
            write(base + 0x480, 0x1000)
            assert not levels[105 - 32]
            write(base + 4, 0x80000000)
            assert read(base + 4) == 0 and count() == 1

            width, height, source = 8256, 5504, 0xf510e800
            plane, maximum = width * height, 0xe15a00
            configure(width, height, source, maximum)
            command(f'memset {source:#x} {plane:#x} 0')
            command(f'memset {source + plane:#x} {plane:#x} 0x80')
            for y in range(32):
                command(f'memset {source + y * width:#x} 0x20 0xff')
            write(output + maximum, 0x50607080)
            start()
            assert count() == 2 and read(base + 0x480) == 0x08001000
            verify(width, height, maximum)
            assert read(output - 4) == 0x12345678 and read(output + maximum) == 0x50607080
            monitor('system_reset')
            assert count() == 0 and read(base + 0x480) == 0 and read(base + 0x2c) == 0
            assert read(base + 0x100) == 0 and read(base + 4) == 0 and not levels[105 - 32]
        finally:
            if stream is not None:
                stream.close()
            if wire is not None:
                wire.close()
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=5)
            process.stdin.close()
            process.stdout.close()
            process.stderr.close()
    print('PASS slave JPEG pixels, quantizers, bounds, rejected jobs, IRQ acknowledgement and reset')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    check(parser.parse_args().qemu)
