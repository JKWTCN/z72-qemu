# SPDX-License-Identifier: GPL-2.0-or-later
"""Check bounded engine JPEG output, decoded pixels and native IRQ register semantics."""
import argparse
import io
import json
import socket
import subprocess
import time

from PIL import Image


def check(qemu):
    base, capacity = 0x24072000, 0x100000
    quantizers = [[1 + index % 8 for index in range(64)],
                  [2 + index * 3 % 11 for index in range(64)]]
    for role, enabled, color in (('slave', True, False), ('slave', False, False),
                                  ('master', True, False), ('master', False, False),
                                  ('slave', True, True)):
        output = 0xdb8c9c00 if role == 'master' else 0xdf52e800
        small_source = 0xbd200000 if role == 'master' else 0xc8900000
        scratch_end = 0xc3dcb400 if role == 'master' else 0xca712200
        output_end = 0xffee5400 if role == 'master' else 0xffe66800
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        machine = 'nikon-z72-slave-lab' if role == 'slave' else 'nikon-z72-lab'
        process = subprocess.Popen([qemu, '-M', machine, '-accel', 'qtest',
            '-display', 'none', '-serial', 'none', '-qmp', 'stdio',
            '-global', 'nikon-z72-boot-config.release-config=on',
            '-global', f'nikon-z72-boot-config.frame-process={"on" if enabled else "off"}',
            '-global', f'nikon-z72-boot-config.jpeg-color-checker={"on" if color else "off"}',
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

            def measured_count():
                return monitor('qom-get', dict(path='/machine/unattached/' + config, property='codec-measured-count'))

            def decoded_count():
                return monitor('qom-get', dict(path='/machine/unattached/' + config, property='codec-decoded-count'))

            # A separate JPEG exercises the read direction, including color;
            # this does not use the modeled encoder as a decode oracle.
            picture = Image.new('RGB', (160, 120), (32, 64, 224))
            picture.paste((240, 208, 32), (16, 16, 80, 64))
            packed = io.BytesIO()
            picture.save(packed, 'JPEG', quality=95, subsampling=2)
            jpeg = packed.getvalue()
            expected = Image.open(io.BytesIO(jpeg)).convert('YCbCr').tobytes()
            plane, target = 160 * 120, small_source
            input_size = (len(jpeg) + 511) & ~511

            def decoder_setup(data=jpeg, destination=target, geometry=(160, 120), stride=160):
                previous_decoded = decoded_count()
                write(base + 4, 0x80000000)
                command(f'memset {output:#x} {input_size:#x} 0')
                command(f'write {output:#x} {len(data):#x} 0x{data.hex()}')
                command(f'memset {target:#x} {2 * plane:#x} 0xa5')
                for offset, value in {0: 0x39, 0x28: 0x10, 0x400: 8, 0x404: 0x4008,
                        0x408: 0x10000, 0x410: 0, 0x414: 0, 0x418: 0, 0x41c: 0,
                        0x420: 0, 0x424: 0, 0x428: 0,
                        0x430: destination, 0x434: destination + plane, 0x440: output,
                        0x458: input_size // 512, 0x484: 0xc4d000}.items():
                    write(base + offset, value)
                write(base + 4, 1)
                if not enabled:
                    assert decoded_count() == 0 and read(base + 0x480) == 0
                    assert data_at(target, 2 * plane) == b'\xa5' * (2 * plane)
                    return
                assert read(base + 0x480) == 0x0a000000 and levels[105 - 32]
                assert read(base + 0x1c) == 160 and read(base + 0x18) == 120
                assert read(base) & 7 == 2 and decoded_count() == previous_decoded
                assert data_at(target, 2 * plane) == b'\xa5' * (2 * plane)
                write(base + 0x480, 0x0a000000)
                write(base + 0x2c, ~0x10 & 0xffffffff)
                assert not levels[105 - 32]
                write(base + 0x410, stride)
                write(base + 0x414, stride)
                write(base + 0x418, geometry[0])
                write(base + 0x41c, geometry[1])
                write(base + 0x400, 0x4008)

            write(target - 4, 0x12345678)
            write(target + 2 * plane, 0x87654321)
            decoder_setup()
            if enabled:
                assert decoded_count() == 1 and read(base + 0x480) == 0x0800c000
                assert levels[105 - 32] and read(base + 0x2c) == 0x80000000
                pixels = data_at(target, 2 * plane)
                assert all(abs(pixels[i] - expected[i * 3]) <= 2 for i in range(plane))
                assert all(abs(pixels[plane + i] - expected[(i & ~1) * 3 + (2 if i & 1 else 1)]) <= 2
                           for i in range(plane))
                assert read(target - 4) == 0x12345678 and read(target + 2 * plane) == 0x87654321
                write(base + 0x480, 0x0800c000)
                assert not levels[105 - 32]
                for data, destination, geometry in ((jpeg[:-64], target, (160, 120)),
                        (jpeg, output_end - plane, (160, 120)), (jpeg, target, (162, 120))):
                    decoder_setup(data, destination, geometry)
                    assert decoded_count() == 1 and read(base + 0x480) == 0
                    assert data_at(target, 2 * plane) == b'\xa5' * (2 * plane)
                write(base + 4, 0x80000000)
                write(base + 0x440, 0x24072000)
                write(base + 4, 1)
                assert read(base + 0x480) == 0 and decoded_count() == 1
                plane = 192 * 120
                write(target + 2 * plane, 0x87654321)
                decoder_setup(stride=192)
                assert decoded_count() == 2
                pixels = data_at(target, 2 * plane)
                for y in range(120):
                    assert all(abs(pixels[y * 192 + x] - expected[(y * 160 + x) * 3]) <= 2 for x in range(160))
                    assert pixels[y * 192 + 160:(y + 1) * 192] == b'\xa5' * 32
                    assert pixels[plane + y * 192 + 160:plane + (y + 1) * 192] == b'\xa5' * 32
                assert read(target + 2 * plane) == 0x87654321
            monitor('system_reset')
            assert decoded_count() == 0 and read(base + 0x480) == 0 and not levels.get(105 - 32, False)

            def configure(width=640, height=424, source=small_source, size=capacity, scale=0, measuring=False):
                stride = 1664 if width == 1620 else width
                rows = 1088 if width == 1620 else height
                write(base + 4, 0x80000000)
                values = {0: 0x31, 0x18: height >> scale, 0x1c: width >> scale, 0x28: 0x70f,
                    0x400: 8 | scale << 4, 0x404: 0xb if measuring else 9,
                    0x408: 0x10000, 0x410: stride, 0x414: stride,
                    0x418: width, 0x41c: height, 0x430: source,
                    0x434: source + stride * rows, 0x440: output, 0x458: 0 if measuring else size // 512,
                    0x484: 0, 0x490: 0x300000, 0x494: 0x300000}
                for offset, value in values.items():
                    write(base + offset, value)
                for index in range(32):
                    table, offset = index // 16, index % 16 * 4
                    write(base + 0x100 + index * 4,
                          int.from_bytes(bytes(quantizers[table][offset:offset + 4]), 'big'))

            def start():
                write(base + 4, 1)
                write(base + 0x400, (read(base + 0x400) & ~0xc000) | 0x4000)
                write(base + 0x404, (read(base + 0x404) & ~0xc000) | 0x4000)

            def verify(width, height, maximum, bright=(8, 8)):
                length = read(base + 0x20)
                assert 128 < length <= maximum
                encoded = data_at(output, length)
                assert encoded[:2] == b'\xff\xd8' and encoded[-2:] == b'\xff\xd9'
                image = Image.open(io.BytesIO(encoded))
                assert image.size == (width, height) and image.mode == 'RGB'
                assert image.layer[0][1:3] == (2, 1), 'Mode 1 must encode 4:2:2 for native playback'
                assert image.quantization[0] == quantizers[0] and image.quantization[1] == quantizers[1]
                assert not image.info.get('progressive', False)
                for point, expected in ((bright, 255), ((width // 2, height // 2), 0), ((width - 8, height - 8), 0)):
                    rgb = ((240, 208, 32) if expected else (32, 64, 224)) if color else (expected,) * 3
                    assert all(abs(value - target) <= 3 for value, target in zip(image.getpixel(point), rgb)), (point, image.getpixel(point))
                image.close()
                return length

            configure()
            if not enabled:
                start()
                assert count() == 0 and read(base + 0x480) == 0 and not levels.get(105 - 32, False)
                continue
            source, plane = small_source, 640 * 424
            command(f'memset {source:#x} {plane:#x} 0')
            command(f'memset {source + plane:#x} {plane:#x} 0x80')
            for y in range(32):
                command(f'memset {source + y * 640:#x} 0x20 0xff')
            write(output, 0xa5a5a5a5)
            write(output - 4, 0x12345678)
            write(output + capacity, 0x87654321)
            for address, value in ((base, 0), (base + 0x418, 16),
                                   (base + 0x430, scratch_end - 16), (base + 0x434, source + 16),
                                   (base + 0x440, output_end - 16), (base + 0x440, source),
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
            assert count() == 1 and read(base + 0x480) == 0x08001000, (
                role, count(), hex(read(base + 0x480)))
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

            width, height = 8256, 5504
            source = 0xed650800 if role == 'master' else 0xf510e800
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

            width, height, stride, rows = 1620, 1080, 1664, 1088
            source = 0xbd284800 if role == 'master' else 0xc8984800
            second = source + stride * rows
            command(f'memset {source:#x} {stride * height:#x} 0')
            command(f'memset {second:#x} {stride * height:#x} 0x80')
            command(f'memset {source + width:#x} 1 0x7f')
            command(f'memset {second + width:#x} 1 1')

            def patch(value):
                for y in range(64):
                    command(f'memset {source + y * stride:#x} 0x40 {value:#x}')

            patch(255)
            write(output, 0xa5a5a5a5)
            write(output + capacity, 0x87654321)
            configure(width, height, source, scale=2, measuring=True)
            write(base + 0x458, 1)
            start()
            assert count() == 2 and measured_count() == 0 and read(output) == 0xa5a5a5a5
            invalid_pixels = [second + (height - 1) * stride + width - 1]
            if color:
                invalid_pixels.append(source + (height - 1) * stride + width - 1)
            for address in invalid_pixels:
                configure(width, height, source, scale=2, measuring=True)
                previous = data_at(address, 1)
                command(f'memset {address:#x} 1 1')
                start()
                assert count() == 2 and measured_count() == 0 and read(base + 0x480) == 0
                command(f'memset {address:#x} 1 {previous[0]:#x}')
            configure(width, height, source, scale=2, measuring=True)
            start()
            measurement = read(base + 0x20)
            assert measured_count() == 1 and count() == 2 and measurement > 128
            assert read(output) == 0xa5a5a5a5 and read(output + capacity) == 0x87654321
            assert read(base + 0x480) == 0x08001000 and read(base + 0x2c) == 0x80000000
            start()
            assert measured_count() == 1
            patch(0)
            configure(width, height, source, scale=2, measuring=True)
            start()
            assert measured_count() == 2 and count() == 2 and read(base + 0x20) != measurement
            assert read(output) == 0xa5a5a5a5
            patch(255)
            configure(width, height, source, scale=2)
            start()
            assert count() == 3 and measured_count() == 2
            assert verify(405, 270, capacity) == measurement, 'Measured size differs from the same written JPEG'
            configure(width, height, source)
            start()
            assert count() == 4 and measured_count() == 2
            verify(width, height, capacity)
            assert data_at(source + width, 1) == b'\x7f' and data_at(second + width, 1) == b'\x01'
            assert read(output - 4) == 0x12345678 and read(output + capacity) == 0x87654321

            write(output, 0xa5a5a5a5)
            configure(scale=2, measuring=True)
            start()
            measurement = read(base + 0x20)
            assert measured_count() == 3 and count() == 4 and read(output) == 0xa5a5a5a5
            configure(scale=2)
            start()
            assert count() == 5 and verify(160, 106, capacity, bright=(2, 2)) == measurement

            width, height = 160, 120
            source = 0xbd5f8800 if role == 'master' else 0xc8cf8800
            plane = width * height
            command(f'memset {source:#x} {plane:#x} 0')
            command(f'memset {source + plane:#x} {plane:#x} 0x80')
            for y in range(32):
                command(f'memset {source + y * width:#x} 0x20 0xff')
            write(output, 0xa5a5a5a5)
            configure(width, height, source, measuring=True)
            start()
            measurement = read(base + 0x20)
            assert measured_count() == 4 and count() == 5 and read(output) == 0xa5a5a5a5
            configure(width, height, source)
            start()
            assert count() == 6 and verify(width, height, capacity) == measurement
            monitor('system_reset')
            assert count() == 0 and measured_count() == 0 and read(base + 0x480) == 0 and read(base + 0x2c) == 0
            assert read(base + 0x100) == 0 and read(base + 4) == 0 and not levels[105 - 32]
            if not color:
                configure(width, height, source)
                command(f'memset {source:#x} {plane:#x} 0x60')
                command(f'memset {source + plane:#x} {plane:#x} 0x80')
                start()
                image = Image.open(io.BytesIO(data_at(output, read(base + 0x20))))
                image.load()
                assert count() == 1 and image.getpixel((80, 60)) == (96, 96, 96)
                image.close()
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
    print('PASS JPEG encoding, staged decoding, color pixels, quantizers, bounds, rejected jobs, IRQ acknowledgement and reset')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    check(parser.parse_args().qemu)
