# SPDX-License-Identifier: GPL-2.0-or-later
"""Check diagnostic still rasters, rejected recipes and completion ordering."""
import argparse
import json
import socket
import struct
import subprocess
import time


def check(qemu):
    width, height, stride = 8288, 5520, 12432
    out_width, out_height = 8256, 5504
    source, first, second = 0xbad0a000, 0xea3b6800, 0xecf0c800
    plane_bytes = out_width * out_height
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

            def load(address, value):
                command(f'write {address:#x} {len(value):#x} 0x{value.hex()}')

            def data_at(address, length):
                return bytes.fromhex(command(f'read {address:#x} {length:#x}')[2:])

            monitor('qmp_capabilities')
            devices = monitor('qom-list', dict(path='/machine/unattached'))
            config = next(d['name'] for d in devices if d['type'] == 'child<nikon-z72-boot-config>')
            gic = next(d['name'] for d in devices if d['type'] == 'child<arm_gic>')
            command('irq_intercept_in /machine/unattached/' + gic)

            def count():
                return monitor('qom-get', dict(path='/machine/unattached/' + config,
                                              property='processing-dma-count'))

            def configure():
                values = {0: 3, 4: 3, 0x10: 1, 0x20: 0, 0x40: 5, 0x44: 0,
                    0x48: width << 16 | height, 0x300: 2, 0x30c: stride, 0x310: source,
                    0x400: 0xa01580, 0x40c: 0x20400048, 0x420: 1, 0x428: 1,
                    0x42c: 2, 0x488: first, 0x498: second, 0x4c8: out_width}
                for offset, value in values.items():
                    write(0x20380000 + offset, value)
                for offset, value in ((0x40, 5), (0x44, 0), (0x48, width << 16 | height)):
                    write(0x203c0000 + offset, value)

            points = [(0, 0), (1, 0), (out_width // 2, out_height // 2),
                      (out_width - 1, out_height - 1)]
            bright = set()
            for x, y in points:
                offset = (y * height // out_height) * stride + (x * width // out_width // 2) * 3
                bright.add(offset)
                load(source + offset, b'\xff' * 3)
            write(source - 4, 0x12345678)
            write(source + stride * height, 0x87654321)
            write(first - 4, 0x10203040)
            write(second + plane_bytes, 0x50607080)
            configure()
            write(first, 0xa5a5a5a5)
            write(second, 0x5a5a5a5a)
            write(0x20380008, 1)
            if not enabled or role == 'master':
                write(0x20100900, 1)
                write(0x201008a0, 1)
                assert count() == 0 and read(0x20380024) == 0
                assert read(0x2010001c) == 0 and read(0x20100900) == 1
                assert read(first) == 0xa5a5a5a5 and read(second) == 0x5a5a5a5a
                continue
            assert count() == 1 and read(0x20380024) == 2, (role, count(), hex(read(0x20380024)))
            assert not levels.get(99 - 32, False)
            for x, y in points + [(10, 10), (out_width - 2, 5), (5, out_height - 1)]:
                offset = (y * height // out_height) * stride + (x * width // out_width // 2) * 3
                assert data_at(first + y * out_width + x, 1) == (b'\xff' if offset in bright else b'\x00')
            for y in (0, out_height // 2, out_height - 1):
                assert data_at(second + y * out_width, out_width) == b'\x80' * out_width
            assert read(first - 4) == 0x10203040 and read(second + plane_bytes) == 0x50607080
            assert read(source - 4) == 0x12345678 and read(source + stride * height) == 0x87654321
            write(0x20380008, 1)
            assert count() == 1, 'Pending completion accepted another job'
            write(0x20380020, 2)
            assert levels[99 - 32]
            write(0x20380024, 2)
            assert not levels[99 - 32]
            for address, value in ((0x20380048, 0x1000100), (0x20380310, 0xbee85ff0),
                                   (0x20380488, 0xffe667e0), (0x20380498, first + 16)):
                configure()
                write(first, 0xa5a5a5a5)
                write(second, 0x5a5a5a5a)
                write(address, value)
                write(0x20380008, 1)
                assert count() == 1 and read(0x20380024) == 0
                assert read(first) == 0xa5a5a5a5 and read(second) == 0x5a5a5a5a
            configure()
            load(source + stride * height - 3, b'\x01\x00\x00')
            write(0x20380008, 1)
            assert count() == 1 and read(0x20380024) == 0
            assert read(first) == 0xa5a5a5a5 and read(second) == 0x5a5a5a5a, 'Late invalid pixels partially changed output'
            load(source + stride * height - 3, bytes(3))
            write(0x20380008, 1)
            assert count() == 2 and read(0x20380024) == 2
            write(0x20380024, 2)

            # Native still transform: full-size copy and a small secondary view.
            full, small, small_uv = 0xf510e800, 0xc8984800, 0xc8b3e800
            small_width, small_height, small_stride = 1620, 1080, 1664

            def configure_transform():
                for index, (pitch, geometry, y_plane, uv_plane) in enumerate((
                        (out_width, out_height << 16 | out_width, first, second),
                        (out_width, out_height << 16 | out_width, full, full + plane_bytes),
                        (small_stride, small_height << 16 | small_width, small, small_uv))):
                    load(0x20100440 + index * 0x40, struct.pack('<13I',
                        0x09000001, 0x10000, 0, 0, pitch, pitch, 0, 0, geometry, y_plane, uv_plane, 0, 0))
                for offset in (0x8a0, 0x9c0, 0x9e0, 0xac0, 0xba0, 0xdc0, 0xde0):
                    write(0x20100000 + offset, 1)
                for index, offset in enumerate((0x9c0, 0x9e0, 0xba0)):
                    pointer = 0xc1001000 + index * 0x100
                    params = [0x110a0000, 0, 0, 0x10003 if index == 2 else 0x10002,
                        0, 0, 0, 0, 0, 0, 0x11080040,
                        0x06530000 if index == 2 else 0x203f0000,
                        0x04370000 if index == 2 else 0x157f0000,
                        0x400040 if index == 2 else 0x800080,
                        0x10001 if index == 2 else 0x80008]
                    load(pointer, struct.pack('<15I', *params))
                    write(0x20100010 + offset, pointer)

            configure_transform()
            write(full, 0xa5a5a5a5)
            write(full + plane_bytes, 0x5a5a5a5a)
            command(f'memset {small:#x} {small_stride * 1088:#x} 0xa5')
            command(f'memset {small_uv:#x} {small_stride * 1088:#x} 0x5a')
            write(full - 4, 0x11223344)
            write(full + 2 * plane_bytes, 0x55667788)
            write(small - 4, 0x12345678)
            write(small_uv + small_stride * 1088, 0x87654321)
            for address, value in ((0x201004a4, first), (0x201004e8, small + 16),
                                   (0x201004e4, 0xca7121f0), (0x201004e0, 0x1000100),
                                   (0x201009d0, 0xfffffff0), (0x20100ba0, 0),
                                   (0xc100122c, 0x10000)):
                configure_transform()
                write(address, value)
                write(0x20100900, 1)
                assert count() == 2 and read(0x2010001c) == 0
                assert read(full) == 0xa5a5a5a5 and read(full + plane_bytes) == 0x5a5a5a5a
                assert read(small) == 0xa5a5a5a5 and read(small_uv) == 0x5a5a5a5a
            configure_transform()
            for address, value, restore in ((second + plane_bytes - 1, b'\x7f', b'\x80'),
                                             (first + plane_bytes - 1, b'\x01', data_at(first + plane_bytes - 1, 1))):
                load(address, value)
                write(0x20100900, 1)
                assert count() == 2 and read(0x2010001c) == 0
                assert read(full) == 0xa5a5a5a5 and read(small) == 0xa5a5a5a5
                load(address, restore)
            write(0x20100900, 1)
            assert count() == 3 and read(0x2010001c) == 0x70 and levels[102 - 32]
            for x, y in points + [(10, 10), (out_width - 1, out_height - 2)]:
                assert data_at(full + y * out_width + x, 1) == data_at(first + y * out_width + x, 1)
                assert data_at(full + plane_bytes + y * out_width + x, 1) == b'\x80'
            for x, y in ((0, 0), (small_width // 2, small_height // 2), (small_width - 1, small_height - 1)):
                sy, sx = y * out_height // small_height, x * out_width // small_width
                assert data_at(small + y * small_stride + x, 1) == data_at(first + sy * out_width + sx, 1)
                assert data_at(small_uv + y * small_stride + x, 1) == b'\x80'
            for y in (0, small_height - 1):
                assert data_at(small + y * small_stride + small_width, small_stride - small_width) == b'\xa5' * 44
                assert data_at(small_uv + y * small_stride + small_width, small_stride - small_width) == b'\x5a' * 44
            assert read(small + small_stride * small_height) == 0xa5a5a5a5
            assert read(small_uv + small_stride * small_height) == 0x5a5a5a5a
            assert read(full - 4) == 0x11223344 and read(full + 2 * plane_bytes) == 0x55667788
            assert read(small - 4) == 0x12345678 and read(small_uv + small_stride * 1088) == 0x87654321
            write(0x20100900, 1)
            assert count() == 3, 'Pending transform completion accepted another job'
            write(0x2010001c, 0x30)
            assert read(0x2010001c) == 0x40 and levels[102 - 32]
            write(0x2010001c, 0x40)
            assert not levels[102 - 32]
            write(0x20100900, 1)
            assert count() == 4 and read(0x2010001c) == 0x70
            write(0x2010001c, 0x70)

            thumbnail, thumbnail_uv = 0xc8900000, 0xc8942400
            thumbnail_bytes = 640 * 424

            def configure_thumbnail():
                for index, (pitch, geometry, y_plane, uv_plane) in enumerate((
                        (small_stride, small_height << 16 | small_width, small, small_uv),
                        (640, 424 << 16 | 640, thumbnail, thumbnail_uv))):
                    load(0x20100440 + index * 0x40, struct.pack('<13I',
                        0x09000001, 0x10000, 0, 0, pitch, pitch, 0, 0, geometry, y_plane, uv_plane, 0, 0))
                load(0xc1001000, struct.pack('<15I', 0x110a0000, 0x400000, 0,
                    0x10002, 0, 0, 0, 0xff000000, 0, 0, 0x11080040,
                    0x027f0000, 0x01a70000, 0x400040, 0x40004))
                write(0x201009d0, 0xc1001000)
                write(0x201009c0, 1)

            write(thumbnail, 0xa5a5a5a5)
            write(thumbnail_uv, 0x5a5a5a5a)
            source_head, source_tail = read(small), read(small_uv + small_stride * 1088)
            for address, value in ((0x20100464, small + 16), (0x201004a8, thumbnail + 16),
                                   (0x201004a4, 0xca7121f0), (0x201004a0, 0x1000100),
                                   (0x201009d0, 0xfffffff0), (0x201009c0, 0),
                                   (0xc100102c, 0x10000)):
                configure_thumbnail()
                write(address, value)
                write(0x201008a0, 1)
                assert count() == 4 and read(0x2010001c) == 0
                assert read(thumbnail) == 0xa5a5a5a5 and read(thumbnail_uv) == 0x5a5a5a5a
            configure_thumbnail()
            for address in (small_uv + (small_height - 1) * small_stride + small_width - 1,
                            small + (small_height - 1) * small_stride + small_width - 1):
                previous = data_at(address, 1)
                load(address, b'\x01')
                write(0x201008a0, 1)
                assert count() == 4 and read(0x2010001c) == 0
                assert read(thumbnail) == 0xa5a5a5a5 and read(thumbnail_uv) == 0x5a5a5a5a
                load(address, previous)
            write(0x201008a0, 1)
            assert count() == 5 and read(0x2010001c) == 0x10 and levels[102 - 32]
            for x, y in ((0, 0), (320, 212), (639, 423), (1, 1), (638, 422)):
                sy, sx = y * small_height // 424, x * small_width // 640
                assert data_at(thumbnail + y * 640 + x, 1) == data_at(small + sy * small_stride + sx, 1)
                assert data_at(thumbnail_uv + y * 640 + x, 1) == b'\x80'
            assert read(small) == source_head and read(small_uv + small_stride * 1088) == source_tail
            assert data_at(thumbnail_uv + thumbnail_bytes - 1, 1) == b'\x80'
            write(0x201008a0, 1)
            assert count() == 5
            write(0x2010001c, 0x10)
            assert not levels[102 - 32]
            write(0x201008a0, 1)
            assert count() == 6 and read(0x2010001c) == 0x10
            write(0x2010001c, 0x10)
            secondary, secondary_uv = 0xc8cf8800, 0xc8cfd300

            def configure_secondary():
                load(0x20100440, struct.pack('<13I', 0x09000001, 0, 0x800000, 0x80,
                    640, 640, 0, 0, 424 << 16 | 640, thumbnail, thumbnail_uv, 0, 0))
                load(0x20100480, struct.pack('<13I', 0x09000001, 0x10000, 0, 0,
                    160, 160, 0, 0, 120 << 16 | 160, secondary, secondary_uv, 0, 0))
                load(0xc1001000, struct.pack('<15I', 0x110a0000, 0x400000, 0,
                    0x10002, 0, 0, 0, 0xff000000, 0, 0, 0x11080040,
                    0x009f0000, 0x00770000, 0x400040, 0x40004))
                write(0x201009d0, 0xc1001000)
                write(0x201009c0, 1)

            write(secondary, 0xa5a5a5a5)
            write(secondary_uv, 0x5a5a5a5a)
            write(secondary - 4, 0x11223344)
            write(secondary_uv + 160 * 120, 0x55667788)
            for address, value in ((0x20100448, 0), (0x2010044c, 0), (0x20100444, 0x10000),
                                   (0x201004a4, thumbnail), (0x201004a8, secondary + 16),
                                   (0x201004a0, 0x1000100), (0xc1001030, 0x10000)):
                configure_secondary()
                write(address, value)
                write(0x201008a0, 1)
                assert count() == 6 and read(0x2010001c) == 0
                assert read(secondary) == 0xa5a5a5a5 and read(secondary_uv) == 0x5a5a5a5a
            configure_secondary()
            load(thumbnail_uv + thumbnail_bytes - 1, b'\x7f')
            write(0x201008a0, 1)
            assert count() == 6 and read(secondary) == 0xa5a5a5a5 and read(secondary_uv) == 0x5a5a5a5a
            load(thumbnail_uv + thumbnail_bytes - 1, b'\x80')
            write(0x201008a0, 1)
            assert count() == 7 and read(0x2010001c) == 0x10 and levels[102 - 32]
            for x, y in ((0, 0), (80, 60), (159, 119), (1, 1), (158, 118)):
                sy, sx = y * 424 // 120, x * 640 // 160
                assert data_at(secondary + y * 160 + x, 1) == data_at(thumbnail + sy * 640 + sx, 1)
                assert data_at(secondary_uv + y * 160 + x, 1) == b'\x80'
            assert read(secondary - 4) == 0x11223344 and read(secondary_uv + 160 * 120) == 0x55667788
            write(0x201008a0, 1)
            assert count() == 7
            monitor('system_reset')
            assert count() == 0 and read(0x20380024) == 0
            assert read(0x20100900) == 0 and read(0x2010001c) == 0 and not levels[102 - 32]
            assert read(0x201008a0) == 0
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
    print('PASS still rasters and transforms, plane guards, unsupported jobs, completion and reset')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    check(parser.parse_args().qemu)
