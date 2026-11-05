# SPDX-License-Identifier: GPL-2.0-or-later
"""Check a P6 scene reaches RAW RAM and bounded NV12 preview destinations."""
import argparse
from io import BytesIO
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time

from PIL import Image


def check(qemu, scene):
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    process = subprocess.Popen([qemu, '-M', 'nikon-z72-lab', '-accel', 'qtest',
        '-display', 'none', '-serial', 'none', '-qmp', 'stdio',
        '-global', f'nikon-z72-boot-config.sensor-image={scene}',
        *[item for name in ('frame-generate', 'frame-process', 'sensor-sample', 'frame-sync')
          for item in ('-global', f'nikon-z72-boot-config.{name}=on')],
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
        wire.settimeout(30)
        stream = wire.makefile('rwb')
        assert 'QMP' in json.loads(process.stdout.readline())

        def monitor(name, **arguments):
            process.stdin.write(json.dumps(dict(execute=name, arguments=arguments)).encode() + b'\n')
            process.stdin.flush()
            while True:
                reply = json.loads(process.stdout.readline())
                if 'event' not in reply:
                    assert 'return' in reply, reply
                    return reply['return']

        def command(text):
            stream.write(text.encode() + b'\n')
            stream.flush()
            reply = stream.readline().decode().split()
            assert reply and reply[0] == 'OK', reply
            return reply[1] if len(reply) > 1 else None

        def write(address, value):
            command(f'writel {address:#x} {value:#x}')

        def data(address, size):
            return bytes.fromhex(command(f'read {address:#x} {size:#x}')[2:])

        monitor('qmp_capabilities')
        config = next(item['name'] for item in monitor('qom-list', path='/machine/unattached')
                      if item['type'] == 'child<nikon-z72-boot-config>')
        path = '/machine/unattached/' + config

        def processed():
            return monitor('qom-get', path=path, property='processing-dma-count')

        source = 0xb0101000
        for address, value in ((0x20069514, 6), (0x20069518, 1380 << 16),
                (0x2006951c, 918 << 16), (0x20069a08, 2080), (0x20100600, 0x09000201),
                (0x20100620, 0x03920560), (0x20102100, 0x121), (0x20102608, 1),
                (0x20380008, 1), (0x20380010, 1), (0x20380048, 0x05640396),
                (0x2038030c, 2080), (0x20380310, source)):
            write(address, value)
        targets = [0xb2001000 + i * 0x1000 for i in range(3)]
        for slot in range(4):
            write(0x20069a50 + slot * 4, source)
            write(0x20102200 + (slot * 16 + 8) * 4, 0x40000000)
            for i, target in enumerate(targets):
                write(0x20102200 + (slot * 16 + i + 3) * 4, target)
        for channel, target in enumerate(targets, 3):
            base = 0x20100400 + channel * 0x40
            for offset, value in ((0, 0x09000201), (0x10, 16), (0x14, 16),
                                  (0x20, 4 << 16 | 8), (0x28, 0x100)):
                write(base + offset, value)
            command(f'memset {target:#x} 0x120 0xa5')
            write(target - 4, 0x12345678)
            write(target + 0x120, 0x87654321)
        command(f'set_irq_in {path} frame-sync-enable 0 1')
        write(0x20068004, 0x200)
        write(0x20068010, 0x200)
        write(0x20068100, 0x80)
        write(0x20068008, 0x200)
        # A late invalid plane must prevent writes to the earlier outputs.
        write(0x20100568, 32)
        command('clock_step 33333333')
        assert processed() == 0 and all(data(p, 0x120) == b'\xa5' * 0x120 for p in targets)
        write(0x20100568, 0x100)
        command('clock_step 33333333')
        assert processed() == 1
        # The declared RAW12 input has R/G on even rows and G/B on odd rows.
        assert data(source, 3) == bytes((224, 32, 0x2e))
        assert data(source + 2080, 3) == bytes((32, 48, 0x32))
        # Independent full-range BT.601 reference, converted to studio NV12.
        rgb = (224, 32, 48)
        y = round(.299 * rgb[0] + .587 * rgb[1] + .114 * rgb[2])
        cb = round(128 - .168736 * rgb[0] - .331264 * rgb[1] + .5 * rgb[2])
        cr = round(128 + .5 * rgb[0] - .418688 * rgb[1] - .081312 * rgb[2])
        expected = (round(16 + y * 219 / 255), round(16 + cb * 224 / 255),
                    round(16 + cr * 224 / 255))
        for target in targets:
            for row in range(4):
                assert all(abs(v - expected[0]) <= 1 for v in data(target + row * 16, 8))
                assert data(target + row * 16 + 8, 8) == b'\x10' * 8
            for row in range(2):
                uv = data(target + 0x100 + row * 16, 8)
                assert all(abs(v - expected[1 + i % 2]) <= 1 for i, v in enumerate(uv))
                assert data(target + 0x108 + row * 16, 8) == b'\x80' * 8
            assert data(target + 64, 0xc0) == b'\xa5' * 0xc0
            assert data(target - 4, 4) == bytes.fromhex('78563412')
            assert data(target + 0x120, 4) == bytes.fromhex('21436587')
        write(0x2006800c, 0x200)
        command('clock_step 33333333')
        assert processed() == 1
        # Quarter-size 1620 input produces an odd 405-column JPEG. Chroma
        # must retain complete pairs without crossing its private row bounds.
        base, first, output = 0x24072000, 0xbd200000, 0xdb8c9c00
        plane = 1664 * 1088
        second = first + plane
        command(f'memset {first:#x} {plane:#x} 0x60')
        command(f'memset {second:#x} {plane:#x} 0xc0')
        for cbcr, expected_rgb in ((192, (186, 28, 209)), (128, (96, 96, 96))):
            command(f'memset {second:#x} {plane:#x} {cbcr:#x}')
            write(base + 4, 0x80000000)
            for offset, value in ((0, 0x31), (0x18, 270), (0x1c, 405),
                    (0x400, 0x28), (0x404, 9), (0x408, 0x10000),
                    (0x410, 1664), (0x414, 1664), (0x418, 1620), (0x41c, 1080),
                    (0x430, first), (0x434, second), (0x440, output), (0x458, 2048),
                    (0x490, 0x300000), (0x494, 0x300000)):
                write(base + offset, value)
            for offset in range(0x100, 0x180, 4):
                write(base + offset, 0x01010101)
            write(output - 4, 0x12345678)
            write(output + 0x100000, 0x87654321)
            write(base + 4, 1)
            write(base + 0x400, 0x4028)
            write(base + 0x404, 0x4009)
            length = int(command(f'readl {base + 0x20:#x}'), 0)
            assert 128 < length < 0x100000
            with Image.open(BytesIO(data(output, length))) as image:
                assert image.size == (405, 270)
                for point in ((0, 0), (202, 135), (404, 269)):
                    assert max(abs(a - b) for a, b in zip(image.getpixel(point), expected_rgb)) <= 3
            assert data(output - 4, 4) == bytes.fromhex('78563412')
            assert data(output + 0x100000, 4) == bytes.fromhex('21436587')
            assert data(first, 8) == b'\x60' * 8
            assert data(second, 8) == bytes((cbcr,)) * 8
        monitor('system_reset')
        assert processed() == 0
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
    print('PASS P6 RAW RAM, NV12, odd-width JPEG chroma from guest RAM, bounds, stop and reset')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as directory:
        scene = Path(directory) / 'scene.ppm'
        scene.write_bytes(b'P6\n1 1\n255\n' + bytes((224, 32, 48)))
        check(args.qemu, scene)
