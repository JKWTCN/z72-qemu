# SPDX-License-Identifier: GPL-2.0-or-later
"""Check diagnostic still rasters, rejected recipes and completion ordering."""
import argparse
import json
import socket
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
                assert count() == 0 and read(0x20380024) == 0
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
            monitor('system_reset')
            assert count() == 0 and read(0x20380024) == 0
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
    print('PASS still raster pixels, plane guards, unsupported jobs, masked completion and reset')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    check(parser.parse_args().qemu)
