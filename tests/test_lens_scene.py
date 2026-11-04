# SPDX-License-Identifier: GPL-2.0-or-later
"""Drive the iris over SPI and check its actual position affects scene RAW."""
import argparse
import json
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import time


def check(qemu, scene, color):
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    process = subprocess.Popen([qemu, '-M', 'nikon-z72-lab', '-accel', 'qtest',
        '-display', 'none', '-serial', 'none', '-qmp', 'stdio',
        '-global', f'nikon-z72-boot-config.sensor-image={scene}',
        *[arg for name in ('virtual-lens', 'frame-generate', 'sensor-sample', 'frame-sync')
          for arg in ('-global', f'nikon-z72-boot-config.{name}=on')],
        '-qtest', f'tcp:127.0.0.1:{port},server=on,wait=off', '-qtest-log', '/dev/null'],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    wire = stream = None
    try:
        deadline = time.monotonic() + 15
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

        def command(line):
            stream.write(line.encode() + b'\n')
            stream.flush()
            reply = stream.readline().decode().split()
            assert reply and reply[0] == 'OK', reply
            return reply[1] if len(reply) > 1 else None

        def write(address, value):
            command(f'writel {address:#x} {value:#x}')

        def read(address):
            return int(command(f'readl {address:#x}'), 0)

        def advance(ns):
            command(f'clock_step {ns}')

        def prop(name, path='/machine/master-lens'):
            return monitor('qom-get', path=path, property=name)

        monitor('qmp_capabilities')
        name = next(d['name'] for d in monitor('qom-list', path='/machine/unattached')
                    if d['type'] == 'child<nikon-z72-boot-config>')
        config = '/machine/unattached/' + name
        spi, sequence = 0x2c0a0300, 0
        write(spi + 0x10, 7 << 8)
        write(spi + 0xc, 0x20)
        write(spi + 0x3c, 1)

        def exchange(data):
            for value in data:
                write(spi, value)
                advance(2000)
                assert not read(spi + 0x14) & 0x20
                read(spi + 4)

        def request(code, size, data=b'', mode=0):
            nonlocal sequence
            header = bytearray((0x55, sequence, mode, code, 0, 0, 0, 0))
            struct.pack_into('<H', header, 5, (size - 2) // 2)
            header[-1] = -sum(header[:-1]) & 255
            sequence = (sequence + 1) & 255
            exchange(header)
            advance(1000000)
            packet = bytearray(size)
            packet[0] = 0x55
            packet[1:1+len(data)] = data
            packet[-1] = -sum(packet[:-1]) & 255
            exchange(packet)
            advance(1000000)
            assert prop('rejected') == 0

        request(0x1f, 4, b'\1', mode=255)
        request(0x13, 14)
        advance(2000000)
        assert prop('configuration-generation') == 1
        target = 0xb0101000
        for address, value in ((0x20069514, 6), (0x20069518, 130 << 16),
                (0x2006951c, 2 << 16), (0x20069a08, 208)):
            write(address, value)
        for i in range(4):
            write(0x20069a50 + i * 4, target)
        write(target - 4, 0x12345678)
        write(target + 416, 0x87654321)
        command(f'set_irq_in {config} frame-sync-enable 0 1')
        write(0x20068008, 0x200)

        def inspect(expected=None):
            aperture = prop('preview-scene-aperture', config)
            factor = prop('preview-scene-factor-q16', config)
            if expected is not None:
                assert aperture == expected, (aperture, expected)
            ideal = 65536 * 2 ** (-aperture / 192)
            assert abs(factor - ideal) <= max(1, ideal * .002)
            raw = bytes.fromhex(command(f'read {target:#x} 0x1a0')[2:])
            for y in range(2):
                if color:
                    values = (224, 32) if y == 0 else (32, 48)
                    decoded = []
                    for i in range(2):
                        decoded.append((raw[y*208+i] << 4) | ((raw[y*208+2] >> (4*i)) & 15))
                    for value, source in zip(decoded, values):
                        ideal_sample = ((source << 4) | (source >> 4)) * 2 ** (-aperture / 192)
                        assert abs(value - ideal_sample) <= max(1, ideal_sample * .002)
                    group = raw[y*208:y*208+3]
                else:
                    ideal_sample = 224 * 2 ** (-aperture / 192)
                    assert abs(raw[y*208] - ideal_sample) <= max(1, ideal_sample * .002)
                    group = raw[y*208:y*208+3]
                    assert len(set(group)) == 1
                assert raw[y*208:y*208+195] == group * 65
                assert raw[y*208+195:(y+1)*208] == bytes(13)
            assert read(target - 4) == 0x12345678 and read(target + 416) == 0x87654321
            return aperture

        advance(33333333)
        inspect(0)
        for target_aperture in (192, 384, 576, 768, 960, 1152, 64, 0):
            request(0xa3, 4, struct.pack('<H', target_aperture))
            advance(150000000)
            assert prop('aperture-position') == target_aperture
            inspect(target_aperture)
        request(0xa3, 4, struct.pack('<H', 1152))
        advance(33333333)
        assert prop('aperture-pending')
        sampled = inspect()
        assert 0 < sampled < 1152
        completed = prop('input-dma-count', config)
        previous = (prop('preview-scene-aperture', config), prop('preview-scene-factor-q16', config))
        for i in range(4):
            write(0x20069a50 + i*4, 0)
        advance(150000000)
        assert prop('input-dma-count', config) == completed
        assert previous == (prop('preview-scene-aperture', config), prop('preview-scene-factor-q16', config))
        for i in range(4):
            write(0x20069a50 + i*4, target)
        advance(33333333)
        inspect(1152)
        write(0x2006800c, 0x200)
        completed = prop('input-dma-count', config)
        advance(33333333)
        assert prop('input-dma-count', config) == completed
        monitor('system_reset')
        assert prop('preview-scene-aperture', config) == prop('primary-scene-aperture', config) == 0
        assert prop('preview-scene-factor-q16', config) == prop('primary-scene-factor-q16', config) == 65536
        assert prop('aperture-position') == 0
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
    print('PASS scene iris coupling:', 'P6 RGB' if color else 'P5 gray', 'whole/fractional stops, actual motion, invalid DMA and reset')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as folder:
        scene = Path(folder)/'scene.pnm'
        for color in (False, True):
            scene.write_bytes(b'P6\n1 1\n255\n'+bytes((224,32,48)) if color else b'P5\n1 1\n255\n\xe0')
            check(args.qemu, scene, color)
