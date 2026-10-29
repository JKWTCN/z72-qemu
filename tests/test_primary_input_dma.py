# SPDX-License-Identifier: GPL-2.0-or-later
"""Check the complete primary RAW12 split and device-local address remapping."""
import argparse
import json
import socket
import subprocess
import time


def check(qemu):
    for role, enabled, sampling, notifying in (
            ('master', True, True, True), ('master', True, True, False),
            ('master', False, True, True), ('master', True, False, True),
            ('slave', True, True, True)):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        process = subprocess.Popen([qemu, '-M', f'nikon-z72-{"slave-" if role == "slave" else ""}lab',
            '-accel', 'qtest', '-display', 'none', '-serial', 'none', '-qmp', 'stdio',
            '-global', f'nikon-z72-boot-config.frame-generate={"on" if enabled else "off"}',
            '-global', f'nikon-z72-boot-config.frame-notify={"on" if notifying else "off"}',
            '-global', f'nikon-z72-boot-config.sensor-sample={"on" if sampling else "off"}',
            '-global', 'nikon-z72-boot-config.frame-sync=on',
            '-global', 'nikon-z72-boot-config.transport-link=on',
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

            def data_at(address, length):
                return bytes.fromhex(command(f'read {address:#x} {length:#x}')[2:])

            monitor('qmp_capabilities')
            names = [item['name'] for item in monitor('qom-list', dict(path='/machine/unattached'))
                     if item['type'] == 'child<nikon-z72-boot-config>']
            assert len(names) == 1
            path = '/machine/unattached/' + names[0]

            def property_value(name):
                return monitor('qom-get', dict(path=path, property=name))

            def count():
                return property_value('primary-input-dma-count')

            def tick():
                command('clock_step 33333333')

            first, full, aperture = 0x62700000, 0x68000000, 0x18000000
            height, first_stride, full_stride = 5520, 4224, 12432
            first_length, full_length = first_stride * height, full_stride * height
            for address, value in ((0x20069500, 2), (0x20069504, 2816 << 16),
                    (0x20069508, height << 16), (0x2006950c, 1), (0x20069510, 5472),
                    (0x20069808, first_stride), (0x20069814, 1), (0x20069818, 1),
                    (0x20069840, 1), (0x20069848, 3), (0x20069850, first),
                    (0x20069908, full_stride), (0x20069950, aperture + first_stride)):
                write(address, value)
            for slot in range(4):
                for address, value in ((0x2013d0b0, (full >> 12) + slot * 0x2000),
                        (0x2013d0d0, 0xfe000), (0x2013d0f0, (aperture >> 12) + slot * 0x2000)):
                    write(address + slot * 4, value)
            active = role == 'master' and enabled and sampling
            rows = (0, 63, 64, 0x2000000 // full_stride, height - 1)
            if role == 'master':
                for address, value in ((first - 4, 0x12345678), (first + first_length, 0x87654321),
                        (full - 4, 0x11223344), (full + full_length, 0x55667788)):
                    write(address, value)
                for y in rows:
                    write(full + y * full_stride, 0xa5a5a5a5)
                    write(full + y * full_stride + first_stride - 4, 0x5a5a5a5a)
            command(f'set_irq_in {path} frame-sync-enable 0 1')
            tick()
            assert count() == 0, 'Primary DMA ran before its channel start'
            write(0x20068008, 0x400)
            tick()
            assert count() == int(active)
            assert read(0x20068210) == (0x41 if active and notifying else 0)
            assert property_value('input-dma-count') == 0, 'Primary DMA changed the other input counter'
            if active:
                assert property_value('primary-input-dma-address') == first
                assert property_value('primary-input-second-dma-address') == full + first_stride

                def expected_row(y, start, width, phase):
                    return bytes(255 if ((start + x) // 64 + y // 64 + phase) & 1 else 0
                                 for x in range(0, width, 2) for _ in range(3))

                for y in rows:
                    assert data_at(first + y * first_stride, first_stride) == expected_row(y, 0, 2816, 0)
                    assert data_at(full + y * full_stride + first_stride, 8208) == expected_row(y, 2816, 5472, 0)
                    assert read(full + y * full_stride) == 0xa5a5a5a5, 'Second stripe overwrote the left columns'
                    assert read(full + y * full_stride + first_stride - 4) == 0x5a5a5a5a
                assert read(first - 4) == 0x12345678 and read(first + first_length) == 0x87654321
                assert read(full - 4) == 0x11223344 and read(full + full_length) == 0x55667788
                write(0x20068210, 0xffffffff)
                original = (data_at(first, 256), data_at(full + first_stride, 256))
                # An invalid final mapping must prevent even the first stripe's writes.
                for address, invalid, valid in ((0x2013d0b8, 0x20000, (full >> 12) + 0x4000),
                        (0x2013d0d8, 0, 0xfe000), (0x2013d0b0 + 0x60, 1, 0),
                        (0x20069850, full, first), (0x20069850, 0x20068500, first),
                        (0x20069850, 0xac1c4ff0, first),
                        (0x20069950, 0x10020000, aperture + first_stride),
                        (0x20069854, first, 0), (0x20069500, 6, 2),
                        (0x20069510, 5471, 5472), (0x20069808, 4220, first_stride),
                        (0x20069908, 12416, full_stride), (0x20069818, 0, 1)):
                    write(address, invalid)
                    tick()
                    assert count() == 1 and read(0x20068210) == 0
                    assert (data_at(first, 256), data_at(full + first_stride, 256)) == original, \
                        'Rejected primary descriptor partially wrote a stripe'
                    write(address, valid)
                write(0x2013d0bc, full >> 12)
                write(0x2013d0fc, aperture >> 12)
                tick()
                assert count() == 1, 'Ambiguous remap aliases were accepted'
                write(0x2013d0bc, (full >> 12) + 0x6000)
                write(0x2013d0fc, (aperture >> 12) + 0x6000)
                write(0x2006800c, 0x400)
                tick()
                assert count() == 1, 'Disabled primary input kept generating pixels'
                write(0x20068008, 0x400)
                tick()
                assert count() == 2
                assert data_at(first, first_stride) == expected_row(0, 0, 2816, 1)
                assert data_at(full + first_stride, 8208) == expected_row(0, 2816, 5472, 1)
                # The native allocation and identity sections establish
                # backing through the old initialization-record gaps.
                native_full = 0xbad0a000
                for slot, (target, mask, base) in enumerate((
                        (0xe0000, 0xf8000, 0), (0xe8000, 0xf8000, 0x8000),
                        (0xb8000, 0xf8000, 0x10000), (0xc0000, 0xf8000, 0x18000),
                        (0xc0000, 0xf0000, 0x20000), (0xd0000, 0xf0000, 0x30000),
                        (0xc0000, 0xf0000, 0x40000), (0, 0, 0))):
                    for address, value in ((0x2013d0b0, target),
                            (0x2013d0d0, mask), (0x2013d0f0, base)):
                        write(address + slot * 4, value)
                write(0x20069950, 0x12d0b080)
                write(0x20068210, 0xffffffff)
                native_rows = rows + tuple((boundary - native_full) // full_stride
                    for boundary in (0xbb300000, 0xbc0a0000, 0xbc100000, 0xbd1e0000, 0xbd200000))
                for y in native_rows:
                    write(native_full + y * full_stride, 0xa5a5a5a5)
                write(native_full - 4, 0x13572468)
                write(native_full + full_length, 0x24681357)
                tick()
                assert count() == 3 and read(0x20068210) == (0x41 if notifying else 0)
                assert property_value('primary-input-second-dma-address') == 0xbad0b080
                for y in native_rows:
                    assert data_at(first + y * first_stride, first_stride) == expected_row(y, 0, 2816, 2)
                    assert data_at(native_full + y * full_stride + first_stride, 8208) == expected_row(y, 2816, 5472, 2)
                    assert read(native_full + y * full_stride) == 0xa5a5a5a5
                assert read(native_full - 4) == 0x13572468
                assert read(native_full + full_length) == 0x24681357
            monitor('system_reset')
            assert count() == 0 and property_value('primary-input-dma-address') == 0
            assert property_value('primary-input-second-dma-address') == 0
            command(f'set_irq_in {path} frame-sync-enable 0 1')
            tick()
            assert count() == 0, 'Reset retained a running primary input'
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
    print('PASS primary RAW12 split DMA, remapping, whole-request validation and lifecycle')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    check(parser.parse_args().qemu)
