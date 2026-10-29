# SPDX-License-Identifier: GPL-2.0-or-later
"""Check bounded RAW12 input DMA, frame rotation and stop requests."""
import argparse
import json
import socket
import subprocess
import time


def check(qemu):
    for role, enabled, sampling, notifying, stopping in (
            ('master', True, True, False, True), ('master', True, True, True, True),
            ('master', False, True, True, True), ('master', True, False, True, True),
            ('slave', True, True, True, True), ('master', False, True, False, False)):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        machine = 'nikon-z72-lab' if role == 'master' else 'nikon-z72-slave-lab'
        process = subprocess.Popen([qemu, '-M', machine, '-accel', 'qtest',
            '-display', 'none', '-serial', 'none', '-qmp', 'stdio',
            '-global', f'nikon-z72-boot-config.frame-generate={"on" if enabled else "off"}',
            '-global', f'nikon-z72-boot-config.frame-notify={"on" if notifying else "off"}',
            '-global', f'nikon-z72-boot-config.frame-process={"on" if role == "master" and enabled and sampling and notifying else "off"}',
            '-global', f'nikon-z72-boot-config.sensor-sample={"on" if sampling else "off"}',
            '-global', f'nikon-z72-boot-config.input-stop-complete={"on" if stopping else "off"}',
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
            assert read(0x20068210) == (0x59 if active and notifying else 0)
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
                assert read(0x20068210) == (0x59 if notifying else 0)
                assert all(read(0x20068210 + bank * 32) == 0 for bank in range(1, 8))
                write(0x20068210, 0x59)
                write(0x20068060, 3)
                tick()
                assert count() == 5, 'Stop request left input DMA active'
                assert read(0x20068210) == 0, 'Stopped DMA produced an input cause'
                start()
                tick()
                assert count() == 6
                write(0x20068210, 0x59)
                for address, invalid, valid in ((0x20069514, 7, 6),
                        (0x20069518, 131 << 16, 130 << 16),
                        (0x20069518, (130 << 16) | 1, 130 << 16),
                        (0x20069a08, 192, 208)):
                    write(address, invalid)
                    tick()
                    assert count() == 6, 'Unsupported input configuration wrote a frame'
                    assert read(0x20068210) == 0, 'Rejected frame produced an input cause'
                    write(address, valid)
                for target in (0, 0x20068500, 0xb08fff00, 0xb0900000):
                    if target == 0xb08fff00:
                        write(target, 0x11223344)
                    planes([target] * 4)
                    tick()
                    assert count() == 6, 'Invalid destination accepted'
                    assert read(0x20068210) == 0, 'Invalid destination produced an input cause'
                    assert read(0x20068500) == 0
                    if target == 0xb08fff00:
                        assert read(target) == 0x11223344, 'Rejected frame partially wrote RAM'
                if notifying:
                    # Native stream profile and small, independently checked output rasters.
                    def processed():
                        return monitor('qom-get', dict(path=path, property='processing-dma-count'))

                    planes([0xb0101000] * 4)
                    write(0x20069518, 1380 << 16)
                    write(0x2006951c, 918 << 16)
                    write(0x20069a08, 2080)
                    write(0x20100600, 0x09000201)
                    write(0x20100620, 0x03920560)
                    for slot in range(4):
                        write(0x20102200 + (slot * 16 + 8) * 4, 0x40000000)
                        for index in range(3):
                            target = 0xb2001000 + slot * 0x10000 + index * 0x1000
                            write(0x20102200 + (slot * 16 + index + 3) * 4, target)
                            write(target, 0x12345678)
                            write(target - 4, 0x11223344)
                            write(target + 64, 0x55667788)
                            write(target + 0x100 + 32, 0x99887766)
                    for channel in range(3, 6):
                        base = 0x20100400 + channel * 0x40
                        write(base, 0x09000201)
                        write(base + 0x10, 16)
                        write(base + 0x14, 16)
                        write(base + 0x20, 4 << 16 | 8)
                        write(base + 0x28, 0x100)
                    tick()
                    assert processed() == 0, 'Processing ran before port enable'
                    write(0x20102100, 0x121)
                    tick()
                    assert processed() == 0, 'Processing ran before sequence enable'
                    write(0x20102608, 1)
                    # A rejected third output must not partially write the first two.
                    write(0x20100568, 32)
                    tick()
                    assert processed() == 0 and read(0x20100020) == 0
                    assert all(read(0xb2001000 + slot * 0x10000 + index * 0x1000) == 0x12345678
                               for slot in range(4) for index in range(3))
                    write(0x20100568, 0x100)
                    for slot in range(4):
                        write(0x20102200 + (slot * 16 + 5) * 4, 0x20068500)
                    tick()
                    assert processed() == 0 and read(0x20100020) == 0
                    assert read(0x20068500) == 0
                    for slot in range(4):
                        write(0x20102200 + (slot * 16 + 5) * 4,
                              0xb2003000 + slot * 0x10000)
                    for expected in range(1, 6):
                        tick()
                        assert processed() == expected
                        assert read(0x20100020) == 8, 'Output notification not tied to completed raster'
                        frame = count() - 1
                        slot = frame % 4
                        first = (0x10, 0x10, 0xeb, 0x10, 0x10, 0xeb, 0x10, 0x10)
                        if frame & 1:
                            first = tuple(0xfb - value for value in first)
                        for index in range(3):
                            target = 0xb2001000 + slot * 0x10000 + index * 0x1000
                            assert read(target) == int.from_bytes(bytes(first[:4]), 'little')
                            assert read(target + 4) == int.from_bytes(bytes(first[4:]), 'little')
                            assert read(target + 8) == 0x10101010, 'Row padding changed'
                            assert read(target + 0x100) == 0x80808080
                            assert read(target - 4) == 0x11223344
                            assert read(target + 64) == 0x55667788
                            assert read(target + 0x100 + 32) == 0x99887766
                        write(0x20100020, 8)
                    write(0x20102100, 0x120)
                    tick()
                    assert processed() == 5 and read(0x20100020) == 0
                    # Boundary causes obey their masks and require successful RAW DMA.
                    def clear_input_causes():
                        for bank in (0, 3, 4):
                            write(0x20068210 + bank * 32, 0xffffffff)

                    clear_input_causes()
                    write(0x20068200, 0)
                    write(0x20068260, 0x25)
                    write(0x20068280, 0x180)
                    tick()
                    assert read(0x20068210) == 0x41
                    assert read(0x20068270) == 0x21
                    assert read(0x20068290) == 0x80
                    clear_input_causes()
                    write(0x20068260, 1)
                    write(0x20068280, 0)
                    tick()
                    assert read(0x20068270) == 1 and read(0x20068290) == 0
                    clear_input_causes()
                    planes([0] * 4)
                    previous = count()
                    tick()
                    assert count() == previous
                    assert all(read(0x20068210 + bank * 32) == 0 for bank in (0, 3, 4))
                # Native channel disable is separate from the stop/flush command.
                write(0x20069518, 130 << 16)
                write(0x2006951c, 2 << 16)
                write(0x20069a08, 208)
                planes(targets)
                start()
                previous = count()
                for disabled in (0, 0x400):
                    write(0x2006800c, disabled)
                    tick()
                    previous += 1
                    assert count() == previous, 'Unrelated disable stopped RAW DMA'
                write(0x2006800c, 0x200)
                tick()
                assert count() == previous, 'Channel disable left RAW DMA active'
                start()
                tick()
                previous += 1
                assert count() == previous, 'Channel enable did not restart RAW DMA'
                write(0x2006800c, 0x600)
                tick()
                assert count() == previous, 'Combined disable left RAW DMA active'
            # A soft disable completes a real running channel once. It must
            # never reuse the hard-stop causes or claim another pixel DMA.
            previous = count()
            for operand, first, second, last in (
                    (1, 0x200, 0, 0), (4, 0x2000, 0, 0), (8, 0x8000, 0, 0),
                    (0x10, 0x80000000, 0, 0), (0x20, 0x8020000, 0, 0),
                    (0x40, 0x80000, 0, 0), (0x200, 0, 0x80, 0),
                    (0x400, 0, 8, 0), (0x800, 0, 0x800, 0), (2, 0, 0, 8),
                    (0x600, 0, 0x88, 0), (0x10000, 0, 0, 0)):
                write(0x2006800c, 0xffffffff)
                for bank in range(8):
                    write(0x20068210 + bank * 32, 0xffffffff)
                    write(0x20068200 + bank * 32, 0)
                write(0x20068008, operand)
                write(0x20068200, 0)
                write(0x2006800c, operand)
                expected = role == 'master' and sampling and stopping
                assert read(0x20068210) == (first if expected else 0)
                assert read(0x20068230) == (second if expected else 0)
                assert read(0x200682f0) == (last if expected else 0)
                assert all(read(0x20068210 + bank * 32) == 0 for bank in range(2, 7))
                write(0x20068210, 0xffffffff)
                write(0x20068230, 0xffffffff)
                write(0x200682f0, 0xffffffff)
                write(0x2006800c, operand)
                assert read(0x20068210) == read(0x20068230) == read(0x200682f0) == 0, 'Repeated disable completed twice'
                assert count() == previous, 'Disable fabricated a pixel transfer'
            monitor('system_reset')
            assert count() == 0
            assert monitor('qom-get', dict(path=path, property='processing-dma-count')) == 0
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
    print('PASS RAW12 input DMA and monochrome processing profiles')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    check(parser.parse_args().qemu)
