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

            irq_levels = {}

            def command(text):
                stream.write(text.encode() + b'\n')
                stream.flush()
                reply = stream.readline().decode().strip().split()
                while reply and reply[0] == 'IRQ':
                    irq_levels[int(reply[2])] = reply[1] == 'raise'
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
            gic = next(item['name'] for item in devices if item['type'] == 'child<arm_gic>')
            command('irq_intercept_in /machine/unattached/' + gic)

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
            write(0x20068200, 0x79)
            start()
            assert read(0x20068200) == 0x79
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
                    tick()
                    assert processed() == 0 and read(0x20380024) == 0, 'Processing ran without image input binding'
                    for address, value in ((0x20380008, 1), (0x20380010, 1),
                                           (0x20380048, 0x05640396), (0x2038030c, 2080),
                                           (0x20380310, 0xb0101000), (0x20380020, 0x1002)):
                        write(address, value)
                    # Image input rejection must preserve output ownership and completion state.
                    for address, invalid, valid in (
                            (0x20380008, 0, 1), (0x20380010, 0, 1),
                            (0x20380048, 0x05640394, 0x05640396),
                            (0x20380300, 1, 0), (0x20380304, 1, 0),
                            (0x20380308, 1, 0), (0x2038030c, 2081, 2080),
                            (0x20380310, 0, 0xb0101000), (0x20380320, 0xb0101000, 0)):
                        write(address, invalid)
                        tick()
                        assert processed() == 0 and read(0x20380024) == 0
                        assert all(read(0xb2001000 + slot * 0x10000 + index * 0x1000) == 0x12345678
                                   for slot in range(4) for index in range(3))
                        write(address, valid)
                    # A rejected third output must not partially write the first two.
                    write(0x20100568, 32)
                    tick()
                    assert processed() == 0 and read(0x20100020) == 0 and read(0x20380024) == 0
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
                        assert read(0x20380024) == 0x1002, 'Image completion not tied to the raster'
                        assert read(0x20380020) == 0x1002 and read(0x203c0024) == 0
                        assert irq_levels.get(99 - 32, False), 'Image completion did not reach IRQ99'
                        assert not irq_levels.get(100 - 32, False), 'Bank0 raster asserted IRQ100'
                        write(0x20380020, 0)
                        assert read(0x20380024) == 0x1002 and not irq_levels.get(99 - 32, False)
                        write(0x20380020, 0x1002)
                        assert irq_levels.get(99 - 32, False), 'Unmasking a latched result did not restore IRQ99'
                        write(0x20380024, 2)
                        assert read(0x20380024) == 0x1000, 'Image status did not clear only written bits'
                        write(0x20380024, 4)
                        assert read(0x20380024) == 0x1000
                        write(0x20380024, 0x1000)
                        assert read(0x20380024) == 0
                        assert not irq_levels.get(99 - 32, False), 'Image acknowledgement left IRQ99 asserted'
                        write(0x203c0024, 0xffffffff)
                        assert read(0x203c0024) == 0, 'Status writes injected a completion'
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
                    assert processed() == 5 and read(0x20100020) == 0 and read(0x20380024) == 0
                    # Native bank0 descriptors: three u16 views and one
                    # experimental packed RAW12 grid. Padding belongs to RAM.
                    def grids():
                        return monitor('qom-get', dict(path=path, property='processing-grid-count'))

                    for channel, control, stride in ((1, 0x20121, 128), (2, 0x10621, 96)):
                        base = 0x20100400 + channel * 0x40
                        for offset, value in ((0, control), (0x10, stride), (0x14, stride),
                                (0x18, 128 if channel == 1 else 0), (0x20, 0x0028003c),
                                (0x28, 0x12000 if channel == 1 else 0),
                                (0x2c, 0x24000 if channel == 1 else 0)):
                            write(base + offset, value)
                    grid_targets = []
                    for slot in range(4):
                        scalar = 0xb3001000 + slot * 0x50000
                        packed = 0xb3201000 + slot * 0x10000
                        write(0x20102200 + (slot * 16 + 1) * 4, scalar)
                        write(0x20102200 + (slot * 16 + 2) * 4, packed)
                        for target, stride, used in (
                                *((scalar + plane * 0x12000, 128, 120) for plane in range(3)),
                                (packed, 96, 90)):
                            grid_targets.append(target)
                            command(f'memset {target:#x} {stride * 40:#x} 0xa5')
                            write(target - 4, 0x11223344)
                            write(target + stride * 40, 0x55667788)
                    write(0x20102100, 0x121)
                    write(0x20102000, 0x121)
                    write(0x20102648, 1)
                    # An invalid final plane, an overlap or a code-cache
                    # destination must reject the entire grid bank.
                    for invalid in (0x20068500, 0xb3001000, 0xbaa01000):
                        for slot in range(4):
                            target = (0xb3001000 + slot * 0x50000
                                      if invalid == 0xb3001000 else invalid)
                            write(0x20102200 + (slot * 16 + 2) * 4, target)
                        tick()
                        assert grids() == 0 and read(0x20100020) == 8
                        assert all(read(target) == 0xa5a5a5a5 for target in grid_targets)
                        write(0x20100020, 8)
                        write(0x20380024, 0x1002)
                    for slot in range(4):
                        write(0x20102200 + (slot * 16 + 2) * 4, 0xb3201000 + slot * 0x10000)
                    for address, invalid, valid in ((0x20102648, 0, 1),
                            (0x20100490, 95, 96), (0x20100460, 0x0028003e, 0x0028003c)):
                        write(address, invalid)
                        tick()
                        assert grids() == 0 and read(0x20100020) == 8
                        assert all(read(target) == 0xa5a5a5a5 for target in grid_targets)
                        write(address, valid)
                        write(0x20100020, 8)
                        write(0x20380024, 0x1002)
                    for expected in range(1, 6):
                        tick()
                        assert grids() == expected and read(0x20100020) == 12, (grids(), expected, hex(read(0x20100020)), processed())
                        frame = count() - 1
                        slot = frame % 4
                        for plane in range(4):
                            stride, used = (128, 120) if plane < 3 else (96, 90)
                            target = (0xb3001000 + slot * 0x50000 + plane * 0x12000
                                      if plane < 3 else 0xb3201000 + slot * 0x10000)
                            for y in (0, 19, 39):
                                sy = 2 + y * (918 - 4) // 40
                                values = []
                                for x in range(0, 60, 1 if plane < 3 else 2):
                                    sx = 2 + x * (1380 - 4) // 60
                                    bright = ((sx // 64) ^ (sy // 64) ^ frame) & 1
                                    values.append((4095 if bright else 0).to_bytes(2, 'little')
                                                  if plane < 3 else bytes([255 if bright else 0]) * 3)
                                row = b''.join(values)
                                for x in range(0, used - 3, 4):
                                    assert read(target + y * stride + x) == int.from_bytes(row[x:x + 4], 'little')
                                if used % 4:
                                    assert command(f'readw {target + y * stride + used - 2:#x}') == int.from_bytes(row[-2:], 'little')
                                assert read(target + y * stride + used) == 0xa5a5a5a5
                            assert read(target - 4) == 0x11223344
                            assert read(target + stride * 40) == 0x55667788
                        write(0x20100020, 12)
                        write(0x20380024, 0x1002)
                    # Native cancellation drains all four channels before
                    # optionally reading a small, output-free scratch input.
                    before_drain, before_grids = processed(), grids()
                    write(0x20380084, 0)
                    write(0x203800f0, 0)
                    for offset in (0x54, 0x60, 0x6c, 0x78):
                        write(0x20380000 + offset, 1)
                    assert read(0x20380024) == 0, 'Unsupported drain prefix completed'
                    write(0x203800f0, 0xfc400)
                    write(0x20380020, 0)
                    for offset in (0x54, 0x60, 0x6c):
                        write(0x20380000 + offset, 1)
                        assert read(0x20380024) == 0, 'Partial drain completed'
                    tick()
                    assert processed() == before_drain and grids() == before_grids
                    write(0x20380078, 1)
                    assert read(0x20380024) == 0x14a0000
                    assert not irq_levels.get(99 - 32, False)
                    write(0x20380020, 0x14a0002)
                    assert irq_levels.get(99 - 32, False)
                    write(0x20380024, 0x20000)
                    assert read(0x20380024) == 0x1480000
                    write(0x20380024, 0x1480000)
                    write(0x20380078, 1)
                    assert read(0x20380024) == 0, 'Repeated drain word completed twice'
                    scratch = 0xb4001000
                    command(f'memset {scratch:#x} 0x280 0x5a')
                    write(scratch - 4, 0x11223344)
                    write(scratch + 0x280, 0x55667788)
                    for offset, value in ((0, 3), (4, 3), (0x10, 1),
                            (0x44, 0), (0x48, 0x14000e), (0x4c, 0), (0x50, 0),
                            (0xbc, 1), (0xc0, 0), (0xc4, 20), (0xc8, 0), (0xcc, 0),
                            (0x120, 0), (0x124, 0), (0x128, 0), (0x12c, 0), (0x130, 0),
                            (0x300, 2), (0x30c, 32), (0x310, scratch),
                            (0x3e8, 2), (0x3ec, scratch), (0x3f0, 32),
                            (0x410, 0), (0x420, 0), (0x580, 1), (0x67c, 0x200)):
                        write(0x20380000 + offset, value)
                    for address, invalid, valid in ((0x20380048, 0x28000e, 0x14000e),
                            (0x2038030c, 64, 32), (0x20380120, 1, 0),
                            (0x203803ec, scratch + 32, scratch)):
                        write(address, invalid)
                        write(0x20380008, 1)
                        assert read(0x20380024) == 0, 'Unsupported scratch profile completed'
                        write(address, valid)
                    for invalid in (0, 0x20068500, 0xb08fff00, 0xfffffff0):
                        write(0x20380310, invalid)
                        write(0x203803ec, invalid)
                        write(0x20380008, 1)
                        assert read(0x20380024) == 0, 'Invalid scratch source completed'
                    write(0x20380310, scratch)
                    write(0x203803ec, scratch)
                    assert read(0x20380024) == 0, 'Scratch completed without a start'
                    write(0x20380008, 1)
                    assert read(0x20380024) == 2 and irq_levels.get(99 - 32, False)
                    write(0x20380024, 2)
                    write(0x20380008, 1)
                    tick()
                    assert read(0x20380024) == 0, 'Scratch input completed twice'
                    assert processed() == before_drain and grids() == before_grids
                    assert read(scratch - 4) == 0x11223344 and read(scratch + 0x280) == 0x55667788
                    assert all(read(scratch + offset) == 0x5a5a5a5a for offset in range(0, 0x280, 4))
                    # Restoring registers alone does not release the drain;
                    # the normal profile needs a fresh input start request.
                    for offset, value in ((0x48, 0x05640396), (0x300, 0),
                                          (0x30c, 2080), (0x310, 0xb0101000)):
                        write(0x20380000 + offset, value)
                    tick()
                    assert processed() == before_drain
                    write(0x20380008, 1)
                    tick()
                    assert processed() == before_drain + 1 and grids() == before_grids + 1, (
                        processed(), before_drain, grids(), before_grids, hex(read(0x20380024)))
                    write(0x20380024, 0x1002)
                    write(0x20100020, 12)
                    write(0x20102100, 0x120)
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
            # Startup grid: the observed bank0 view, then the reselected
            # zero-increment view. This is independent of RAW DMA count.
            def startup_grids():
                return monitor('qom-get', dict(path=path, property='input-grid-count'))

            grid_target = 0xb4001000 if role == 'master' else 0xc3001000
            command(f'memset {grid_target:#x} 0x304 0xa5')
            write(grid_target - 4, 0x11223344)
            for index, value in enumerate((3, 0x50787, 16, 6, 0x1044, 0xc1e)):
                write(0x2006a2bc + index * 4, value)
            for offset, value in ((0x14, 3), (0x18, 1), (0x24, 0), (0x3c, 0),
                    (0x40, 1), (0x44, 0), (0x48, 60), (0x4c, 0),
                    (0x50, grid_target), (0x60, grid_target), (0x80, 0x12000)):
                write(0x2006a500 + offset, value)
            write(0x20068270, 0xffffffff)
            tick()
            assert startup_grids() == 0, 'Startup grid ran before input enable'
            write(0x20068008, 0x10)
            # Reject altered geometry, missing ownership and an unmapped
            # allocation before touching the first destination row.
            for address, invalid, valid in ((0x2006a2d0, 0xd1e, 0xc1e),
                    (0x2006a514, 1, 3), (0x2006a548, 61, 60),
                    (0x2006a560, 0, grid_target), (0x2006a580, 0, 0x12000)):
                write(address, invalid)
                tick()
                assert startup_grids() == 0 and read(0x20068270) == 0
                assert read(grid_target) == 0xa5a5a5a5
                write(address, valid)
            for invalid in (0x20068500, 0xbaa01000):
                write(0x2006a550, invalid)
                write(0x2006a560, invalid)
                tick()
                assert startup_grids() == 0 and read(0x20068270) == 0
                assert read(grid_target) == 0xa5a5a5a5
            write(0x2006a550, grid_target)
            write(0x2006a560, grid_target)
            tick()
            assert startup_grids() == int(active)
            assert read(0x20068270) == (0x80 if active and notifying else 0)
            if active:
                phase = monitor('qom-get', dict(path=path, property='frame-sync-count')) - 1
                assert read(grid_target) == (0xfff if phase & 1 else 0xfff0000)
                assert read(grid_target + 60) == 0xa5a5a5a5
                assert read(grid_target - 4) == 0x11223344
                assert read(grid_target + 768) == 0xa5a5a5a5
            else:
                assert read(grid_target) == 0xa5a5a5a5
            write(0x20068270, 0x80)
            tick()
            assert startup_grids() == int(active) and read(0x20068270) == 0
            write(0x2006a53c, 1)
            tick()
            assert startup_grids() == int(active), 'Bank switch reused the old increment'
            write(0x2006a580, 0)
            tick()
            assert startup_grids() == 2 * int(active)
            assert read(0x20068270) == (0x80 if active and notifying else 0)
            write(0x20068270, 0x80)
            write(0x20068008, 0x10)
            tick()
            assert startup_grids() == 2 * int(active) and read(0x20068270) == 0
            write(0x2006800c, 0x10)
            write(0x20068008, 0x10)
            tick()
            assert startup_grids() == 2 * int(active), 'Restart accepted a second view without the first'
            assert monitor('qom-get', dict(path=path, property='input-grid-address')) == (grid_target if active else 0)
            # A soft disable completes a real running channel once. It must
            # never reuse the hard-stop causes or claim another pixel DMA.
            previous = count()
            for operand, first, second, last in (
                    (1, 0x200, 0, 0), (4, 0x2000, 0, 0), (8, 0x8000, 0, 0),
                    (0x10, 0x80000000, 0, 0), (0x20, 0x8000000, 0, 0),
                    (0x40, 0x20000, 0, 0), (0x80, 0x80000, 0, 0), (0x200, 0, 0x80, 0),
                    (0x400, 0, 8, 0), (0x800, 0, 0x800, 0), (2, 0, 0, 8),
                    (0x600, 0, 0x88, 0), (0x10000, 0, 0, 0)):
                write(0x2006800c, 0xffffffff)
                for bank in range(8):
                    write(0x20068210 + bank * 32, 0xffffffff)
                    write(0x20068200 + bank * 32, 0)
                write(0x20068008, operand)
                assert read(0x20068200) == 0, 'Channel enable changed the interrupt mask'
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
            # Bank1 remains passive. Default-off and slave configurations
            # retain register storage without manufacturing drain causes.
            for bank in (0x203c0000, 0x20380000):
                write(bank + 0x84, 0)
                write(bank + 0xf0, 0xfc400)
                for offset in (0x54, 0x60, 0x6c, 0x78):
                    write(bank + offset, 1)
                    assert read(bank + offset) == 1
                expected = 0x14a0000 if bank == 0x20380000 and active and notifying else 0
                assert read(bank + 0x24) == expected
            write(0x20380020, 0xffffffff)
            write(0x203c0020, 0xffffffff)
            monitor('system_reset')
            assert count() == 0
            assert startup_grids() == 0
            assert monitor('qom-get', dict(path=path, property='input-grid-address')) == 0
            assert monitor('qom-get', dict(path=path, property='processing-dma-count')) == 0
            assert monitor('qom-get', dict(path=path, property='processing-grid-count')) == 0
            assert all(read(address) == 0 for address in (0x20380020, 0x20380024, 0x203c0020, 0x203c0024))
            assert all(read(0x20380000 + offset) == 0 for offset in (8, 0x54, 0x60, 0x6c, 0x78))
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
