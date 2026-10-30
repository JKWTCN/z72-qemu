# SPDX-License-Identifier: GPL-2.0-or-later
"""Check split RAW12 DMA, peer ownership and device-local address remapping."""
import argparse
import json
import re
import socket
import subprocess
import time


def check(qemu):
    height, first_stride, full_stride = 5520, 4224, 12432
    first_length, full_length = first_stride * height, full_stride * height
    rows = (0, 63, 64, 0x2000000 // full_stride, height - 1)
    peer_guards = {0x88000000 - 4: 0x11223344, 0x88000000 + full_length: 0x55667788,
                   0xbad0a000 - 4: 0x13572468, 0xbad0a000 + full_length: 0x24681357}
    for full in (0x88000000, 0xbad0a000):
        for y in rows:
            peer_guards[full + y * full_stride] = 0xa5a5a5a5
            peer_guards[full + y * full_stride + first_stride - 4] = 0x5a5a5a5a
    for case, (role, enabled, sampling, notifying, paired, linked) in enumerate((
            ('master', True, True, True, True, True), ('master', True, True, False, True, True),
            ('master', False, True, True, True, True), ('master', True, False, True, True, True),
            ('master', True, True, True, True, False), ('master', True, True, True, False, True),
            ('slave', True, True, True, False, True),
            ('master', True, True, True, True, True))):
        synchronized = case == 7
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        machine = 'nikon-z72-dual-lab' if paired else f'nikon-z72-{"slave-" if role == "slave" else ""}lab'
        loaders = []
        if paired:
            for address, value in peer_guards.items():
                loaders += ['-device', f'loader,addr={address:#x},data={value:#x},data-len=4,cpu-num=2']
        process = subprocess.Popen([qemu, '-M', machine, '-smp', '4' if paired else '2',
            '-accel', 'qtest', '-display', 'none', '-serial', 'none', '-qmp', 'stdio',
            '-global', f'nikon-z72-boot-config.frame-generate={"on" if enabled else "off"}',
            '-global', f'nikon-z72-boot-config.frame-notify={"on" if notifying else "off"}',
            '-global', f'nikon-z72-boot-config.sensor-sample={"on" if sampling else "off"}',
            '-global', 'nikon-z72-boot-config.frame-sync=on',
            '-global', 'nikon-z72-boot-config.input-stop-complete=on',
            '-global', f'nikon-z72-boot-config.primary-exposure-sync={"on" if synchronized else "off"}',
            '-global', f'nikon-z72-boot-config.sampling-output-complete={"on" if synchronized else "off"}',
            '-global', f'nikon-z72-boot-config.transport-link={"on" if linked else "off"}',
            '-qtest', f'tcp:127.0.0.1:{port},server=on,wait=off', '-qtest-log', '/dev/null'] + loaders,
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

            def read(address, peer=False):
                if peer:
                    return int.from_bytes(data_at(address, 4, True), 'little')
                return int(command(f'readl {address:#x}'), 0)

            def write(address, value):
                command(f'writel {address:#x} {value:#x}')

            def data_at(address, length, peer=False):
                if peer:
                    output = monitor('human-monitor-command',
                        {'command-line': f'xp /{length}bx {address:#x}', 'cpu-index': 2})
                    data = bytes(int(value, 16) for line in output.splitlines() if ':' in line
                        for value in re.findall(r'0x([0-9a-fA-F]{2})(?=\s|$)', line.split(':', 1)[1]))
                    assert len(data) == length, output[:200]
                    return data
                return bytes.fromhex(command(f'read {address:#x} {length:#x}')[2:])

            monitor('qmp_capabilities')
            names = [item['name'] for item in monitor('qom-list', dict(path='/machine/unattached'))
                     if item['type'] == 'child<nikon-z72-boot-config>']
            assert len(names) == (2 if paired else 1)
            path = next('/machine/unattached/' + name for name in names if
                monitor('qom-get', dict(path='/machine/unattached/' + name,
                    property='master-role')) == (role == 'master'))

            def property_value(name):
                return monitor('qom-get', dict(path=path, property=name))

            def count():
                return property_value('primary-input-dma-count')

            def tick():
                command('clock_step 33333333')

            def exposure():
                write(0x20063130, 1)
                write(0x20060020, 16)
                command('clock_step 1000000')

            # Equal numeric addresses in two engines must remain independent.
            first, full, aperture = 0x88000000, 0x88000000, 0x18000000
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
            active = role == 'master' and enabled and sampling and paired and linked
            write(0x20068200, 0x98)
            write(0x20068260, 0xc0000021)
            if role == 'master':
                for address, value in ((first - 4, 0x12345678), (first + first_length, 0x87654321)):
                    write(address, value)
            command(f'set_irq_in {path} frame-sync-enable 0 1')
            tick()
            assert count() == 0, 'Primary DMA ran before its channel start'
            write(0x20068008, 0x400)
            assert property_value('input-running') == 0x400
            assert read(0x20068200) == 0x98, 'Input enable changed the interrupt mask'
            tick()
            if synchronized:
                # Only configuration boundaries precede the real comparison.
                assert count() == 0 and read(0x20068210) == 0x18
                assert read(0x20068270) == 0x40000021
                assert data_at(first, 256) == bytes(256)
                assert data_at(full + first_stride, 256, True) == bytes(256)
                write(0x20068210, 0xffffffff)
                write(0x20068270, 0xffffffff)
                write(0x2006800c, 0x400)
                assert read(0x20068210) == 0, 'A boundary-only run emitted a frame tail'
                write(0x20068008, 0x400)
                # A 1 ms output-16 deadline, using the recovered 72 MHz format.
                for offset, value in enumerate((0xffffffff, 0xffffff, 0xffff,
                        0xffff1940, 1, 0xffffff, 0xffff0000, 0x06000006)):
                    write(0x20063110 + offset * 4, value)
                write(0x20063130, 1)
                write(0x20060020, 16)
                command('clock_step 1000000')
                assert read(0x20060038) == 0, 'Closed output gate fired'
                write(0x2006000c, 32)
                write(0x20063130, 1)
                write(0x20060020, 16)
                command('clock_step 999999')
                assert count() == 0 and read(0x20060038) == 0
                command('clock_step 1')
                assert read(0x20060038) == 16 and count() == 0
                # Native output reconfiguration must not lose a comparison
                # already observed during this primary input run.
                write(0x20063130, 1)
                tick()
            assert count() == int(active)
            assert read(0x20068210) == (0x59 if active and notifying else 0)
            assert read(0x20068270) == (0x40000021 if active and notifying else 0)
            assert property_value('input-dma-count') == 0, 'Primary DMA changed the other input counter'
            if active:
                assert property_value('primary-input-dma-address') == first
                assert property_value('primary-input-second-dma-address') == full + first_stride

                def expected_row(y, start, width, phase):
                    return bytes(255 if ((start + x) // 64 + y // 64 + phase) & 1 else 0
                                 for x in range(0, width, 2) for _ in range(3))

                for y in rows:
                    assert data_at(first + y * first_stride, first_stride) == expected_row(y, 0, 2816, 0)
                    assert data_at(full + y * full_stride + first_stride, 8208, True) == expected_row(y, 2816, 5472, 0)
                    assert read(full + y * full_stride, True) == 0xa5a5a5a5, 'Second stripe overwrote the left columns'
                    assert read(full + y * full_stride + first_stride - 4, True) == 0x5a5a5a5a
                assert read(first - 4) == 0x12345678 and read(first + first_length) == 0x87654321
                assert read(full - 4, True) == 0x11223344 and read(full + full_length, True) == 0x55667788
                write(0x20068210, 0xffffffff)
                write(0x20068270, 0xffffffff)
                original = (data_at(first, 256), data_at(full + first_stride, 256, True))
                # An invalid final mapping must prevent even the first stripe's writes.
                for address, invalid, valid in ((0x2013d0b8, 0x20000, (full >> 12) + 0x4000),
                        (0x2013d0d8, 0, 0xfe000), (0x2013d0b0 + 0x60, 1, 0),
                        (0x20069850, 0xbaa00000, first), (0x20069850, 0x20068500, first),
                        (0x20069850, 0xac1c4ff0, first),
                        (0x20069950, 0x10020000, aperture + first_stride),
                        (0x20069854, first, 0), (0x20069500, 6, 2),
                        (0x20069510, 5471, 5472), (0x20069808, 4220, first_stride),
                        (0x20069908, 12416, full_stride), (0x20069818, 0, 1)):
                    write(address, invalid)
                    tick()
                    assert count() == 1 and read(0x20068210) == 0
                    assert read(0x20068270) == 0
                    assert (data_at(first, 256), data_at(full + first_stride, 256, True)) == original, \
                        'Rejected primary descriptor partially wrote a stripe'
                    write(address, valid)
                write(0x2013d0bc, full >> 12)
                write(0x2013d0fc, aperture >> 12)
                tick()
                assert count() == 1, 'Ambiguous remap aliases were accepted'
                write(0x2013d0bc, (full >> 12) + 0x6000)
                write(0x2013d0fc, (aperture >> 12) + 0x6000)
                write(0x2006800c, 0x400)
                assert property_value('input-running') == 0
                assert read(0x20068210) == (0x80 if notifying else 0)
                write(0x20068210, 0xffffffff)
                tick()
                assert count() == 1, 'Disabled primary input kept generating pixels'
                # A new run with no successful transfer cannot reuse the old
                # frame's tail, even if its stop interrupt is enabled.
                write(0x20069850, 0)
                write(0x20068008, 0x400)
                tick()
                write(0x2006800c, 0x400)
                assert count() == 1 and read(0x20068210) == 0
                write(0x20069850, first)
                write(0x20068008, 0x400)
                if synchronized:
                    tick()
                    assert count() == 1, 'A new input run reused the old exposure comparison'
                    exposure()
                tick()
                assert count() == 2
                assert read(0x20068210) == (0x59 if notifying else 0)
                assert read(0x20068270) == (0x40000021 if notifying else 0)
                assert data_at(first, first_stride) == expected_row(0, 0, 2816, 1)
                assert data_at(full + first_stride, 8208, True) == expected_row(0, 2816, 5472, 1)
                # Actual full-frame address belongs to peer storage, while
                # the same numeric address holds the sender's execution RAM.
                native_full = 0xbad0a000
                first = 0x62700000
                write(0x20069850, first)
                cache_guard = bytes(range(256))
                command(f'write {native_full:#x} {len(cache_guard):#x} 0x{cache_guard.hex()}')
                for slot, (target, mask, base) in enumerate((
                        (0xe0000, 0xf8000, 0), (0xe8000, 0xf8000, 0x8000),
                        (0xb8000, 0xf8000, 0x10000), (0xc0000, 0xf8000, 0x18000),
                        (0xc0000, 0xf0000, 0x20000), (0xd0000, 0xf0000, 0x30000),
                        (0xc0000, 0xf0000, 0x40000), (0, 0, 0))):
                    for address, value in ((0x2013d0b0, target),
                            (0x2013d0d0, mask), (0x2013d0f0, base)):
                        write(address + slot * 4, value)
                write(0x20069950, 0x12d0b080)
                write(0x20068200, 0)
                write(0x20068260, 0)
                write(0x20068210, 0xffffffff)
                write(0x20068270, 0xffffffff)
                native_rows = rows
                tick()
                assert count() == 3 and read(0x20068210) == (0x41 if notifying else 0)
                assert read(0x20068270) == 0, 'Disabled boundary causes were emitted'
                assert property_value('primary-input-second-dma-address') == native_full + first_stride
                for y in native_rows:
                    assert data_at(first + y * first_stride, first_stride) == expected_row(y, 0, 2816, 2)
                    assert data_at(native_full + y * full_stride + first_stride, 8208, True) == expected_row(y, 2816, 5472, 2)
                    assert read(native_full + y * full_stride, True) == 0xa5a5a5a5
                assert read(native_full - 4, True) == 0x13572468
                assert read(native_full + full_length, True) == 0x24681357
                assert data_at(native_full, 256) == cache_guard, 'Peer DMA overwrote master execution RAM'
                # A late row outside the peer pool rejects both stripes.
                write(0x20069950, 0x14001080)
                write(0x20068210, 0xffffffff)
                original = (data_at(first, 256), data_at(native_full + first_stride, 256, True))
                tick()
                assert count() == 3 and read(0x20068210) == 0
                assert (data_at(first, 256), data_at(native_full + first_stride, 256, True)) == original
                write(0x2006800c, 0x400)
                assert read(0x20068210) == 0, 'Masked primary tail was delivered'
            monitor('system_reset')
            assert property_value('input-running') == 0
            assert count() == 0 and property_value('primary-input-dma-address') == 0
            assert property_value('primary-input-second-dma-address') == 0
            command(f'set_irq_in {path} frame-sync-enable 0 1')
            tick()
            assert count() == 0, 'Reset retained a running primary input'
            write(0x20068200, 0x80)
            write(0x20068008, 0x400)
            write(0x2006800c, 0x400)
            assert read(0x20068210) == 0, 'Reset retained a completed primary frame'
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
    print('PASS primary split DMA, peer ownership, sender code isolation, validation and lifecycle')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    check(parser.parse_args().qemu)
