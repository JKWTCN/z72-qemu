# SPDX-License-Identifier: GPL-2.0-or-later
"""Check optional audio output queues, deadlines, interrupts and reset."""
import argparse
import json
import socket
import subprocess
import time


def check(qemu):
    for machine, enabled in (('nikon-z72-lab', True),
                             ('nikon-z72-lab', False),
                             ('nikon-z72-slave-lab', True)):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        process = subprocess.Popen([qemu, '-M', machine, '-accel', 'qtest',
            '-display', 'none', '-serial', 'none', '-qmp', 'stdio',
            '-global', f'nikon-z72-boot-config.audio-output={"on" if enabled else "off"}',
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

            monitor('qmp_capabilities')
            devices = monitor('qom-list', dict(path='/machine/unattached'))
            gic = next(item['name'] for item in devices if item['type'] == 'child<arm_gic>')
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

            command('irq_intercept_in /machine/unattached/' + gic)
            base = 0x2c080000
            if not enabled or machine == 'nikon-z72-slave-lab':
                assert read(base + 0x108) == 0
                continue
            for index in range(2):
                channel = base + 0x100 * (index + 1)
                irq = 167 + index - 32
                control, status = channel + 8, channel + 16
                output, divider = channel + 4, channel + 20
                occupancy = channel + 32
                monitor0, monitor1 = channel + 0x5c, channel + 0x60
                assert read(control) == 0x200
                assert read(status) == 1 << 25
                # Filling the one-word queue removes both polling-ready causes.
                write(output, 0x12345678)
                assert read(occupancy) == 3
                assert not read(control) & 0x200
                assert not read(status) & (1 << 25)
                write(output, 0xdeadbeef)  # Full writes must not replace queued data.
                write(control, 1 << 13)
                command('clock_step 1000000')
                assert read(occupancy) == 3  # Clock disabled.
                write(divider, 1 << 30)
                command('clock_step 1333')
                assert read(occupancy) == 3
                command('clock_step 1')
                assert read(occupancy) == 0
                assert read(monitor0) == 0x5678 and read(monitor1) == 0x1234
                assert not irq_levels.get(irq, False)
                write(control, (1 << 13) | (1 << 11))
                assert irq_levels.get(irq, False)
                write(output, 0xabcd4321)
                assert not irq_levels.get(irq, False)
                write(control, 0)  # Stop cancels consumption, preserves queued data.
                command('clock_step 5000')
                assert read(occupancy) == 3
                write(control, (1 << 13) | (1 << 11))
                command('clock_step 1334')
                assert read(monitor0) == 0x4321 and read(monitor1) == 0xabcd
                assert irq_levels.get(irq, False)
                # Underrun is latched, masked independently, and cleared by zero.
                write(control, 1 << 13)
                command('clock_step 1334')
                assert read(status) & (1 << 17)
                assert not irq_levels.get(irq, False)
                write(status, (1 << 17) | (1 << 19))
                assert irq_levels.get(irq, False)
                write(status, 1 << 19)
                assert not read(status) & (1 << 17)
                assert not irq_levels.get(irq, False)
                # Per-channel reset clears data and disables output.
                write(base, 1 << index)
                assert read(control) == 0x200 and read(occupancy) == 0
                assert read(monitor0) == 0 and read(monitor1) == 0
                write(output, 0xdeadbeef)
                assert read(occupancy) == 0
                write(base, 0)
                write(channel + 12, 1 << 25)
                for n in range(16):
                    write(output, 0x10000 * (n + 1) + n)
                assert read(occupancy) == 0xffffffff
                write(channel + 12, 0)  # Cannot shrink a populated queue.
                assert read(channel + 12) == 1 << 25
                write(control, 2)  # Cannot change packing with queued words.
                assert read(control) & 2 == 0
                write(status, (3 << 30) | (1 << 27))  # Four free slots.
                write(control, 1 << 13)
                write(divider, 1 << 30)
                for n in range(16):
                    command('clock_step 1334')
                    assert read(monitor0) == n and read(monitor1) == n + 1
                    assert irq_levels.get(irq, False) == (n >= 3)
                write(base, 1 << index)
                write(base, 0)
                # Separate lanes consume together; one lane alone is retained.
                write(control, (1 << 13) | 2)
                write(divider, 1 << 30)
                write(channel + 0x30, 0xaaaa1122)
                assert read(status) & (1 << 25)  # Permit the matching lane write.
                command('clock_step 1334')
                assert read(occupancy) == 1 and read(monitor0) == 0
                write(channel + 0x34, 0xbbbb3344)
                command('clock_step 1334')
                assert read(occupancy) == 0
                assert read(monitor0) == 0x1122 and read(monitor1) == 0x3344
                # Derived readiness cannot be manufactured by status writes.
                write(control, 0)
                write(output, 0x55)
                write(status, 1 << 25)
                assert read(status) & (1 << 25) == 0
                # Input activation remains unsupported.
                write(control, 1 << 12)
                assert read(control) & ~0x200 == 0
                write(base, 1 << index)
                write(base, 0)
                # Three nonzero divider fields select a 32 us functional period.
                write(output, 0x77885566)
                write(control, 1 << 13)
                write(divider, (1 << 30) | (2 << 24) | (3 << 18) | (1 << 16))
                command('clock_step 31999')
                assert read(occupancy) == 3
                command('clock_step 1')
                assert read(monitor0) == 0x5566 and read(monitor1) == 0x7788
                write(divider, 0)
                write(output, 0x55)
                command('clock_step 64000')
                assert read(occupancy) == 3
                write(base, 1 << index)
                write(base, 0)
            # Both channels run independently; resetting one leaves the other live.
            for index in range(2):
                channel = base + 0x100 * (index + 1)
                write(channel + 4, 0x12340000 + index)
                write(channel + 8, (1 << 13) | (1 << 11))
                write(channel + 20, 1 << 30)
            write(base, 1)
            command('clock_step 1334')
            assert read(base + 0x15c) == 0
            assert read(base + 0x25c) == 1
            assert not irq_levels.get(167 - 32, False)
            assert irq_levels.get(168 - 32, False)
            monitor('system_reset')
            command('clock_step 5000')
            for index in range(2):
                channel = base + 0x100 * (index + 1)
                assert read(channel + 8) == 0x200
                assert read(channel + 32) == 0
                assert read(channel + 0x5c) == 0
                assert not irq_levels.get(167 + index - 32, False)
            # Audio demand belongs to DMA bank 1, independent of channel number.
            source, sentinel = 0xb1800400, 0xb1800500
            for audio_index, dma_index, status_request in ((0, 5, False), (1, 2, True)):
                monitor('system_reset')
                channel = base + 0x100 * (audio_index + 1)
                selection = 3 if audio_index == 0 else 7
                dma = 0x2c030010 + 16 * dma_index
                other = 0x2c020010
                for n in range(4):
                    write(source + 4 * n, 0x11110001 + n)
                write(sentinel, 0xdeadbeef)
                for bank, address, target in ((0x2c030000, dma, channel + 4),
                                               (0x2c020000, other, sentinel)):
                    write(bank, 0x80000000)
                    write(address + 4, 0x09180000)  # Word writes, fixed destination.
                    write(address + 8, source)
                    write(address + 12, target)
                    write(address, 0x80000003 | (selection << 24))
                command('clock_step 1')
                assert read(dma + 8) == source and read(channel + 32) == 0
                write(channel + 8, 1 << 13)
                command('clock_step 1')
                assert read(dma + 8) == source  # Output alone does not enable DMA.
                if status_request:
                    write(channel + 16, 1 << 29)
                else:
                    write(channel + 8, (1 << 13) | (1 << 15))
                command('clock_step 1')
                assert read(dma + 8) == source + 4
                assert read(channel + 32) == 3
                assert read(dma + 4) >> 16 & 7 == 0  # Full queue applies backpressure.
                assert read(other + 8) == source and read(sentinel) == 0xdeadbeef
                write(channel + 20, 1 << 30)
                command('clock_step 1334')
                assert read(channel + 0x5c) == 1
                assert read(dma + 8) == source + 8
                # Stopping output lowers demand and preserves the pending DMA.
                write(channel + 8, 0)
                command('clock_step 5000')
                assert read(dma + 8) == source + 8
                write(channel + 8, (1 << 13) | (0 if status_request else 1 << 15))
                for _ in range(3):
                    command('clock_step 1334')
                assert read(dma + 4) >> 16 & 7 == 5
                assert read(channel + 0x5c) == 4 and read(channel + 0x60) == 0x1111
                assert irq_levels.get(142 + dma_index - 32, False)
                assert read(other + 8) == source and read(sentinel) == 0xdeadbeef
                write(dma + 4, read(dma + 4) & ~0x1f0000)
                assert not irq_levels.get(142 + dma_index - 32, False)
                write(channel + 8, 0)
                write(channel + 16, 0)
                write(channel + 8, 2)
                write(channel + 8, 2 | (1 << 15))
                assert read(channel + 8) & ~0x200 == 2
                write(channel + 16, 1 << 29)
                assert not read(channel + 16) & (1 << 29)
            # A serial TX request with the same selector cannot wake audio's bank.
            monitor('system_reset')
            for bank in (0x2c020000, 0x2c030000):
                address = bank + 0x10
                write(bank, 0x80000000)
                write(address + 4, 0x09180000)
                write(address + 8, source)
                write(address + 12, sentinel + (4 if bank == 0x2c030000 else 0))
                write(address, 0x83000000)
            write(0x2c0a0010, 15 << 8)
            write(0x2c0a000c, 0x420)
            write(0x2c0a003c, 1)
            command('clock_step 1')
            assert read(0x2c020014) >> 16 & 7 == 5
            assert read(0x2c030018) == source
            assert read(0x2c030010) & 0x80000000
        finally:
            if stream is not None:
                stream.close()
            if wire is not None:
                wire.close()
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=10)
            process.stdin.close()
            process.stdout.close()
            process.stderr.close()
    print('PASS audio output: queues, pacing, IRQs, cancellation, lane pairing, reset and role gates')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    check(parser.parse_args().qemu)
