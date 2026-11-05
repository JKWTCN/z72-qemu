# SPDX-License-Identifier: GPL-2.0-or-later
"""Check optional sampling feedback through real delay capture inputs."""
import argparse
import json
import socket
import subprocess
import time


def check(qemu):
    for machine, enabled, automatic, sampling, outputs in (
            ('nikon-z72-lab', True, True, True, True),
            ('nikon-z72-lab', False, True, True, True),
            ('nikon-z72-slave-lab', True, True, True, True),
            ('nikon-z72-lab', True, False, True, True),
            ('nikon-z72-lab', True, True, False, True),
            ('nikon-z72-lab', True, True, True, False)):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        process = subprocess.Popen([qemu, '-M', machine, '-accel', 'qtest',
            '-display', 'none', '-serial', 'none', '-qmp', 'stdio',
            '-global', f'nikon-z72-boot-config.sampling-feedback={"on" if enabled else "off"}',
            '-global', f'nikon-z72-boot-config.sensor-sample={"on" if sampling else "off"}',
            '-global', f'nikon-z72-boot-config.sampling-output-complete={"on" if outputs else "off"}',
            '-global', f'nikon-z72-boot-config.auto-complete={"on" if automatic else "off"}',
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
            completes = enabled and automatic and sampling and outputs and machine == 'nikon-z72-lab'
            def request(level):
                write(0x0428201c, 0x08000000 | (0x800 if level else 0))

            def arm():
                write(0x2c010004, 1)
                write(0x2c011700, 1)
                write(0x2c011704, 3)
                write(0x2c011708, 0xffffffff)
                write(0x2c011710, 1)
                write(0x2c010700, 6)
                write(0x2c011700, 0)
                write(0x2c011000, 0x40)

            # An unarmed preparation request must not change the polled level.
            request(1)
            command('clock_step 2000000')
            assert read(0x04282028) & 0x1000 == 0
            assert read(0x2c010710) == 0
            request(0)
            arm()
            request(1)
            assert bool(read(0x04282028) & 0x1000) == completes
            command('clock_step 999999')
            assert read(0x2c010710) == 0
            command('clock_step 1')
            assert read(0x2c010710) == (4 if completes else 0)
            assert irq_levels.get(178 - 32, False) == completes
            first = read(0x2c011718)
            assert bool(first) == completes
            write(0x2c010710, 2)
            assert read(0x2c010710) == (4 if completes else 0)
            write(0x2c010710, 4)
            assert not irq_levels.get(178 - 32, False)
            request(1)  # A held output must not retrigger.
            command('clock_step 2000000')
            assert read(0x2c010710) == 0
            assert read(0x2c011718) == first
            # Output 16 completes at two milliseconds through its native gates.
            write(0x2c010700, 0)
            base = 0x20063110
            values = (0xffffffff, 0xffffff, 0xffff, 0xffff3280,
                      2, 0xffffff, 0xffff0000, 0x06000006)
            for offset, value in enumerate(values):
                write(base + offset * 4, value)
            write(0x2006000c, 0x20)
            write(base + 0x20, 1)
            write(0x20060020, 16)
            command('clock_step 1999999')
            assert read(0x2c010710) == 0
            command('clock_step 1')
            assert read(0x2c010710) == (2 if completes else 0)
            assert not irq_levels.get(178 - 32, False)
            write(0x2c010700, 2)
            assert irq_levels.get(178 - 32, False) == completes
            if completes:
                assert read(0x2c011714) > first
            write(0x2c010710, 2)
            command('clock_step 2000000')
            assert read(0x2c010710) == 0
            # Request release, capture stop, alternate mode and board reset
            # cancel pending responses and lower the optional feedback level.
            for action in ('release', 'stop', 'alternate', 'reset'):
                request(0)
                arm()
                write(0x2c010708, 0)
                request(1)
                command('clock_step 500000')
                if action == 'release':
                    request(0)
                elif action == 'stop':
                    write(0x2c011000, 0)
                elif action == 'alternate':
                    write(0x2c010708, 0x20)
                else:
                    monitor('system_reset')
                command('clock_step 2000000')
                assert read(0x04282028) & 0x1000 == 0
                assert read(0x2c010710) == 0
            # The deadline is relative to the request, not to capture arming.
            monitor('system_reset')
            request(1)
            command('clock_step 400000')
            arm()
            command('clock_step 599999')
            assert read(0x2c010710) == 0
            command('clock_step 1')
            assert read(0x2c010710) == (4 if completes else 0)
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
    print('PASS sampling feedback: preparation, capture deadlines, output completion, one-shot, cancellation, reset and role/source gates')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    check(parser.parse_args().qemu)
