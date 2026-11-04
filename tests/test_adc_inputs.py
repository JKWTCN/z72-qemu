# SPDX-License-Identifier: GPL-2.0-or-later
"""Check live analog inputs without producing conversions or interrupts."""
import argparse
import json
import socket
import subprocess
import time


def run(qemu):
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    process = subprocess.Popen([qemu, '-M', 'nikon-z72-controller-lab',
        '-accel', 'qtest', '-display', 'none', '-serial', 'none', '-monitor', 'none',
        '-qmp', 'stdio', '-qtest', f'tcp:127.0.0.1:{port},server=on,wait=off',
        '-qtest-log', '/dev/null'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
    wire = stream = None
    try:
        deadline = time.monotonic() + 15
        while wire is None:
            try:
                wire = socket.create_connection(('127.0.0.1', port), timeout=3)
            except OSError:
                if process.poll() is not None:
                    raise RuntimeError(process.stderr.read().decode())
                if time.monotonic() >= deadline:
                    raise
                time.sleep(.05)
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
            return int(reply[1], 0) if len(reply) > 1 else None

        monitor('qmp_capabilities')
        devices = monitor('qom-list', path='/machine/unattached')
        names = [entry['name'] for entry in devices
                 if entry['type'] == 'child<nikon-z72-controller-adc>']
        assert len(names) == 1
        path = '/machine/unattached/' + names[0]

        def drive(channel, value):
            command(f'set_irq_in {path} channel-in {channel} {value}')

        def read(address):
            return command(f'readl {address:#x}')

        def start(channel):
            command(f'writel 0x40012034 {channel}')
            command('writel 0x40012008 0x40000001')

        for channel, value in ((0, 0), (2, 1506), (18, 4095)):
            before = read(0x4001204c)
            drive(channel, value)
            command('clock_step 10000')
            assert read(0x40012000) == 0
            assert read(0x4001204c) == before
            assert monitor('qom-get', path=path, property=f'channel{channel}') == value
            start(channel)
            command('clock_step 1000')
            assert read(0x40012000) & 2
            assert read(0x4001204c) == value
            command('writel 0x40012000 0')

        # Invalid host levels leave the existing source and conversion untouched.
        for value in (-1, 4096):
            drive(2, value)
            assert monitor('qom-get', path=path, property='channel2') == 1506
            assert read(0x40012000) == 0
        # An admitted sample owns its value even if the physical input changes.
        start(2)
        drive(2, 975)
        command('clock_step 1000')
        assert read(0x4001204c) == 1506
        start(2)
        command('clock_step 1000')
        assert read(0x4001204c) == 975
        monitor('system_reset')
        command('clock_step 1')
        assert read(0x40012000) == 0 and read(0x4001204c) == 0
        assert monitor('qom-get', path=path, property='channel2') == 975
        start(2)
        command('clock_step 1000')
        assert read(0x4001204c) == 975
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
    print('PASS live ADC inputs: bounds, passive updates, sample ownership and reset')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    run(parser.parse_args().qemu)
