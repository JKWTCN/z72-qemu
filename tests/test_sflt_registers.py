# SPDX-License-Identifier: GPL-2.0-or-later
"""Check SFLT cause delivery without inventing processing completion."""
import argparse
import json
import socket
import subprocess
import time


def check(qemu):
    for machine in ('nikon-z72-lab', 'nikon-z72-slave-lab'):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        process = subprocess.Popen([qemu, '-M', machine, '-accel', 'qtest',
            '-display', 'none', '-serial', 'none', '-qmp', 'stdio',
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
            config = next(item['name'] for item in devices
                          if item['type'] == 'child<nikon-z72-boot-config>')
            levels = {}

            def command(text):
                stream.write(text.encode() + b'\n')
                stream.flush()
                reply = stream.readline().decode().strip().split()
                while reply and reply[0] == 'IRQ':
                    levels[int(reply[2])] = reply[1] == 'raise'
                    reply = stream.readline().decode().strip().split()
                assert reply and reply[0] == 'OK', reply
                return int(reply[1], 0) if len(reply) > 1 else None

            def read(offset):
                return command(f'readl {0x20203000 + offset:#x}')

            def write(offset, value):
                command(f'writel {0x20203000 + offset:#x} {value:#x}')

            def cause(bit, level):
                command(f'set_irq_in /machine/unattached/{config} sflt-event {bit} {level}')

            command('irq_intercept_in /machine/unattached/' + gic)
            # Arbitrary payload sentinels: neither configuration nor start may
            # consume a program, change pixels or report completed work.
            for address, value in ((0x10003000, 0x11223344), (0x10004000, 0xaabbccdd)):
                command(f'writel {address:#x} {value:#x}')
            configuration = {0x20: 0x401, 0x44: 1, 0x4c: 0, 0x50: 1,
                             0x60: 0x10003000, 0x70: 0x10004000}
            for offset, value in configuration.items():
                write(offset, value)
            write(4, 1)
            assert all(read(offset) == value for offset, value in configuration.items())
            assert read(0x2c) == 0 and not levels.get(124 - 32, False)
            assert command('readl 0x10003000') == 0x11223344
            assert command('readl 0x10004000') == 0xaabbccdd

            write(0x20, 0)
            cause(0, 1)
            assert read(0x2c) == 1 and not levels.get(124 - 32, False)
            write(0x20, 1)
            assert read(0x2c) == 1 and levels[124 - 32]
            write(0x2c, 0)
            write(0x2c, 0x400)
            assert read(0x2c) == 1 and levels[124 - 32]
            write(0x2c, 1)
            assert read(0x2c) == 0 and not levels[124 - 32]
            cause(0, 1)
            assert read(0x2c) == 0
            cause(0, 0)
            cause(0, 1)
            cause(10, 1)
            assert read(0x2c) == 0x401 and levels[124 - 32]
            write(0x2c, 1)
            assert read(0x2c) == 0x400 and not levels[124 - 32]
            write(0x20, 0x400)
            assert read(0x2c) == 0x400 and levels[124 - 32]
            write(0x2c, 0x400)
            assert read(0x2c) == 0 and not levels[124 - 32]
            assert all(not levels.get(intid - 32, False) for intid in (116, 227, 228, 229))

            monitor('system_reset')
            assert all(read(offset) == 0 for offset in (*configuration, 0, 4, 0x2c))
            cause(10, 1)
            assert read(0x2c) == 0x400 and not levels[124 - 32]
            write(0x20, 0x400)
            assert read(0x2c) == 0x400 and levels[124 - 32]
            monitor('system_reset')
            assert read(0x2c) == 0 and not levels[124 - 32]
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
    print('PASS SFLT: configuration, no completion on start, masked causes, '
          'selective acknowledgement, IRQ 124 and reset on both roles')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    check(parser.parse_args().qemu)
