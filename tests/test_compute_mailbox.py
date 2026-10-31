# SPDX-License-Identifier: GPL-2.0-or-later
"""Check request delivery, recipient-driven acknowledgement and separate results."""
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
                return command(f'readl {0x24061000 + offset:#x}')

            def write(offset, value):
                command(f'writel {0x24061000 + offset:#x} {value:#x}')

            command('irq_intercept_in /machine/unattached/' + gic)

            def send(channel, source, destination, payload, mode=3):
                base = 0x100 + channel * 0x80
                write(base, source)
                write(base + 4, mode)
                write(base + 0x10, destination)
                for index, word in enumerate(payload):
                    write(base + 0x40 + index * 4, word)
                # Configuring a destination does not start delivery.
                assert read(0x88) == 0
                write(base + 8, 1)
                return base

            request = [0, 0x50003000]
            base = send(0, 1, 4, request)
            for unused in range(2):
                assert read(8) == 1 and read(0x88) == base
                assert [read(base + 0x40 + i * 4) for i in range(2)] == request
                assert read(base + 0x18) == 4
                assert read(base + 0x38) == 0 and read(0x80) == 0
                assert not levels.get(227 - 32, False)
                assert not levels.get(228 - 32, False)
                assert not levels.get(229 - 32, False)
            # The receiver clears its own endpoint, as the original result
            # callback does. This acknowledges receipt, without a result job.
            write(base + 0x14, 4)
            assert read(0x88) == 0 and read(base + 0x18) == 0
            assert read(base + 0x38) == 4 and read(0x80) == base
            assert levels[227 - 32] and not levels.get(228 - 32, False)
            assert [read(base + 0x40 + i * 4) for i in range(2)] == request
            write(base + 0x34, 4)
            write(base, 0)
            assert read(0x80) == 0 and not levels[227 - 32]

            # This fixture supplies nine arbitrary words. Their arrival is a
            # separate message, never a calculation synthesized by the device.
            payload = [0x89abcdef, *range(0x21, 0x29)]
            reply = send(7, 4, 2, payload)
            assert read(0x84) == reply and levels[228 - 32]
            assert [read(reply + 0x40 + i * 4) for i in range(9)] == payload
            write(reply + 0x14, 2)
            assert read(0x84) == 0 and not levels[228 - 32]
            assert read(0x88) == reply and read(reply + 0x38) == 2
            assert not levels.get(229 - 32, False)
            write(reply + 0x34, 2)
            write(reply, 0)
            assert read(0x88) == 0 and read(0x900) == 0

            manual = send(3, 1, 4, request, mode=1)
            write(manual + 0x14, 4)
            assert read(0x80) == 0 and read(manual + 0x38) == 0
            write(manual + 0x30, 4)
            assert read(0x80) == manual and levels[227 - 32]
            monitor('system_reset')
            assert all(read(offset) == 0 for offset in
                       (0, 4, 8, 0x80, 0x84, 0x88, 0x900, manual, manual + 0x40))
            assert not levels[227 - 32] and not levels[228 - 32]
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
    print('PASS compute mailbox: recipient notification, delayed automatic ack, '
          'separate nine-word results, explicit ack, IRQ routing and reset')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    check(parser.parse_args().qemu)
