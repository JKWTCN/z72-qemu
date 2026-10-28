# SPDX-License-Identifier: GPL-2.0-or-later
"""Check opt-in input stop responses, isolation and acknowledgement."""
import argparse
import json
import socket
import subprocess
import time


def check(qemu):
    for role, enabled, sampling, automatic in (
            ('master', True, True, True), ('master', False, True, True),
            ('master', True, False, True), ('master', True, True, False),
            ('slave', True, True, True)):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        machine = 'nikon-z72-lab' if role == 'master' else 'nikon-z72-slave-lab'
        process = subprocess.Popen([qemu, '-M', machine, '-accel', 'qtest',
            '-display', 'none', '-serial', 'none', '-qmp', 'stdio',
            '-global', f'nikon-z72-boot-config.input-stop-complete={"on" if enabled else "off"}',
            '-global', f'nikon-z72-boot-config.sensor-sample={"on" if sampling else "off"}',
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

            def monitor(name):
                process.stdin.write(json.dumps(dict(execute=name)).encode() + b'\n')
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
            active = role == 'master' and enabled and sampling and automatic
            for request, bank, bits in ((3, 1, 0x110), (4, 1, 1),
                                        (8, 0, 0x10000000), (0x10, 1, 0x1000),
                                        (0x60, 7, 0x30), (0, 0, 0), (1, 0, 0),
                                        (2, 0, 0), (0x63, 0, 0), (0x10003, 0, 0)):
                for index in range(8):
                    write(0x20068210 + index * 32, 0xffffffff)
                    write(0x20068200 + index * 32, 0)
                write(0x20068060, request)
                # The existing input status profile also reports bit 0 ready.
                assert read(0x20068060) == (request | 1)
                expected = bits if active else 0
                for index in range(8):
                    assert read(0x20068210 + index * 32) == (expected if index == bank else 0)
                status = 0x20068210 + bank * 32
                write(status - 16, 0xffffffff)
                assert read(status) == expected, 'Unmask must retain the cause'
                write(status, 0x80000000)
                assert read(status) == expected, 'Unrelated ACK cleared the cause'
                write(status, bits)
                assert read(status) == 0
                assert all(read(address) == 0 for address in
                           (0x2006807c, 0x20068084, 0x20068140, 0x20068144, 0x20061300))
            write(0x20068060, 3)
            monitor('system_reset')
            assert all(read(0x20068210 + index * 32) == 0 for index in range(8))
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
    print('PASS input stop response profiles')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    check(parser.parse_args().qemu)
