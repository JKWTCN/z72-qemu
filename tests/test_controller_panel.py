# SPDX-License-Identifier: GPL-2.0-or-later
"""Exercise the shoulder-panel register model through its controller bus."""
import argparse
import socket
from test_controller_gpio import run
from analyze.decode_z72 import require


def check(port):
    def checks(remote, access):
        base = 0x40005400
        wire = socket.create_connection(('127.0.0.1', port), timeout=5)
        stream = wire.makefile('rb')

        def qtest(command):
            wire.sendall((command + '\n').encode())
            line = stream.readline().decode().strip()
            require(line.startswith('OK'), 'Panel signal command failed: ' + line)

        def monitor(command):
            reply = remote.command('qRcmd,' + command.encode().hex())
            while reply.startswith('O') and reply != 'OK':
                reply = remote.receive()
            require(reply == 'OK', 'Panel monitor command failed: ' + reply)

        def property(name):
            reply = remote.command('qRcmd,' +
                (f'qom-get /machine/peripheral/panel {name}').encode().hex())
            text = bytearray()
            while reply.startswith('O') and reply != 'OK':
                text.extend(bytes.fromhex(reply[1:]))
                reply = remote.receive()
            require(reply == 'OK', 'Panel property read failed')
            return text.decode().strip().strip('"')

        def read(address):
            return access(address, opcode=0x104)

        def address(receiving=False):
            access(base, 0x101 | 0x400)
            access(base + 16, 0xc0 | receiving)
            require(read(base + 20) & 2, 'Panel did not acknowledge its address')
            read(base + 24)

        def stop():
            access(base, 0x201)
            access(base + 20, 0)

        def write(reg, values):
            address()
            access(base + 16, reg)
            for value in values:
                access(base + 16, value)
            stop()

        def get(reg, size):
            write(reg, ())
            address(True)
            values = [read(base + 16) for _ in range(size - 1)]
            access(base, 1)
            values.append(read(base + 16))
            stop()
            return values

        identity = get(26, 3)
        require(identity[0] == 0 and identity[1] == 0xc9,
                'Panel identity read did not report the configured class byte')
        require(identity[2] == 0, 'Identity read continued into a nonzero register')
        require(property('id-reads') == '1', 'Identity read counter differs')

        write(0xd6, [5])
        page = get(0xd6, 2)
        require(page[0] == 5, 'Page register did not echo the selected page')
        require(property('page') == '5', 'Page observation property differs')
        require(property('page-writes') == '1', 'Page write counter differs')

        write(0x10, [1, 2, 3])
        values = get(0x10, 4)
        require(values[:3] == [1, 2, 3], 'Auto-increment storage differs')
        require(int(property('writes')) == 4, 'Write counter differs')

        monitor('system_reset')
        image = property('image')
        require(image[0x20:0x24] == '0000', 'Reset kept a data register')
        require(image[0x36:0x38] == 'c9', 'Reset dropped the identity byte')
        require(property('page') == '0', 'Reset kept the page selection')

        reference = ['00'] * 256
        reference[27] = 'c9'
        expected = ''.join(reference)
        require(len(image) == 512 and image == expected,
                'Register image length or identity slot differs')
        print('PASS controller panel: identity, page echo, storage, counters and reset')
    return checks


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    args = parser.parse_args()
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    run(args.qemu, check(port), ('-device',
        'nikon-z72-controller-panel,bus=controller-i2c0,address=96,id=panel',
        '-qtest', f'tcp:127.0.0.1:{port},server=on,wait=off'))
