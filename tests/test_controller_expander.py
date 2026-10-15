# SPDX-License-Identifier: GPL-2.0-or-later
"""Exercise the input expander through its controller bus and external pins."""
import argparse
import socket
from test_controller_gpio import run
from analyze.decode_z72 import require


def check(port):
    def checks(remote, access):
        base = 0x40005400
        wire = socket.create_connection(('127.0.0.1', port), timeout=5)
        stream = wire.makefile('rb')
        irq = None
        def qtest(command):
            nonlocal irq
            wire.sendall((command + '\n').encode())
            while True:
                line = stream.readline().decode().strip()
                require(bool(line), 'Expander signal observation disconnected')
                if line.startswith('IRQ '):
                    irq = line.split()[1] == 'raise'
                else:
                    require(line.startswith('OK'), 'Expander signal command failed: ' + line)
                    return
        def read(address):
            return access(address, opcode=0x104)
        def address(receiving=False, ack=True, pos=False):
            access(base, 0x101 | (0x400 if ack else 0) | (0x800 if pos else 0))
            access(base + 16, 0x44 | receiving)
            require(read(base + 20) & 2, 'Expander did not acknowledge its address')
            read(base + 24)
        def stop(control=1):
            access(base, control | 0x200)
        def write(reg, values, rejected=False):
            address()
            access(base + 16, reg)
            for value in values:
                access(base + 16, value)
            require(bool(read(base + 20) & 0x400) == rejected, 'Expander write acknowledgement differs')
            stop()
            access(base + 20, 0)
        def get(reg, size=3):
            write(reg, ())
            address(True, ack=size != 1, pos=size == 2)
            if size == 1:
                stop()
                return [read(base + 16)]
            if size == 2:
                access(base, 0x801)
                stop(0x801)
                return [read(base + 16), read(base + 16)]
            values = [read(base + 16) for _ in range(size - 3)]
            access(base, 1)
            values.append(read(base + 16))
            stop()
            return values + [read(base + 16), read(base + 16)]
        def levels(value):
            response = remote.command('qRcmd,' +
                ('qom-set /machine/peripheral/keys input-levels ' + str(value)).encode().hex())
            require(response == 'OK', 'Expander external input update failed')
            qtest('readl 0x40005400')
            if irq is not None:
                qtest('set_irq_in /machine/capture-timer capture 0 ' + str(int(irq)))
        try:
            qtest('irq_intercept_out /machine/peripheral/keys')
            access(base + 4, 25)
            require(get(0) == [255] * 3 and get(12) == [255] * 3,
                    'Expander input or direction reset differs')
            write(8, (1, 2, 4))
            require(get(0) == [254, 253, 251] and get(0x6c) == [255] * 3,
                    'Expander polarity changed physical input status')
            write(0, (0,), rejected=True)
            require(get(0) == [254, 253, 251], 'Input write changed externally driven pins')
            write(8, (0, 0, 0))
            write(4, (0, 255, 255))
            write(12, (254, 255, 255))
            require(get(0) == [254, 255, 255], 'Output direction did not select the output latch')
            write(12, (255, 255, 255))
            get(0)
            write(0x54, (254, 255, 255))
            capture = 0x40000400
            access(capture + 0x18, 1)
            access(capture + 0x20, 3)
            access(capture + 0x28, 0xffff)
            access(capture + 0x24, 1000)
            access(capture + 0x0c, 2)
            qtest('set_irq_in /machine/capture-timer capture 0 1')
            access(capture, 1)
            before = read(capture + 0x24)
            levels(0xfffffe)
            require(irq is False and get(0x58) == [1, 0, 0], 'Input change did not assert active-low interrupt')
            require(read(capture + 0x10) & 2 and read(0xe000e200) & (1 << 29),
                    'Expander falling interrupt did not reach timer capture and IRQ29')
            value = read(capture + 0x34)
            require(before <= value <= read(capture + 0x24) and not read(capture + 0x10) & 2,
                    'Capture value or captured-register acknowledgement differs')
            access(capture + 0x34, 0)
            require(read(capture + 0x34) == value, 'Input capture register accepted a software value')
            access(capture, 0)
            require(get(0x6c, 1) == [254] and get(0x58, 1) == [1],
                    'Input status read acknowledged its pending interrupt')
            require(get(0, 1) == [254] and get(0x58, 1) == [0],
                    'Input read did not acknowledge the corresponding port')
            qtest('readl 0x40005400')
            require(irq is True, 'Input acknowledgement did not release interrupt')
            levels(0xffffff)
            get(0)
            write(0x48, (1, 0, 0))
            levels(0xfffffe)
            levels(0xffffff)
            require(get(0x6c, 1) == [255] and get(0, 1) == [254] and get(0, 1) == [255],
                    'Input latch lost a pulse before its input register was read')
            write(0x48, (0, 0, 0))
            write(0x60, (2,))
            levels(0xfffffe)
            levels(0xffffff)
            require(get(0x58, 1) == [1], 'Falling-edge interrupt did not retain a completed pulse')
            write(0x68, (1,))
            require(get(0x58, 1) == [0], 'Individual interrupt clear failed')
            write(0x40, (1, 2, 3, 4, 5, 6))
            require(get(0x44, 6) == [5, 6, 1, 2, 3, 4], 'Six-register group pointer did not wrap')
            write(0x8c, (0xa1, 0xb2, 0xc3, 0xd4))
            require(get(0x0c) == [0xa1, 0xb2, 0xc3] and get(0x40, 1) == [0xd4],
                    'Auto-increment did not skip reserved register addresses')
            write(0x03, (), rejected=True)
            write(0x74, (1,), rejected=True)
            levels(0xfffffe)
            require(remote.command('qRcmd,' + 'system_reset'.encode().hex()) == 'OK',
                    'Expander reset failed')
            require(get(0) == [254, 255, 255] and get(12) == [255] * 3 and get(0x58) == [0] * 3,
                    'Reset lost physical levels or retained register and interrupt state')
            access(capture + 0x18, 0x201)
            access(capture + 0x20, 0x31)
            access(capture + 0x28, 0xffff)
            access(capture + 0x24, 1000)
            qtest('set_irq_in /machine/capture-timer capture 0 0')
            require(read(capture + 0x10) == 0, 'Stopped counter generated capture')
            access(capture, 1)
            qtest('set_irq_in /machine/capture-timer capture 0 1')
            require(read(capture + 0x10) == 2, 'Rising edge did not select its direct channel')
            qtest('set_irq_in /machine/capture-timer capture 0 0')
            require(read(capture + 0x10) == 6, 'Falling edge did not select its indirect channel')
            qtest('set_irq_in /machine/capture-timer capture 0 1')
            require(read(capture + 0x10) == 0x206, 'Unread capture did not publish overcapture')
            read(capture + 0x34)
            require(read(capture + 0x10) == 0x204, 'Captured read cleared unrelated channel or overcapture')
            read(capture + 0x38)
            access(capture + 0x10, 0)
            access(capture + 0x20, 0xb)
            qtest('set_irq_in /machine/capture-timer capture 0 0')
            require(read(capture + 0x10) == 2, 'Both-edge input missed its falling edge')
            read(capture + 0x34)
            qtest('set_irq_in /machine/capture-timer capture 0 1')
            require(read(capture + 0x10) == 2, 'Both-edge input missed its rising edge')
            access(capture, 0)
        finally:
            stream.close()
            wire.close()
        print('PASS input expander: pins, direction, polarity, IRQ, latch, edge, pointer groups and reset')
    return checks


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    args = parser.parse_args()
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    run(args.qemu, check(port), ('-device',
        'nikon-z72-controller-expander,bus=controller-i2c0,address=34,id=keys',
        '-qtest', f'tcp:127.0.0.1:{port},server=on,wait=off'))
