# SPDX-License-Identifier: GPL-2.0-or-later
"""Exercise delayed interrupt delivery without firmware or parameter images."""
import argparse
from pathlib import Path
import re
import socket
import struct
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import BASE, require
from tools.dual_boot_probe import dual_machine


def check(qemu):
    image = struct.pack('<3I', 0xE5810000, 0xE5912000, 0xEAFFFFFE)
    with tempfile.TemporaryDirectory(prefix='delay-counter-') as folder:
        directory = Path(folder)
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        process = remote = wire = stream = None
        try:
            process, remote = dual_machine(qemu, directory, image, image,
                directory / 'console.txt', icount=None, trace=None,
                extra_arguments=('-qtest', f'tcp:127.0.0.1:{port},server=on,wait=off',
                                 '-qtest-log', '/dev/null'))
            wire = socket.create_connection(('127.0.0.1', port), timeout=10)
            stream = wire.makefile('rb')
            reply = remote.command('qRcmd,' + 'qom-list /machine/unattached'.encode().hex())
            listing = bytearray()
            while reply.startswith('O') and reply != 'OK':
                listing.extend(bytes.fromhex(reply[1:]))
                reply = remote.receive()
            devices = re.findall(r'(device\[\d+\]) \(child<nikon-z72-delay>\)', listing.decode())
            devices.sort(key=lambda name: int(re.search(r'\d+', name)[0]))
            require(len(devices) == 2, 'Expected two delay devices')

            def signal(thread, line, level):
                role = 0 if thread == 1 else 1
                wire.sendall((f'set_irq_in /machine/unattached/{devices[role]} '
                              f'capture-event {line} {level}\n').encode())
                require(stream.readline().strip() == b'OK', 'Capture event command failed')

            def access(thread, address, value=None):
                remote.select_thread(thread)
                remote.set(pc=BASE if value is not None else BASE + 4,
                           cpsr=0xD3, r0=value or 0, r1=address)
                remote.command(f'vCont;s:{thread:x}')
                regs = remote.regs()
                require(remote.get(regs, 'pc') ==
                        BASE + (4 if value is not None else 8),
                        'Delay register access faulted')
                return remote.get(regs, 'r2')

            def run(seconds):
                # Park every CPU on the synthetic branch. The virtual clock
                # advances only while the machine runs; wall time bounds it.
                for thread in (1, 2, 3, 4):
                    remote.select_thread(thread)
                    remote.set(pc=BASE + 8, cpsr=0xD3)
                remote.sock.settimeout(seconds)
                try:
                    remote.command('vCont;c')
                    raise AssertionError('Unexpected synthetic execution stop')
                except TimeoutError:
                    remote.sock.settimeout(15)
                    remote.interrupt()

            def pending(thread, channel):
                irq = 172 + channel
                return bool(access(thread, 0x04001200 + irq // 32 * 4) &
                            (1 << (irq % 32)))

            def acknowledge(thread, channel, mask=1):
                access(thread, 0x2c010110 + channel * 0x100, mask)
                irq = 172 + channel
                access(thread, 0x04001280 + irq // 32 * 4, 1 << (irq % 32))

            for thread, peer in ((1, 3), (3, 1)):
                access(thread, 0x2c010004, 1)
                for channel in range(12):
                    a = 0x2c010100 + channel * 0x100
                    b = a + 0x1000
                    access(thread, a, 1)
                    access(thread, b + 8, 0xfffffffe)
                # Load a 100 ms period for every channel, then change the
                # staging word without a load strobe. Existing deadlines
                # must retain the earlier value.
                access(thread, 0x2c011004, 0xffffffff - 4999999)
                access(thread, 0x2c011008, 0xfff)
                access(thread, 0x2c011004, 0)
                access(thread, 0x2c011000, 0xfff)
                for channel in range(12):
                    require(access(thread, 0x2c010110 + channel * 0x100) == 0,
                            'Starting a delay completed it synchronously')
                run(0.01)
                for channel in range(12):
                    require(access(thread, 0x2c010110 + channel * 0x100) == 0,
                            'Delay expired before its programmed interval')
                run(0.15)
                for channel in range(12):
                    status = 0x2c010110 + channel * 0x100
                    require(access(thread, status) == 1 and pending(thread, channel),
                            'Delay did not deliver its channel interrupt')
                    require(access(peer, status) == 0 and not pending(peer, channel),
                            'Delay event leaked into the other engine')
                    access(thread, status, 2)
                    require(access(thread, status) == 1,
                            'W1C cleared an unrelated event')
                access(thread, 0x2c01100c, 1)
                access(thread, 0x04001280 + 172 // 32 * 4, 1 << (172 % 32))
                require(not pending(thread, 0) and access(thread, 0x2c010110) == 1,
                        'Interrupt mask discarded status or retained the line')
                access(thread, 0x2c01100c, 0)
                require(pending(thread, 0), 'Unmask did not report a pending event')
                access(thread, 0x2c011000, 0)

                for channel in range(12):
                    require(access(thread, 0x2c010110 + channel * 0x100) == 1,
                            'Stopping a channel discarded its pending event')
                    acknowledge(thread, channel)
                    require(not pending(thread, channel), 'Acknowledged IRQ stayed high')
                run(0.15)
                for channel in range(12):
                    require(access(thread, 0x2c010110 + channel * 0x100) == 0,
                            'Stopped delay produced a new event')
                # The initial preset is consumed. Restart from the retained
                # count, rather than repeating that short initial interval.
                count = access(thread, 0x2c011a0c)
                access(thread, 0x2c011000, 0x200)
                run(0.15)
                require(access(thread, 0x2c010a10) == 0 and
                        access(thread, 0x2c011a0c) > count,
                        'Restart repeated the preset or failed to count')
                access(thread, 0x2c011000, 0)
                # Divider 49 gives one microsecond per tick. The initial
                # preset is cleared so the 500000 ticks span 500 ms.
                access(thread, 0x2c011100, 1)
                access(thread, 0x2c011104, 49)
                access(thread, 0x2c011108, 499999)
                access(thread, 0x2c011100, 0)
                access(thread, 0x2c011000, 1)
                run(0.01)
                require(access(thread, 0x2c010110) == 0 and
                        0 < access(thread, 0x2c01110c) < 100000,
                        'Prescaler did not slow the counter')
                run(0.6)
                require(access(thread, 0x2c010110) == 1 and pending(thread, 0),
                        'Divided counter did not reach its terminal')
                access(thread, 0x2c011000, 0)
                acknowledge(thread, 0)
                # Bits above the byte field have no established clock meaning.
                access(thread, 0x2c011104, 0x100)
                count = access(thread, 0x2c01110c)
                access(thread, 0x2c011000, 1)
                run(0.15)
                require(access(thread, 0x2c010110) == 0 and
                        access(thread, 0x2c01110c) == count,
                        'Reserved divider bits fabricated a clock')
                access(thread, 0x2c011000, 0)

                # The first five hardware descriptors expose a repetition
                # limit. A one-tick period must stop after one expiration,
                # rather than flooding the original completion callback.
                for channel in range(5):
                    a = 0x2c010100 + channel * 0x100
                    b = a + 0x1000
                    access(thread, b, 1)
                    access(thread, b + 4, 49)
                    access(thread, b + 8, 0)
                    access(thread, b + 0x38, 1)
                    access(thread, b + 0x3c, 1)
                    access(thread, a, 8)  # Only the limit event requests IRQ.
                    access(thread, b, 0)
                access(thread, 0x2c011000, 0x1f)
                run(0.01)
                for channel in range(5):
                    a = 0x2c010100 + channel * 0x100
                    b = a + 0x1000
                    require(access(thread, b + 0x40) == 1 and
                            access(thread, a + 0x10) == 9 and pending(thread, channel),
                            'One-shot count, completion event or IRQ differs')
                    access(thread, b + 0x40, 99)
                    require(access(thread, b + 0x40) == 1,
                            'Software changed the hardware repetition count')
                    acknowledge(thread, channel)
                    require(access(thread, a + 0x10) == 8 and pending(thread, channel),
                            'Terminal acknowledgement cleared the limit event')
                    acknowledge(thread, channel, 8)
                    require(not pending(thread, channel), 'Limit acknowledgement retained IRQ')
                run(0.05)
                for channel in range(5):
                    require(access(thread, 0x2c010110 + channel * 0x100) == 0 and
                            access(thread, 0x2c011140 + channel * 0x100) == 1,
                            'Limited timer restarted after acknowledgement')
                access(thread, 0x2c011000, 0)
                access(thread, 0x2c011500, 1)
                require(access(thread, 0x2c011540) == 0,
                        'Channel reset retained its repetition count')
                access(thread, 0x2c01153c, 2)
                access(thread, 0x2c011500, 0)
                access(thread, 0x2c011000, 0x10)
                run(0.01)
                require(access(thread, 0x2c011540) == 2 and
                        access(thread, 0x2c010510) == 9,
                        'Two-shot timer did not stop at its requested count')
                acknowledge(thread, 4, 9)
                access(thread, 0x2c011000, 0)

                # Only channels 5 and 6 expose two capture latches. Explicit
                # event inputs do not imply physical pins or edge polarity.
                for channel in (5, 6):
                    a = 0x2c010100 + channel * 0x100
                    b = a + 0x1000
                    first_line = (channel - 5) * 2
                    access(thread, b, 1)
                    access(thread, b + 4, 255)
                    access(thread, b + 8, 0xffffffff)
                    access(thread, b + 0x10, 1)
                    access(thread, a, 0)
                    access(thread, b, 0)
                    access(thread, 0x2c011000, 1 << channel)
                    run(0.01)
                    for latch in (0, 1):
                        line = first_line + latch
                        status = 2 << latch
                        captured = b + 0x14 + latch * 4
                        before = access(thread, b + 0xc)
                        signal(thread, line, 1)
                        value = access(thread, captured)
                        after = access(thread, b + 0xc)
                        require(0 < before <= value <= after and access(thread, a + 0x10) == status,
                                'Capture did not latch its independent running count')
                        require(not pending(thread, channel) and access(peer, captured) == 0,
                                'Masked capture raised IRQ or leaked across engines')
                        access(thread, captured, 0xffffffff)
                        require(access(thread, captured) == value, 'Software changed a capture latch')
                        access(thread, a, 6)
                        require(pending(thread, channel), 'Unmask lost captured event')
                        acknowledge(thread, channel, status ^ 6)
                        require(pending(thread, channel), 'Unrelated acknowledgement cleared capture')
                        acknowledge(thread, channel, status)
                        signal(thread, line, 1)
                        require(not pending(thread, channel) and access(thread, captured) == value,
                                'Held event repeated capture or acknowledgement cleared latch')
                        signal(thread, line, 0)
                        require(access(thread, a + 0x10) == 0, 'Falling event assertion captured')
                        access(thread, a, 0)
                    access(thread, b + 0x10, 0)
                    signal(thread, first_line, 1)
                    access(thread, b + 0x10, 1)
                    signal(thread, first_line, 1)
                    require(access(thread, a + 0x10) == 0, 'Capture enable invented an edge')
                    signal(thread, first_line, 0)
                    access(thread, a + 8, 0x20)
                    signal(thread, first_line, 1)
                    require(access(thread, a + 0x10) == 0, 'Unsupported alternate mode captured')
                    signal(thread, first_line, 0)
                    access(thread, a + 8, 0)
                    access(thread, 0x2c011000, 0)
                    signal(thread, first_line, 1)
                    require(access(thread, a + 0x10) == 0, 'Stopped counter captured')
                    signal(thread, first_line, 0)
                    access(thread, b, 1)
                    require(access(thread, b + 0x14) == 0 and access(thread, b + 0x18) == 0,
                            'Channel reset retained capture latches')

            # Channel reset clears the preset and holds the count at zero.
            access(1, 0x2c011000, 0x200)
            access(1, 0x2c011a00, 1)
            require(access(1, 0x2c011a0c) == 0, 'Channel reset retained its count')
            access(1, 0x2c011a00, 0)
            run(0.15)
            require(access(1, 0x2c010a10) == 0, 'Channel reset repeated its old preset')
            access(1, 0x2c011000, 0x100)
            require(remote.command('qRcmd,' + 'system_reset'.encode().hex()) == 'OK',
                    'Machine reset failed')
            for thread in (1, 3):
                require(access(thread, 0x2c010004) == 0 and
                        access(thread, 0x2c011000) == 0,
                        'Reset retained delay enables')
            run(0.15)
            require(access(1, 0x2c010910) == 0, 'Reset left an armed timer running')
            print('PASS delay counters: deadlines, 12 IRQs, repetitions, dual captures, masks, W1C, reset and isolation')
        finally:
            if stream is not None:
                stream.close()
            if wire is not None:
                wire.close()
            if remote is not None:
                remote.sock.close()
            if process is not None and process.poll() is None:
                process.terminate()
                process.wait(timeout=5)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    check(parser.parse_args().qemu)
