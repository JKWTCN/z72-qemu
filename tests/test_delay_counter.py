# SPDX-License-Identifier: GPL-2.0-or-later
"""Exercise delayed interrupt delivery without firmware or parameter images."""
import argparse
from pathlib import Path
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
        process = remote = None
        try:
            process, remote = dual_machine(qemu, directory, image, image,
                directory / 'console.txt', icount=None, trace=None)

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

            def acknowledge(thread, channel):
                access(thread, 0x2c010110 + channel * 0x100, 1)
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
                # External clock selection must not acquire an internal clock.
                access(thread, 0x2c011104, 1)
                access(thread, 0x2c011000, 1)
                run(0.15)
                require(access(thread, 0x2c010110) == 0,
                        'Unsupported clock selection fabricated an event')
                access(thread, 0x2c011000, 0)

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
            print('PASS delay counters: deadlines, 12 IRQs, W1C, stop, reset and isolation')
        finally:
            if remote is not None:
                remote.sock.close()
            if process is not None and process.poll() is None:
                process.terminate()
                process.wait(timeout=5)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    check(parser.parse_args().qemu)
