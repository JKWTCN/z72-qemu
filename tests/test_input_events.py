# SPDX-License-Identifier: GPL-2.0-or-later
"""Check external input events, interrupt masks and engine isolation."""
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
    with tempfile.TemporaryDirectory(prefix='input-events-') as folder:
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
            devices = re.findall(r'(device\[\d+\]) \(child<nikon-z72-boot-config>\)',
                                 listing.decode())
            devices.sort(key=lambda name: int(re.search(r'\d+', name)[0]))
            require(len(devices) == 2, 'Expected two engine event receivers')

            def signal(role, line, level, name='input-event'):
                command = (f'set_irq_in /machine/unattached/{devices[role]} '
                           f'{name} {line} {level}\n')
                wire.sendall(command.encode())
                require(stream.readline().strip() == b'OK', 'Input event signal failed')

            def store(thread, address, value):
                remote.select_thread(thread)
                remote.set(pc=BASE, cpsr=0xD3, r0=value, r1=address)
                remote.command(f'vCont;s:{thread:x}')
                require(remote.get(remote.regs(), 'pc') == BASE + 4,
                        'Synthetic event register store faulted')

            def read(thread, address):
                remote.select_thread(thread)
                remote.set(pc=BASE + 4, cpsr=0xD3, r1=address)
                remote.command(f'vCont;s:{thread:x}')
                regs = remote.regs()
                require(remote.get(regs, 'pc') == BASE + 8,
                        'Synthetic event register read faulted')
                return remote.get(regs, 'r2')

            def pending(thread, irq):
                return bool(read(thread, 0x04001200 + (irq // 32) * 4) &
                            (1 << (irq % 32)))

            def clear_pending(thread, irq):
                store(thread, 0x04001280 + (irq // 32) * 4, 1 << (irq % 32))

            groups = (94, 94, 95, 96, 96, 97, 97, 98)
            for role, thread, peer in ((0, 1, 3), (1, 3, 1)):
                for bank, irq in enumerate(groups):
                    mask = 0x20068200 + bank * 0x20
                    status = mask + 0x10
                    line = bank * 32 + 31
                    bit = 1 << 31
                    signal(role, line, 1)
                    require(read(thread, status) == bit and not pending(thread, irq),
                            'Masked event was lost or raised an interrupt')
                    store(thread, mask, bit)
                    require(pending(thread, irq) and not pending(peer, irq) and
                            read(peer, status) == 0,
                            'Input interrupt routing or engine isolation differs')
                    store(thread, status, 1)
                    require(read(thread, status) == bit,
                            'Acknowledgement cleared an unrelated status bit')
                    store(thread, mask, 0)
                    clear_pending(thread, irq)
                    require(not pending(thread, irq) and read(thread, status) == bit,
                            'Mask change did not lower the line or retained status incorrectly')
                    store(thread, mask, bit)
                    require(pending(thread, irq), 'Unmask did not deliver the retained event')
                    store(thread, status, bit)
                    clear_pending(thread, irq)
                    signal(role, line, 1)
                    require(read(thread, status) == 0 and not pending(thread, irq),
                            'Unchanged high level manufactured a second edge')
                    signal(role, line, 0)
                    signal(role, line, 1)
                    require(read(thread, status) == bit and pending(thread, irq),
                            'Second rising edge did not deliver an event')
                    signal(role, line, 0)
                    store(thread, status, bit)
                    clear_pending(thread, irq)
                    store(thread, mask, 0)

                # Two status banks share one interrupt and must retain each
                # other's pending cause until both are acknowledged.
                for bank in (0, 1):
                    store(thread, 0x20068200 + bank * 0x20, 1)
                    signal(role, bank * 32, 1)
                store(thread, 0x20068210, 1)
                clear_pending(thread, 94)
                require(pending(thread, 94), 'One bank lowered another bank\'s interrupt')
                store(thread, 0x20068230, 1)
                clear_pending(thread, 94)
                require(not pending(thread, 94), 'Acknowledged shared interrupt stayed asserted')
                for output in (0x2006807C, 0x20068084, 0x20068140, 0x20068144):
                    require(read(thread, output) == 0, 'Status event manufactured sample data')

                for line in range(11 + 32):
                    bank = int(line >= 11)
                    bit = 1 << (line - 11 if bank else line)
                    mask = 0x20060040 if bank else 0x20060034
                    status, irq = mask + 4, 86 + bank
                    store(thread, status, bit)
                    require(read(thread, status) == 0,
                            'Software manufactured a synchronization event')
                    signal(role, line, 1, 'sync-event')
                    require(read(thread, status) == bit and not pending(thread, irq),
                            'Masked synchronization event or interrupt differs')
                    store(thread, mask, bit)
                    require(pending(thread, irq) and not pending(peer, irq) and
                            read(peer, status) == 0,
                            'Synchronization interrupt routing or isolation differs')
                    store(thread, mask, 0)
                    clear_pending(thread, irq)
                    require(read(thread, status) == bit and not pending(thread, irq),
                            'Synchronization masking lost status or retained the interrupt')
                    store(thread, mask, bit)
                    require(pending(thread, irq), 'Synchronization unmask lost the event')
                    store(thread, status, bit ^ 0xffffffff)
                    require(read(thread, status) == bit,
                            'Acknowledgement cleared another synchronization event')
                    store(thread, status, bit)
                    clear_pending(thread, irq)
                    signal(role, line, 1, 'sync-event')
                    require(read(thread, status) == 0 and not pending(thread, irq),
                            'Held synchronization input repeated an event')
                    signal(role, line, 0, 'sync-event')
                    store(thread, mask, 0)

                # Third synchronization bank: the automatic-sample event.
                store(thread, 0x20060050, 1)
                require(read(thread, 0x20060050) == 0,
                        'Software manufactured an automatic-sample event')
                signal(role, 0, 1, 'auto-sample-event')
                require(read(thread, 0x20060050) == 1 and not pending(thread, 88),
                        'Masked automatic-sample event or interrupt differs')
                store(thread, 0x2006004c, 1)
                require(pending(thread, 88) and not pending(peer, 88) and
                        read(peer, 0x20060050) == 0,
                        'Automatic-sample routing or isolation differs')
                store(thread, 0x2006004c, 0)
                clear_pending(thread, 88)
                require(read(thread, 0x20060050) == 1 and not pending(thread, 88),
                        'Automatic-sample masking lost status or retained the interrupt')
                store(thread, 0x2006004c, 1)
                require(pending(thread, 88), 'Automatic-sample unmask lost the event')
                store(thread, 0x20060050, 1)
                require(read(thread, 0x20060050) == 0 and not pending(thread, 88),
                        'Automatic-sample acknowledgement failed')
                clear_pending(thread, 88)
                signal(role, 0, 1, 'auto-sample-event')
                require(read(thread, 0x20060050) == 0,
                        'Held automatic-sample input repeated an event')
                signal(role, 0, 0, 'auto-sample-event')
                store(thread, 0x2006004c, 0)
                # Sampled result window: latched zero, software writes rejected.
                for index in range(5):
                    store(thread, 0x20061300 + index * 4, 0xffffffff)
                    require(read(thread, 0x20061300 + index * 4) == 0,
                            'Result window accepted a software write')

            for role, thread in ((0, 1), (1, 3)):
                store(thread, 0x20060034, 1)
                signal(role, 0, 1, 'sync-event')
                store(thread, 0x20060040, 1)
                signal(role, 11, 1, 'sync-event')
                store(thread, 0x2006004c, 1)
                signal(role, 0, 1, 'auto-sample-event')
            require(remote.command('qRcmd,' + 'system_reset'.encode().hex()) == 'OK',
                    'Input event reset failed')
            for role, thread in ((0, 1), (1, 3)):
                require(read(thread, 0x20060034) == 0 and
                        read(thread, 0x20060038) == 0 and not pending(thread, 86),
                        'Reset retained synchronization status or interrupt')
                store(thread, 0x20060034, 1)
                signal(role, 0, 1, 'sync-event')
                require(read(thread, 0x20060038) == 1 and pending(thread, 86),
                        'Reset retained the synchronization edge detector')
                require(read(thread, 0x20060040) == 0 and
                        read(thread, 0x20060044) == 0 and not pending(thread, 87),
                        'Reset retained synchronization condition status or interrupt')
                store(thread, 0x20060040, 1)
                signal(role, 11, 1, 'sync-event')
                require(read(thread, 0x20060044) == 1 and pending(thread, 87),
                        'Reset retained the synchronization condition edge detector')
                require(read(thread, 0x2006004c) == 0 and
                        read(thread, 0x20060050) == 0 and not pending(thread, 88),
                        'Reset retained automatic-sample status or interrupt')
                store(thread, 0x2006004c, 1)
                signal(role, 0, 1, 'auto-sample-event')
                require(read(thread, 0x20060050) == 1 and pending(thread, 88),
                        'Reset retained the automatic-sample edge detector')
                for bank in range(8):
                    require(read(thread, 0x20068200 + bank * 0x20) == 0 and
                            read(thread, 0x20068210 + bank * 0x20) == 0,
                            'Reset retained event mask or status')
                store(thread, 0x20068200, 1)
                signal(role, 0, 1)
                require(read(thread, 0x20068210) == 1 and pending(thread, 94),
                        'Reset retained the edge detector')
            print('PASS input events: eight banks, 43 sync lines, automatic-sample bank, '
                  'result window, masks, IRQs, reset and isolation', flush=True)
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
