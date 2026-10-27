# SPDX-License-Identifier: GPL-2.0-or-later
"""Exercise display status acknowledgement and SPI routing with ARM loads/stores."""
import argparse
from pathlib import Path
import socket
import struct
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import BASE, require
from tools.dual_boot_probe import dual_machine


def check(qemu):
    image = struct.pack('<3I', 0xe5810000, 0xe5912000, 0xeafffffe)
    with tempfile.TemporaryDirectory(prefix='display-output-') as folder:
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

            def signal(line, level):
                wire.sendall((f'set_irq_in /machine/master-display '
                              f'output-event {line} {level}\n').encode())
                require(stream.readline().strip() == b'OK', 'Display signal rejected')

            def access(address, value=None, thread=1):
                remote.select_thread(thread)
                store = value is not None
                remote.set(pc=BASE if store else BASE + 4, cpsr=0xd3,
                           r0=value or 0, r1=address)
                remote.command(f'vCont;s:{thread:x}')
                regs = remote.regs()
                require(remote.get(regs, 'pc') == BASE + (4 if store else 8),
                        'Display register access faulted')
                return remote.get(regs, 'r2')

            def pending(irq, thread=1):
                return bool(access(0x04001200 + irq // 32 * 4, thread=thread) &
                            (1 << (irq % 32)))

            def clear(irq):
                access(0x04001280 + irq // 32 * 4, 1 << (irq % 32))

            for bank, irq in ((0, 112), (1, 111)):
                mask = 0x20141210 + bank * 0x4000
                status = mask + 4
                bit = 0x10001
                # Initialization acknowledgements must not manufacture events.
                access(status, 0xffffffff)
                require(access(status) == 0, 'Software manufactured display status')
                for line in (bank * 32, bank * 32 + 16):
                    signal(line, 1)
                require(access(status) == bit and not pending(irq),
                        'Masked display events were lost or delivered early')
                access(mask, bit)
                require(pending(irq) and not pending(irq, 3),
                        'Display SPI route or engine isolation differs')
                access(status, 1)
                clear(irq)
                require(access(status) == 0x10000 and pending(irq),
                        'Acknowledging one cause lost the other cause')
                access(mask, 0)
                clear(irq)
                require(not pending(irq) and access(status) == 0x10000,
                        'Masking did not lower the line while retaining status')
                access(mask, bit)
                access(status, bit)
                clear(irq)
                signal(bank * 32 + 16, 1)
                require(access(status) == 0 and not pending(irq),
                        'Held input repeated a display event')
                signal(bank * 32 + 16, 0)
                signal(bank * 32 + 16, 1)
                require(access(status) == 0x10000 and pending(irq),
                        'A second display edge was lost')
            require(remote.command('qRcmd,' + 'system_reset'.encode().hex()) == 'OK',
                    'Display reset failed')
            for bank in range(2):
                mask = 0x20141210 + bank * 0x4000
                require(access(mask) == access(mask + 4) == 0,
                        'Reset retained display mask or status')
                signal(bank * 32 + 16, 1)
                require(access(mask + 4) == 0x10000,
                        'Reset retained display input level')
            print('PASS display events: W1C, masks, retained causes, SPI111/112, '
                  'engine isolation, edges and reset', flush=True)
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
