# SPDX-License-Identifier: GPL-2.0-or-later
"""Observe the slave compute program loader from reset without changing it."""
import hashlib
import re
import struct
import time

from analyze.decode_z72 import require
from tools.web_console import Machine, SYNC_WAIT

POINTS = {
    0x100535e0: 'compute-init-task',
    0x10054a2a: 'compute-program-prepare',
    0x10054a56: 'compute-program-copy',
    0x10054a5a: 'compute-program-copy-return',
    0x100593a0: 'compute-program-configure',
    0x10054a80: 'compute-program-configure-return',
    0x10053602: 'compute-init-return',
}


class CaptureComputeMachine(Machine):
    def _boot_dance(self):
        remote = self.remote
        self.compute_boot = dict(records=[], initialized=False, synchronized=False)
        armed = set(POINTS) | {SYNC_WAIT}
        for address in armed:
            remote.breakpoint(address)
        deadline = time.monotonic() + 100
        try:
            while time.monotonic() < deadline:
                require(not self.shutdown.is_set(), 'Console stopped during compute observation')
                remote.sock.settimeout(1)
                try:
                    reply = remote.command('vCont;c')
                except TimeoutError:
                    remote.interrupt()
                    continue
                match = re.search(r'thread:([0-9a-f]+);', reply)
                require(match is not None, 'Missing compute observation thread')
                thread = int(match[1], 16)
                remote.select_thread(thread)
                registers = remote.regs()
                pc = remote.get(registers, 'pc')
                require(pc in armed, 'Unexpected compute boot stop')
                if pc == SYNC_WAIT:
                    require(thread <= 2 and all(remote.get(registers, name) == value for name, value in
                        (('r0', 0xb18a764c), ('r1', 8), ('r3', 50))), 'Unexpected synchronization wait')
                    require(int.from_bytes(remote.read(0x20060040, 4), 'little') & 0x10,
                            'Synchronization input is masked')
                    for level in (1, 0):
                        self._qtest(f'set_irq_in /machine/unattached/{self.config_names[0]} '
                                    f'sync-event 15 {level}')
                    for level in (0, 1):
                        self._qtest(f'set_irq_in /machine/unattached/{self.config_names[0]} '
                                    f'frame-sync-enable 0 {level}')
                    self.compute_boot['synchronized'] = True
                    remote.breakpoint(pc, False)
                    armed.remove(pc)
                else:
                    if thread in (3, 4):
                        record = dict(entry=POINTS[pc], pc=hex(pc), thread=thread,
                            registers={name: hex(remote.get(registers, name)) for name in
                                ('r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'sp', 'lr')},
                            memory_channels=[[hex(value) for value in struct.unpack('<11I',
                                remote.read(0x04251010 + channel * 0x30, 44))] for channel in range(4)],
                            core_words=[hex(value) for value in struct.unpack('<16I',
                                remote.read(0x24060000, 64))])
                        if pc == 0x10054a56:
                            source, length = remote.get(registers, 'r2'), remote.get(registers, 'r3')
                            require(source == 0x10834b54 and length == 0x27800,
                                    'Compute program source or length differs')
                            data = b''.join(remote.read(source + offset, min(1024, length - offset))
                                            for offset in range(0, length, 1024))
                            record['source_program'] = dict(address=hex(source), bytes=length,
                                sha256=hashlib.sha256(data).hexdigest())
                        if pc == 0x10054a5a:
                            try:
                                data = b''.join(remote.read(0x80300000 + offset, min(1024, 0x27800 - offset))
                                                for offset in range(0, 0x27800, 1024))
                                record['loaded_program'] = dict(address='0x80300000', bytes=len(data),
                                    sha256=hashlib.sha256(data).hexdigest())
                            except ValueError as error:
                                record['loaded_program_read_error'] = str(error)
                        self.compute_boot['records'].append(record)
                        if pc == 0x10053602:
                            self.compute_boot['initialized'] = True
                    remote.breakpoint(pc, False)
                    remote.command(f'vCont;s:{thread:x}')
                    if thread not in (3, 4):
                        remote.breakpoint(pc)
                    else:
                        armed.remove(pc)
                if self.compute_boot['synchronized'] and self.compute_boot['initialized']:
                    break
            require(self.compute_boot['synchronized'], 'Compute observation missed startup synchronization')
        finally:
            remote.sock.settimeout(15)
            for address in armed:
                remote.breakpoint(address, False)
        require(remote.command('D') == 'OK', 'Could not resume after compute observation')
        remote.sock.close()
        self.remote = None
