# SPDX-License-Identifier: GPL-2.0-or-later
"""Observe capture resource bits 37/44 from reset without changing them."""
import re
import struct
import time

from analyze.decode_z72 import require
from tools.web_console import Machine, SYNC_WAIT

WORD = 0xB23F7E28
TARGET_MASK = (1 << (37 - 32)) | (1 << (44 - 32))


class CaptureResourceMachine(Machine):
    def _boot_dance(self):
        remote = self.remote
        self.resource_boot_writes = []
        remote.breakpoint(SYNC_WAIT)
        watch = f'2,{WORD:x},4'
        require(remote.command('Z' + watch) == 'OK', 'Resource write observation rejected')
        deadline = time.monotonic() + 300
        synchronized = False
        observed = 0
        try:
            while time.monotonic() < deadline:
                require(not self.shutdown.is_set(), 'Console stopped during resource observation')
                remote.sock.settimeout(1)
                try:
                    reply = remote.command('vCont;c')
                except TimeoutError:
                    remote.interrupt()
                    continue
                match = re.search(r'thread:([0-9a-f]+);', reply)
                require(match is not None, 'Missing resource observation thread')
                thread = int(match[1], 16)
                remote.select_thread(thread)
                registers = remote.regs()
                pc = remote.get(registers, 'pc')
                if 'watch:' in reply:
                    require(thread in (1, 2), 'Resource word changed outside the master engine')
                    before = int.from_bytes(remote.read(WORD, 4), 'little')
                    record = dict(pc=hex(pc), thread=thread, before=hex(before),
                        registers={name: hex(remote.get(registers, name)) for name in
                                   ('r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'sp', 'lr')},
                        stack_words=[hex(word) for word in struct.unpack('<24I',
                            remote.read(remote.get(registers, 'sp'), 96))])
                    require(remote.command('z' + watch) == 'OK', 'Could not remove resource watch')
                    remote.command(f'vCont;s:{thread:x}')
                    remote.select_thread(thread)
                    after = int.from_bytes(remote.read(WORD, 4), 'little')
                    record['after'] = hex(after)
                    record['target_changes'] = [bit for bit in (37, 44)
                        if (before ^ after) & 1 << (bit - 32)]
                    if record['target_changes']:
                        self.resource_boot_writes.append(record)
                    observed |= after & TARGET_MASK
                    require(remote.command('Z' + watch) == 'OK', 'Could not restore resource watch')
                elif pc == SYNC_WAIT and not synchronized:
                    require(all(remote.get(registers, name) == value for name, value in
                        (('r0', 0xB18A764C), ('r1', 8), ('r3', 50))), 'Unexpected synchronization wait')
                    require(int.from_bytes(remote.read(0x20060040, 4), 'little') & 0x10,
                            'Synchronization input is masked')
                    for level in (1, 0):
                        self._qtest(f'set_irq_in /machine/unattached/{self.config_names[0]} '
                                    f'sync-event 15 {level}')
                    for level in (0, 1):
                        self._qtest(f'set_irq_in /machine/unattached/{self.config_names[0]} '
                                    f'frame-sync-enable 0 {level}')
                    remote.breakpoint(SYNC_WAIT, False)
                    synchronized = True
                else:
                    raise ValueError('Unexpected stop during resource boot observation')
                if synchronized and observed == TARGET_MASK:
                    break
            else:
                raise TimeoutError('Resource writers were not observed before the boot deadline')
        finally:
            remote.sock.settimeout(15)
            remote.command('z' + watch)
            if not synchronized:
                remote.breakpoint(SYNC_WAIT, False)
        require(remote.command('D') == 'OK', 'Could not resume after resource observation')
        remote.sock.close()
        self.remote = None
