# SPDX-License-Identifier: GPL-2.0-or-later
"""Observe the C 1.70 primary-buffer descriptor source from reset."""
import re
import struct
import time

from analyze.decode_z72 import require
from tools.web_console import Machine, SYNC_WAIT

SOURCE_WORD = 0xb2cbcc0c
SOURCE_VALUE = 0xbad0a000
SOURCE_WRITER = 0x102e5f2a


class CaptureAllocationMachine(Machine):
    def _boot_dance(self):
        remote = self.remote
        self.allocation_boot_writes = []
        remote.breakpoint(SYNC_WAIT)
        watch = f'2,{SOURCE_WORD:x},4'
        require(remote.command('Z' + watch) == 'OK', 'Allocation write observation rejected')
        deadline = time.monotonic() + 240
        synchronized = found = False
        try:
            while time.monotonic() < deadline:
                require(not self.shutdown.is_set(), 'Console stopped during allocation observation')
                remote.sock.settimeout(1)
                try:
                    reply = remote.command('vCont;c')
                except TimeoutError:
                    remote.interrupt()
                    continue
                match = re.search(r'thread:([0-9a-f]+);', reply)
                require(match is not None, 'Missing allocation observation thread')
                thread = int(match[1], 16)
                remote.select_thread(thread)
                registers = remote.regs()
                pc = remote.get(registers, 'pc')
                if 'watch:' in reply:
                    before = int.from_bytes(remote.read(SOURCE_WORD, 4), 'little')
                    sp = remote.get(registers, 'sp')
                    stack = struct.unpack('<32I', remote.read(sp, 128))
                    record = dict(pc=hex(pc), thread=thread, before=hex(before),
                        registers={name: hex(remote.get(registers, name)) for name in
                            ('r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7',
                             'r8', 'r9', 'r10', 'r11', 'r12', 'sp', 'lr')},
                        stack_code_candidates=[dict(offset=hex(index * 4), value=hex(value))
                            for index, value in enumerate(stack) if 0x10020000 <= value < 0x10800000])
                    if pc == SOURCE_WRITER and thread in (1, 2):
                        argument = remote.get(registers, 'r5')
                        require(0xb1800000 <= argument <= 0xb5efffe8,
                                'Allocation constructor argument escaped runtime RAM')
                        record['constructor_arguments'] = {hex(index * 4): hex(value)
                            for index, value in enumerate(struct.unpack('<6I', remote.read(argument, 24)))}
                        profile = stack[0x3c // 4]
                        require(0xb1800000 <= profile <= 0xb5efffea or
                                0x10020000 <= profile <= 0x12400000,
                                f'Allocation profile escaped known memory: {profile:#x}')
                        data = remote.read(profile, 22)
                        record['caller_profile'] = dict(address=hex(profile),
                            words={hex(index * 4): hex(value) for index, value in enumerate(
                                struct.unpack_from('<5I', data))},
                            field_0x14=data[20], field_0x15=data[21])
                    require(remote.command('z' + watch) == 'OK', 'Could not remove allocation watch')
                    remote.command(f'vCont;s:{thread:x}')
                    remote.select_thread(thread)
                    after = int.from_bytes(remote.read(SOURCE_WORD, 4), 'little')
                    record['after'] = hex(after)
                    require(len(self.allocation_boot_writes) < 32, 'Allocation observation budget exceeded')
                    self.allocation_boot_writes.append(record)
                    found = pc == SOURCE_WRITER and thread in (1, 2) and after == SOURCE_VALUE
                    require(remote.command('Z' + watch) == 'OK', 'Could not restore allocation watch')
                elif pc == SYNC_WAIT and not synchronized:
                    require(all(remote.get(registers, name) == value for name, value in
                        (('r0', 0xb18a764c), ('r1', 8), ('r3', 50))), 'Unexpected synchronization wait')
                    require(int.from_bytes(remote.read(0x20060040, 4), 'little') & 0x10,
                            'Synchronization input is masked')
                    for level in (1, 0):
                        self._qtest(f'set_irq_in /machine/unattached/{self.config_names[0]} sync-event 15 {level}')
                    for level in (0, 1):
                        self._qtest(f'set_irq_in /machine/unattached/{self.config_names[0]} frame-sync-enable 0 {level}')
                    remote.breakpoint(SYNC_WAIT, False)
                    synchronized = True
                else:
                    raise ValueError('Unexpected stop during allocation boot observation')
                if synchronized and found:
                    break
            else:
                raise TimeoutError('Primary allocation source was not observed before the boot deadline')
        finally:
            remote.sock.settimeout(15)
            remote.command('z' + watch)
            if not synchronized:
                remote.breakpoint(SYNC_WAIT, False)
        require(remote.command('D') == 'OK', 'Could not resume after allocation observation')
        remote.sock.close()
        self.remote = None
