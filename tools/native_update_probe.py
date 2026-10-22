# SPDX-License-Identifier: GPL-2.0-or-later
"""Run bounded original update directory/member checks on local input files.

File I/O, cache maintenance, runtime memory/string primitives, ASCII flags,
locks, component-version responses and parameter storage are provided by the
host. Original directory collection, candidate enumeration, scanning and
classification run through their return paths; the directory record vector
comes from the host. GetProprietyCheck runs with a synthetic snapshot.
Whole-package control flow uses synthetic boot material and host bulk
primitives, checked separately against original small-input operations.
This probe does not activate menu dispatch, establish real package
acceptance, or program storage. Firmware bytes stay local.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import BASE, SCATTER, crc, digest, require, validate_master
from analyze.upgrade_signature import appended_key, decode, update_digest


class NativeUpdateProbe:
    PARSER_CONTEXT = 0xB25EBFA0
    UPDATE_STATE = 0xB1887C80
    MEMBER_STATE = 0xB25EC3A0
    SCRATCH = 0x51000000
    STACK = 0x500FF000
    STOP = 0x50000000

    def __init__(self, master, data, image_capacity=0x4000000):
        from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
        from unicorn.arm_const import (UC_CPU_ARM_CORTEX_A15, UC_ARM_REG_R0,
                                       UC_ARM_REG_R1, UC_ARM_REG_R2,
                                       UC_ARM_REG_R3, UC_ARM_REG_SP,
                                       UC_ARM_REG_LR, UC_ARM_REG_PC)
        self.regs = (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)
        self.sp, self.lr, self.pc = UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC
        self.u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        self.u.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15)
        for address, size in ((BASE, (len(master) + 4095) & ~4095),
                              (0xB1800000, 0x100000), (0xB25E0000, 0x20000),
                              (0xB23BC000, 0x2000),
                              (0xB20D2000, 0x1000),
                              (0x50000000, 0x100000), (self.SCRATCH, 0x100000)):
            self.u.mem_map(address, size)
        self.u.mem_write(BASE, master)
        self.master = master
        self.u.hook_add(UC_HOOK_CODE, lambda u, *args: u.emu_stop(),
                        begin=self.STOP, end=self.STOP)
        self.executed = []
        for offset in (0x747048, 0x3D645A, 0x37AA82, 0x37AAA6,
                       0x3D9A2A, 0x3D8AE4, 0x37C360, 0x37C236,
                       0x37BC0E, 0x38D340, 0x37AE0E, 0x37D5BC,
                       0x37D4D4, 0x37DAA4, 0x37DB20, 0x3D6938,
                       0x37C638, 0x38FE82, 0x39C310, 0x39C308,
                       0x747092, 0x3D636A, 0x37D3A8, 0x37D71C,
                       0x37D2E8, 0x37D372, 0x37D984, 0x37D6B4,
                       0x37D940, 0x37D922, 0x37AAE4):
            self.u.hook_add(UC_HOOK_CODE,
                            lambda u, address, size, unused: self.executed.append(hex(address - BASE)),
                            begin=BASE + offset, end=BASE + offset)
        self.data, self.position, self.io = data, 0, []
        self.parameter_writes = []
        self.parameter_reads = []
        self.parameters = {}
        self.put_word(self.UPDATE_STATE + 0x40, self.SCRATCH)
        # Explicit synthetic running-image descriptor, not a captured body state.
        self.put_word(0xB25EC0DC + 4, BASE)
        self.put_word(0xB25EC0DC + 0x10, image_capacity)
        # Provide the ASCII flags consumed by the original runtime callers.
        # Locale initialization is outside this bounded execution environment.
        self.put_word(self.SCRATCH + 0x1000, self.SCRATCH + 0x1100)
        # The suffix transform tests digit flags for equality with 0x20.
        flags = bytes(0x20 if 48 <= c <= 57 else 16 if 65 <= c <= 90
                      else 128 if 97 <= c <= 122 else 0 for c in range(256))
        self.u.mem_write(self.SCRATCH + 0x1100, flags)
        self.hooks = {
            0x4B3D90: self.seek, 0x4B3D82: self.read,
            0x340F44: self.copy, 0x340FAC: self.copy,
            0x341034: self.zero, 0x32FA28: self.noop,
            0x32F9EC: self.noop, 0x3802DA: self.upper,
            0x3D7144: self.ctype,
            # Single-thread snapshot reads need no host lock operation.
            0x340F18: self.noop, 0x340F12: self.noop,
            0x4C09FE: self.noop,
            # Peripheral version query and parameter storage are RTOS boundaries.
            0x3BB958: self.component_version, 0xE06CA: self.store_parameter,
            0xE04CE: self.load_parameter,
        }
        for offset, callback in self.hooks.items():
            self.install_hook(offset, callback)

    def install_hook(self, offset, callback):
        from unicorn import UC_HOOK_CODE
        def hook(u, address, size, unused):
            callback(*(u.reg_read(r) for r in self.regs))
            u.reg_write(self.pc, u.reg_read(self.lr))
        self.u.hook_add(UC_HOOK_CODE, hook, begin=BASE + offset, end=BASE + offset)

    def component_version(self, output, *args):
        self.u.mem_write(output, bytes(12))
        self.result(1)

    def store_parameter(self, number, source, length, mode):
        require(length <= 0x100, 'Unexpected parameter write length')
        self.parameters[number] = bytes(self.u.mem_read(source, length))
        self.parameter_writes.append(dict(number=hex(number), length=length, mode=mode))
        self.result(1)

    def load_parameter(self, number, target, length, unused):
        require(number in self.parameters, f'Missing runtime parameter: {number:#x}')
        data = self.parameters[number]
        require(length <= len(data), 'Runtime parameter is shorter than requested')
        self.u.mem_write(target, data[:length])
        self.parameter_reads.append(dict(number=hex(number), length=length))
        self.result(0)

    def put_word(self, address, value):
        self.u.mem_write(address, struct.pack('<I', value))

    def word(self, address):
        return struct.unpack('<I', self.u.mem_read(address, 4))[0]

    def result(self, value):
        self.u.reg_write(self.regs[0], value)

    def noop(self, *args):
        pass

    def copy(self, target, source, size, unused):
        require(size <= 0x4000000, 'Unexpected copy length')
        if size:
            self.u.mem_write(target, bytes(self.u.mem_read(source, size)))
        self.result(target)

    def zero(self, target, size, *args):
        require(size <= 0x100000, 'Unexpected zero length')
        if size:
            self.u.mem_write(target, bytes(size))
        self.result(target)

    def upper(self, value, *args):
        self.result(value - 32 if 97 <= value <= 122 else value)

    def ctype(self, *args):
        self.result(self.SCRATCH + 0x1000)

    def seek(self, handle, offset, whence, tell):
        offset = offset if offset < 0x80000000 else offset - 0x100000000
        require(whence in (0, 1, 2), 'Unexpected seek mode')
        position = (0, self.position, len(self.data))[whence] + offset
        self.io.append(dict(operation='seek', position=position))
        if position < 0:
            self.result(0)
            return
        self.position = position
        self.put_word(tell, position)
        self.result(1)

    def read(self, handle, request, count, actual):
        target, capacity = struct.unpack('<II', self.u.mem_read(request + 4, 8))
        require(count <= capacity and count <= 0x4000000, 'Unexpected read length')
        block = self.data[self.position:self.position + count]
        self.io.append(dict(operation='read', position=self.position,
                            requested=count, actual=len(block)))
        if block:
            self.u.mem_write(target, block)
        self.position += len(block)
        self.put_word(actual, len(block))
        self.result(0x043A0080)

    def call(self, offset, *args, stop_offset=None):
        for register, value in zip(self.regs, args):
            self.u.reg_write(register, value)
        self.u.reg_write(self.sp, self.STACK)
        self.u.reg_write(self.lr, self.STOP | 1)
        stop = BASE + stop_offset if stop_offset is not None else self.STOP
        self.u.emu_start((BASE + offset) | 1, stop,
                         count=2000000, timeout=10000000)
        reached = self.u.reg_read(self.pc)
        require(reached in (stop, self.STOP),
                'Native execution did not return within its budget')
        if reached != self.STOP:
            return None
        require(self.u.reg_read(self.sp) == self.STACK, 'Native stack mismatch')
        return self.u.reg_read(self.regs[0])

    def parser(self):
        returned = self.call(0x38D340, 1, 0x20)
        return dict(returned=returned,
                    encoded_package_flag=self.u.mem_read(self.PARSER_CONTEXT + 8, 1)[0],
                    member_count=struct.unpack('<H', self.u.mem_read(
                        self.PARSER_CONTEXT + 0x2E, 2))[0], io=self.io)

    def member_checks(self):
        returned = self.call(0x37BC0E, 0, 1, stop_offset=0x37C100)
        return dict(returned=returned,
                    reached_version_list_formatting=returned is None,
                    encoded_package_flag=self.u.mem_read(self.PARSER_CONTEXT + 8, 1)[0],
                    member_mask=self.word(self.MEMBER_STATE + 0x78),
                    io=self.io)

    def classify(self):
        returned = self.call(0x37BC0E, 0, 1)
        summary = 0xB25EC7F4 - 0xB8
        return dict(returned=returned, member_mask=self.word(self.MEMBER_STATE + 0x78),
                    version_count=self.word(summary + 8),
                    parameter_writes=self.parameter_writes)

    def cstring(self, address):
        data = bytearray()
        for index in range(256):
            char = self.u.mem_read(address + index, 1)[0]
            if not char:
                return data.decode('ascii')
            data.append(char)
        raise ValueError('Unterminated directory string')

    def directory_record(self, name, long_name):
        require(len(name) <= 12 and len(long_name) <= 255,
                'Directory fixture name exceeds its field')
        record = bytearray(0x220)
        record[:len(name)] = name.encode('ascii')
        wide = long_name.encode('utf-16-le')
        record[14:14 + len(wide)] = wide
        struct.pack_into('<I', record, 0x218, len(self.data))
        return bytes(record)

    def directory_fixture(self, entries, state, failed_roots):
        self.directory_entries = tuple(entries)
        opened = []
        def directory_open(path, output, *args):
            root = self.cstring(path)
            opened.append(root)
            self.directory_cursor = iter(self.directory_entries)
            self.put_word(output, 1)
            self.result(0xFFFFFFFF if root in failed_roots else 0)
        def directory_next(handle, output, *args):
            entry = next(self.directory_cursor, None)
            if entry is None:
                self.result(1)
                return
            self.u.mem_write(output, self.directory_record(*entry))
            self.result(0)
        self.install_hook(0x47D2E6, directory_open)
        self.install_hook(0x47D3DA, directory_next)
        self.install_hook(0x47D3F8, lambda *args: self.result(0))
        # Restore card roots and relative-directory pointers from initialized data.
        roots_source = SCATTER[0] + self.UPDATE_STATE + 0x80 - SCATTER[1]
        self.u.mem_write(self.UPDATE_STATE + 0x80, bytes(self.u.mem_read(roots_source, 16)))
        self.put_word(self.UPDATE_STATE + 0x90, state)
        return opened

    def find_update_name(self, entries, state=0, failed_roots=()):
        opened = self.directory_fixture(entries, state, failed_roots)
        output = 0xB25EC51C
        returned = self.call(0x37C236, BASE + 0x208680C, 4, output)
        short_name = self.cstring(output) if returned else None
        long_name = None
        if returned:
            target = self.SCRATCH + 0x3000
            self.call(0x37C218, target, output)
            long_name = self.cstring(target)
        return dict(returned=returned, selected_short_name=short_name,
                    selected_long_name=long_name,
                    opened_roots=list(opened))

    def file_fixture(self, open_succeeds=True):
        file_paths = []
        def file_init(handle, path, *args):
            file_paths.append(self.cstring(path))
            self.position = 0
            self.result(handle)
        self.install_hook(0x4B3C00, file_init)
        self.install_hook(0x4B3C04, lambda *args: self.result(
            0x043A0080 if open_succeeds else 0))
        self.install_hook(0x4B3C90, lambda *args: self.result(0))
        self.install_hook(0x4E9992, self.noop)
        self.install_hook(0x4E99FA, self.noop)
        return file_paths

    def scan_update(self, entries, open_succeeds=True):
        opened = self.directory_fixture(entries, 0, ())
        file_paths = self.file_fixture(open_succeeds)
        returned = self.call(0x37C360, 0)
        return dict(returned=returned, category=self.u.mem_read(self.UPDATE_STATE, 1)[0],
                    file_length=self.word(self.UPDATE_STATE + 0x64),
                    version_count=self.word(0xB25EC73C + 8),
                    opened_roots=list(opened), opened_files=list(file_paths),
                    executed_entries=list(self.executed))

    def installed_version_fixture(self, master_version='01.70'):
        for number, version in ((0x3800, master_version.encode('ascii')),
                                (0x3801, b'01.30'),
                                (0x3803, b'01.01'), (0x3808, master_version.encode('ascii'))):
            self.parameters[number] = version + bytes(10 - len(version))

    def enumerate_packages(self, entries, directory_index=0, card_state=0):
        require(len(entries) <= 50 and directory_index in (0, 1),
                'Directory fixture exceeds the original enumeration bounds')
        self.directory_fixture(entries, card_state, ())
        file_paths = self.file_fixture()
        self.installed_version_fixture()
        def attributes(path, output, *args):
            self.u.mem_write(output, bytes(1))
            self.result(0x043A0080)
        def scalar(number, *args):
            require(number in (0x2F02, 0x2F03), 'Unexpected card parameter')
            self.result(0)
        self.install_hook(0x4B3E6C, attributes)
        self.install_hook(0x4E6980, lambda *args: self.result(0))
        self.install_hook(0xE0490, scalar)
        records, directories, summary = (self.SCRATCH + offset for offset in (0x10000, 0x20000, 0x30000))
        for index, entry in enumerate(entries):
            self.u.mem_write(records + 0x220 * index, self.directory_record(*entry))
            self.put_word(directories + 4 * index, directory_index)
        self.put_word(self.UPDATE_STATE + 0x44, records)
        self.put_word(self.UPDATE_STATE + 0x48, directories)
        self.put_word(self.UPDATE_STATE + 0x60, len(entries))
        self.call(0x37D71C, 0, summary)
        record = 0xB25EC904 + 13 * 0x1CC
        return dict(record_path=self.cstring(record),
                    record_slot=13, directory_index=directory_index, card_state=card_state,
                    record_package_flag=self.word(record + 0x1C4),
                    record_category=self.u.mem_read(record + 0x1C8, 1)[0],
                    matching_count=self.word(self.UPDATE_STATE + 0x4C),
                    opened_files=list(file_paths), executed_entries=list(self.executed))

    def collect_packages(self, directories, failed_directories=(), mode=0,
                         card_state=0, installed_master_version='01.70'):
        from unicorn import UC_HOOK_CODE
        self.directory_fixture([], card_state, ())
        file_paths = self.file_fixture()
        self.installed_version_fixture(installed_master_version)
        allocations, freed, queries = [], [], []
        next_allocation = self.SCRATCH + 0x80000
        def allocate(size, *args):
            nonlocal next_allocation
            require(next_allocation + size <= self.SCRATCH + 0x100000,
                    'Original directory allocation exceeds the fixture heap')
            address = next_allocation
            next_allocation += (size + 7) & ~7
            allocations.append(address)
            self.result(address)
        def release(address, *args):
            require(address in allocations and address not in freed, 'Unexpected directory buffer release')
            freed.append(address)
        def directory_exists(path, *args):
            name = self.cstring(path)
            queries.append(dict(operation='exists', path=name))
            self.result(int(name in directories))
        def attributes(path, output, *args):
            self.u.mem_write(output, bytes(1))
            self.result(0x043A0080)
        def scalar(number, *args):
            require(number in (0x2F02, 0x2F03), 'Unexpected card parameter')
            self.result(0)
        self.install_hook(0x32FE30, allocate)
        self.install_hook(0x32FE7E, release)
        self.install_hook(0x4B3EF0, directory_exists)
        self.install_hook(0x4B3E6C, attributes)
        self.install_hook(0x4E6980, lambda *args: self.result(0))
        self.install_hook(0xE0490, scalar)
        # No attached-component snapshot is available in this fixture.
        self.install_hook(0x3A541E, lambda *args: self.result(0))
        callback_return = self.SCRATCH + 0x5000
        entry_buffer = self.SCRATCH + 0x7000
        pending = {}
        def deliver_next():
            entry = next(pending['entries'], None)
            if entry is None:
                self.result(0x043A0080)
                self.u.reg_write(self.lr, pending['return_address'])
                self.u.reg_write(self.pc, pending['return_address'])
                return
            self.u.mem_write(entry_buffer, self.directory_record(*entry))
            self.u.reg_write(self.regs[0], entry_buffer)
            self.u.reg_write(self.lr, callback_return | 1)
            self.u.reg_write(self.pc, pending['callback'])
        def enumerate_directory(u, address, size, unused):
            path = self.cstring(u.reg_read(self.regs[0]))
            queries.append(dict(operation='enumerate', path=path))
            pending.update(entries=iter(directories[path]), return_address=u.reg_read(self.lr))
            pending['callback'] = u.reg_read(self.regs[2])
            require(pending['callback'] == BASE + 0x37D6B5, 'Unexpected directory callback')
            if path in failed_directories:
                self.result(0)
                u.reg_write(self.pc, pending['return_address'])
                return
            deliver_next()
        def callback_finished(u, address, size, unused):
            if u.reg_read(self.regs[0]):
                pending['entries'] = iter(())
            deliver_next()
        self.u.hook_add(UC_HOOK_CODE, enumerate_directory,
                        begin=BASE + 0x4B3E92, end=BASE + 0x4B3E92)
        self.u.hook_add(UC_HOOK_CODE, callback_finished,
                        begin=callback_return, end=callback_return)
        returned = self.call(0x37D984, mode, self.SCRATCH + 0x30000)
        record = 0xB25EC904 + 13 * 0x1CC
        collected = self.word(self.UPDATE_STATE + 0x60)
        return dict(returned=returned, requested_mode=mode,
                    stored_mode=self.u.mem_read(self.UPDATE_STATE + 2, 1)[0],
                    summary_head=self.word(self.SCRATCH + 0x30000),
                    collected_count=collected,
                    matching_count=self.word(self.UPDATE_STATE + 0x4C),
                    record_path=self.cstring(record), record_slot=13,
                    record_package_flag=self.word(record + 0x1C4),
                    record_category=self.u.mem_read(record + 0x1C8, 1)[0],
                    collected_directory_indices=(
                        [self.word(allocations[1] + 4 * i) for i in range(collected)]
                        if len(allocations) > 1 else []),
                    allocated_buffers=len(allocations), released_buffers=len(freed),
                    directory_queries=list(queries), opened_files=list(file_paths),
                    executed_entries=list(self.executed))

    def propriety(self, snapshot):
        require(len(snapshot) == 0x50, 'Expected 80-byte runtime snapshot')
        # Original snapshot getter reads this global while holding its lock.
        self.u.mem_write(0xB23BCCF0 + 0xAC, snapshot)
        output = self.SCRATCH + 0x2000
        returned = self.call(0x747048, 0, 0, output)
        return dict(service_return=returned, reason=self.word(output),
                    executed_entries=list(self.executed))

    def select_scanned_package(self):
        collected = self.collect_packages({'A:\\firmware\\': [('Z7_2_0~1.BIN', 'Z7_2_0170.BIN')],
                                           'A:\\': []})
        if not collected['record_path']:
            return dict(collection=collected, selected=False,
                        executed_entries=list(self.executed))
        record = 0xB25EC904 + 13 * 0x1CC
        self.call(0x37DAA4, 13)
        flag = self.call(0x37DB20)
        # Timer setup is an RTOS boundary. Stop at the selected check entry.
        self.install_hook(0x3B3E3E, lambda *args: self.result(0))
        self.install_hook(0x3BC514, lambda *args: self.result(0))
        self.put_word(0xB1887D20 + 0x4C, 0x52000000)
        self.call(0x3D6938, stop_offset=0x37C638)
        return dict(collection=collected, selected=True,
                    record_package_flag=self.word(record + 0x1C4), selector_flag=flag,
                    selected_check_offset=hex(self.u.reg_read(self.pc) - BASE),
                    selected_buffer=hex(self.u.reg_read(self.regs[0])),
                    executed_entries=list(self.executed))

    def whole_package_check(self, boot_material):
        require(len(boot_material) == 8, 'Expected eight synthetic boot bytes')
        selection = self.select_scanned_package()
        require(selection['selected'], 'Package did not reach selection')
        self.u.mem_map(0x10000000, 0x1000)
        self.u.mem_write(0x10000088, boot_material)
        self.u.mem_map(0xB2B42000, 0x1000)
        self.u.mem_map(0x52000000, 0x4000000)
        primitive_calls = []
        def decode_buffer(target, index, length, unused):
            skipped = 0x20 if index == 0 else 0
            payload = bytes(self.u.mem_read(target + skipped, length - skipped))
            self.u.mem_write(target + skipped, decode(self.master, payload, index + skipped))
            primitive_calls.append('decode')
        def sha_update(context, source, length, unused):
            self.pending_digest = hashlib.sha1(bytes(self.u.mem_read(source, length))).digest()
            primitive_calls.append('sha1_update')
        def sha_final(target, context, *args):
            self.u.mem_write(target, self.pending_digest)
            primitive_calls.append('sha1_final')
        def checksum(length, source, *args):
            self.result(crc(bytes(self.u.mem_read(source, length))))
            primitive_calls.append('crc16')
        self.install_hook(0x38D2C2, decode_buffer)
        self.install_hook(0x38FDDE, sha_update)
        self.install_hook(0x38FF06, sha_final)
        self.install_hook(0x39C308, checksum)
        self.install_hook(0x4174E4, self.copy)
        self.install_hook(0x37FB8A, self.noop)
        self.install_hook(0x3BC538, self.noop)
        self.install_hook(0x39099C, self.noop)
        notifications = []
        def event_set(event, mask, *args):
            notifications.append(dict(event=hex(event), mask=hex(mask)))
            self.result(0)
        self.install_hook(0x3410CC, event_set)
        dispatcher_return = self.call(0x3D6938)
        returned = struct.unpack('<H', self.u.mem_read(0xB1887D20 + 2, 2))[0]
        return dict(returned=returned, primitive_calls=primitive_calls,
                    dispatcher_return=dispatcher_return, notifications=notifications,
                    selection=selection, executed_entries=list(self.executed))

    def version_summary_service(self):
        scanned = self.scan_update([('Z7_2_0~1.BIN', 'Z7_2_0170.BIN')])
        require(scanned['returned'] == 0, 'Version fixture requires a classified package')
        # Synthetic installed versions for the parameter-read boundary.
        self.installed_version_fixture()
        output = self.SCRATCH + 0x6000
        self.call(0x3D636A, output)
        count = self.word(output)
        require(count <= 5, 'Unexpected version-list count')
        kinds = [self.u.mem_read(output + 4 + 21 * i, 1)[0] for i in range(count)]
        returned = self.call(0x747092, 0, 0, output + 0x100)
        return dict(version_count=count, kinds=kinds, service_return=returned,
                    reason=self.word(output + 0x100), parameter_reads=self.parameter_reads,
                    installed_versions_are_synthetic=True, executed_entries=list(self.executed))


def propriety_suite(master):
    baseline = bytearray(0x50)
    struct.pack_into('<I', baseline, 0, 1)
    baseline[4] = 1
    cases = [('baseline', {}, 1, 0), ('snapshot_absent', {0: 0}, 3, 1),
             ('source_zero', {4: 0}, 3, 1), ('source_five', {4: 5}, 3, 1),
             ('level_one', {0xB: 1}, 1, 0), ('level_two', {0xB: 2}, 3, 1),
             ('second_level_two', {7: 1, 0x23: 2}, 3, 1),
             ('third_level_two', {7: 2, 0x3B: 2}, 3, 1)]
    cases.extend((f'flag_{offset:x}', {offset: 1}, 3, 1)
                 for offset in (8, 0x20, 0x38))
    results = []
    for label, edits, returned, reason in cases:
        snapshot = bytearray(baseline)
        for offset, value in edits.items():
            snapshot[offset] = value
        result = NativeUpdateProbe(master, b'').propriety(bytes(snapshot))
        require(result['service_return'] == returned and result['reason'] == reason and
                result['executed_entries'][:3] == ['0x747048', '0x3d645a', '0x37aa82'] and
                '0x3d9a2a' in result['executed_entries'],
                'Unexpected propriety result: ' + label)
        results.append(dict(case=label, snapshot_edits={hex(k): v for k, v in edits.items()},
                            **result))
    return dict(scope='Original GetProprietyCheck and snapshot predicates; synthetic runtime snapshot',
                baseline=dict(valid_word=1, source_byte=1, other_bytes=0),
                snapshot_getter_executed=True, locks_and_diagnostic_logger_skipped=True,
                cases=results)


def directory_suite(master):
    entry = ('Z7_2_0~1.BIN', 'Z7_2_0170.BIN')
    wrong = ('Z6_2_0~1.BIN', 'Z6_2_0170.BIN')
    cases = [
        ('root_a', [entry], 0, (), 1, ['A:\\']),
        ('root_b', [entry], 2, (), 1, ['B:\\']),
        ('case_insensitive', [(entry[0].lower(), entry[1])], 0, (), 1, ['A:\\']),
        ('skip_other_model', [wrong, entry], 0, (), 1, ['A:\\']),
        ('other_model_only', [wrong], 0, (), 0, ['A:\\']),
        ('empty_directory', [], 0, (), 0, ['A:\\']),
        ('open_failure_without_fallback', [entry], 0, ('A:\\',), 0, ['A:\\']),
        ('open_failure_with_fallback', [entry], 16, ('A:\\',), 1, ['A:\\', 'B:\\']),
        ('empty_does_not_fallback', [], 16, (), 0, ['A:\\']),
        ('both_roots_fail', [entry], 16, ('A:\\', 'B:\\'), 0, ['A:\\', 'B:\\']),
    ]
    results = []
    for label, entries, state, failed, returned, roots in cases:
        result = NativeUpdateProbe(master, b'').find_update_name(entries, state, failed)
        require(result['returned'] == returned and result['opened_roots'] == roots and
                (not returned or result['selected_long_name'] == entry[1]),
                'Unexpected directory result: ' + label)
        results.append(dict(case=label, directory_entries=entries, state=state,
                            failed_roots=failed, **result))
    return dict(scope='Original 0x37C236 directory scan and 0x37C218 long-name conversion',
                pattern='Z7_2_???.BIN', synthetic_directory_records=True, cases=results)


def scan_suite(master, package, candidate):
    cases = [('stock_package', package, True, 0, 5),
             ('bare_master_as_package', master, True, 3, 0),
             ('file_open_failure', package, False, 3, 0)]
    if candidate is not None:
        cases.append(('local_candidate', candidate, True, 0, 5))
    results = []
    for label, data, can_open, returned, count in cases:
        result = NativeUpdateProbe(master, data).scan_update(
            [('Z7_2_0~1.BIN', 'Z7_2_0170.BIN')], can_open)
        require(result['returned'] == returned and result['version_count'] == count and
                result['category'] == 4 and result['opened_files'] == ['A:\\Z7_2_0170.BIN'] and
                '0x37c360' in result['executed_entries'] and
                (not can_open or '0x37bc0e' in result['executed_entries']),
                'Unexpected scanner result: ' + label)
        results.append(dict(case=label, input_sha256=digest(data), **result))
    return dict(scope='Original 0x37C360 through directory enumeration and classification return',
                file_io_and_component_version_are_host_supplied=True,
                whole_package_integrity_checked=False, cases=results)


def primitive_suite(master):
    probe = NativeUpdateProbe(master, b'')
    probe.u.mem_map(0xB2B42000, 0x1000)
    probe.install_hook(0x39099C, probe.noop)
    buffer, model = probe.SCRATCH + 0x4000, probe.SCRATCH + 0x3000
    probe.u.mem_write(model, b'Z_7_2\0')
    transforms = []
    decoders = []
    for index, size in ((0, 96), (255, 65), (65530, 65)):
        data = bytes((i * 37 + size) & 255 for i in range(size))
        skipped = 32 if index == 0 else 0
        expected = data[:skipped] + decode(master, data[skipped:], index + skipped)
        probe.u.mem_write(buffer, data)
        probe.call(0x38D2C2, buffer, index, size)
        require(bytes(probe.u.mem_read(buffer, size)) == expected,
                'Native decode disagrees with the host primitive')
        decoders.append(dict(index=index, length=size, matched=True))
    for material in (bytes(8), bytes(range(8)), bytes([255]) * 8):
        probe.u.mem_write(buffer, material)
        probe.call(0x39C310, buffer, 8, 0xB4FBFFFF, model)
        require(bytes(probe.u.mem_read(buffer, 8)) == appended_key(material, master),
                'Native suffix transform disagrees with the host formula')
        transforms.append(dict(input_sha256=digest(material), matched=True))
    checks = []
    for size in (1, 55, 56, 64, 65):
        payload = bytes((i * 37 + size) & 255 for i in range(size))
        probe.u.mem_write(buffer, payload + bytes(16))
        require(probe.call(0x39C308, size, buffer) == crc(payload),
                'Native CRC disagrees with the host primitive')
        expected = hashlib.sha1(payload + appended_key(bytes(8), master)).digest()
        for corrupt, wanted in ((False, 1), (True, 0)):
            comparison = bytes([expected[0] ^ 1]) + expected[1:] if corrupt else expected
            context = (struct.pack('<III', buffer, size, BASE + 0x37C635) + bytes(8) +
                       struct.pack('<I', 0x44B) + b'Z_7_2\0\0\0' + comparison)
            probe.u.mem_write(0xB2B422C8, context)
            require(probe.call(0x38FE82) == wanted,
                    'Native SHA-1 comparison disagrees with the host primitive')
            checks.append(dict(length=size, changed_expected_digest=corrupt, returned=wanted))
    return dict(scope='Unaccelerated original decode, suffix transform, CRC and SHA-1 checker on synthetic inputs',
                decode_checks=decoders, transforms=transforms,
                sha1_checks=checks, crc_lengths=[1, 55, 56, 64, 65])


def enumeration_suite(master, package, candidate):
    entry = ('Z7_2_0~1.BIN', 'Z7_2_0170.BIN')
    cases = [('subdirectory_a', package, [entry], 0, 0, 'A:\\firmware\\Z7_2_0170.BIN', 1),
             ('root_a', package, [entry], 1, 0, 'A:\\Z7_2_0170.BIN', 1),
             ('subdirectory_b', package, [entry], 0, 2, 'B:\\firmware\\Z7_2_0170.BIN', 1),
             ('bare_member', master, [entry], 0, 0, '', 0),
             ('truncated_package', package[:64], [entry], 0, 0, '', 0),
             ('other_model_name', package, [('Z6_2_0~1.BIN', 'Z6_2_0170.BIN')], 0, 0, '', 0),
             ('empty_directory', package, [], 0, 0, '', 0),
             ('same_payload_two_names', package, [entry, ('Z7_2_0~2.BIN', 'Z7_2_0171.BIN')],
              0, 0, 'A:\\firmware\\Z7_2_0171.BIN', 2)]
    if candidate is not None:
        cases.append(('local_candidate', candidate, [entry], 0, 0,
                      'A:\\firmware\\Z7_2_0170.BIN', 1))
    results = []
    for label, data, entries, directory, state, path, count in cases:
        result = NativeUpdateProbe(master, data).enumerate_packages(entries, directory, state)
        require(result['record_path'] == path and result['matching_count'] == count and
                result['record_category'] == (4 if path else 0) and
                result['record_package_flag'] == (1 if path else 0),
                'Unexpected candidate enumeration result: ' + label)
        results.append(dict(case=label, input_sha256=digest(data), directory_entries=entries, **result))
    return dict(scope='Original 0x37D71C enumeration, matching, category checks and record construction',
                directory_vector_supplied_by_host=True, record_category_assigned_by_fixture=False,
                installed_version_and_card_status_are_synthetic=True, cases=results)


def collection_suite(master, package, candidate):
    entry = ('Z7_2_0~1.BIN', 'Z7_2_0170.BIN')
    wrong = ('Z6_2_0~1.BIN', 'Z6_2_0170.BIN')
    stock = {'A:\\firmware\\': [entry], 'A:\\': []}
    cases = [
        ('firmware_and_root', stock, (), 0, 0, 1, 'A:\\firmware\\Z7_2_0170.BIN', 1, [0]),
        ('root_only', {'A:\\': [entry]}, (), 0, 0, 1, 'A:\\Z7_2_0170.BIN', 1, [1]),
        ('firmware_only', {'A:\\firmware\\': [entry]}, (), 0, 0, 1,
         'A:\\firmware\\Z7_2_0170.BIN', 1, [0]),
        ('both_directories_absent', {}, (), 0, 0, 0, '', 0, []),
        ('second_directory_error_aborts', stock, ('A:\\',), 0, 0, 0, '', 1, [0]),
        ('first_directory_error_aborts', stock, ('A:\\firmware\\',), 0, 0, 0, '', 0, []),
        ('other_model_name_only', {'A:\\firmware\\': [wrong], 'A:\\': []}, (), 0, 0, 1,
         '', 1, [0]),
        ('rejected_mode_one', stock, (), 1, 0, 0, '', 0, []),
        ('rejected_mode_five', stock, (), 5, 0, 0, '', 0, []),
        # Mode 2 passes the collection gate but targets no whole-camera record.
        ('accepted_mode_two', stock, (), 2, 0, 1, '', 1, [0]),
        ('card_b_firmware', {'B:\\firmware\\': [entry], 'B:\\': []}, (), 0, 2, 1,
         'B:\\firmware\\Z7_2_0170.BIN', 1, [0]),
        ('card_state_three_falls_back_to_a', {'A:\\firmware\\': [entry]}, (), 0, 3, 1,
         'A:\\firmware\\Z7_2_0170.BIN', 1, [0]),
    ]
    if candidate is not None:
        cases.append(('local_candidate', stock, (), 0, 0, 1,
                      'A:\\firmware\\Z7_2_0170.BIN', 1, [0]))
    accepted_modes = (0, 2, 3, 4, 6, 7, 8, 9, 0xC, 0xD, 0xE, 0x10, 0x12)
    results = []
    for (label, directories, failed, mode, card_state, returned, path,
         collected, directory_indices) in cases:
        result = NativeUpdateProbe(master, package).collect_packages(
            directories, failed, mode, card_state)
        buffers = 2 if mode in accepted_modes else 0
        require(result['returned'] == returned and result['record_path'] == path and
                result['collected_count'] == collected and
                result['collected_directory_indices'] == directory_indices and
                result['allocated_buffers'] == result['released_buffers'] == buffers and
                result['stored_mode'] == (mode if buffers else 0) and
                result['summary_head'] == (0 if not buffers else 19 if mode == 0 else 1) and
                (path == '' or (result['matching_count'] == 1 and
                                result['record_category'] == 4 and
                                result['record_package_flag'] == 1)) and
                (buffers or result['directory_queries'] == []) and
                '0x37d984' in result['executed_entries'] and
                ('0x37d71c' in result['executed_entries']) == (returned == 1) and
                ('0x37d6b4' in result['executed_entries']) == (collected > 0),
                'Unexpected collection result: ' + label)
        results.append(dict(case=label, directory_keys=list(directories),
                            failed_directories=list(failed), **result))
    return dict(scope='Original 0x37D984 directory collection, mode gate, root selection and enumeration abort conditions',
                directory_records_supplied_by_host=True,
                allocation_and_release_are_host_heap=True, cases=results)


def cross_version_suite(master, packages):
    """Check collection acceptance across stock package and installed versions.

    packages is a list of (label, whole-package bytes). Every package is
    collected against every synthetic installed master version; the whole-camera
    record must be built for each combination and must not depend on the
    installed version.
    """
    entry = ('Z7_2_0~1.BIN', 'Z7_2_0170.BIN')
    directories = {'A:\\firmware\\': [entry], 'A:\\': []}
    installed_versions = ('01.70', '01.61', '01.10')
    results = []
    for label, data in packages:
        records = {}
        for installed in installed_versions:
            probe = NativeUpdateProbe(master, data)
            result = probe.collect_packages(dict(directories),
                                            installed_master_version=installed)
            records[installed] = bytes(probe.u.mem_read(
                0xB25EC904 + 13 * 0x1CC, 0x1CC))
            require(result['returned'] == 1 and result['matching_count'] == 1 and
                    result['record_path'] == 'A:\\firmware\\Z7_2_0170.BIN' and
                    result['record_category'] == 4 and
                    result['record_package_flag'] == 1 and
                    '0x37d71c' in result['executed_entries'],
                    f'Unexpected cross-version result: {label}/{installed}')
            results.append(dict(package=label, installed_master_version=installed,
                                input_sha256=digest(data), input_length=len(data),
                                **result))
        require(len(set(records.values())) == 1,
                'Whole-camera record depends on the installed version: ' + label)
    return dict(scope='Original directory collection across stock package versions and installed master versions',
                whole_package_digest_and_execute_not_exercised=True,
                record_independent_of_installed_version=True, cases=results)


def integrity_suite(master, package, candidate):
    material = bytes(8)
    def matching_header(data):
        return update_digest(data[32:64], data[64:], material, master) + data[20:]
    matched = matching_header(package)
    damaged = bytearray(package)
    damaged[-17] ^= 1
    cases = [('distributed_package_under_fixture', package, material, 3, False),
             ('matching_synthetic_digest', matched, material, 0, True),
             ('wrong_synthetic_material', matched, bytes(range(8)), 3, False),
             ('damaged_crc_matching_synthetic_digest', matching_header(bytes(damaged)), material, 3, True)]
    if candidate is not None:
        cases.extend((('built_candidate_under_fixture', candidate, material, 3, False),
                      ('candidate_matching_synthetic_digest', matching_header(candidate), material, 0, True)))
    results = []
    for label, data, key, returned, checked_crc in cases:
        result = NativeUpdateProbe(master, data).whole_package_check(key)
        require(result['returned'] == returned and
                ('crc16' in result['primitive_calls']) == checked_crc and
                result['selection']['record_package_flag'] == 1 and
                result['selection']['selector_flag'] == 1 and
                result['selection']['collection']['record_slot'] == 13 and
                result['notifications'] == [dict(event='0xb1887d24', mask='0x20')] and
                result['dispatcher_return'] == 0,
                'Unexpected whole-package result: ' + label)
        results.append(dict(case=label, input_sha256=digest(data), **result))
    return dict(scope='Original directory collection, selector, whole-package dispatcher and result notification',
                boot_material='explicit synthetic eight-byte fixtures; real material remains unknown',
                host_bulk_primitives=['decode', 'sha1_update', 'sha1_final', 'crc16', 'memmove'],
                record_category_assigned_by_fixture=False,
                helper_invocation_sequence_supplied_by_host=True,
                timer_and_status_callbacks_supplied_by_host=True,
                actual_distributed_package_acceptance_verified=False,
                storage_programmed=False, cases=results)


def run_suite(master, package, candidate=None, extra_packages=()):
    validate_master(master)
    require(digest(package) ==
            'fc0e94f57500a1f0e287c6b9a036c81a5ffceccb8432a377d645b3fa35a19b6a',
            'Requires stock Z7 II C 1.70 update package')

    def flipped(offset):
        changed = bytearray(package)
        changed[offset] ^= 1
        return bytes(changed)

    cases = [
        ('stock_package', package, 0x4000000, 1, None, 31),
        ('bare_master', master, 0x4000000, 0, 12, 0),
        ('truncated_before_directory', package[:64], 0x4000000, 0, 12, 0),
        ('changed_outer_digest', flipped(0), 0x4000000, 1, None, 31),
        ('changed_last_member_crc', flipped(len(package) - 17), 0x4000000, 1, None, 31),
        ('capacity_equal_master_length', package, len(master), 1, 11, 29),
        # First member length is big-endian at body +0x44, file +0x64.
        ('invalid_ex_member_length', flipped(0x67), 0x4000000, 1, 11, 12),
    ]
    if candidate is not None:
        cases.append(('local_candidate', candidate, 0x4000000, 1, None, 31))
    results = []
    for label, data, capacity, expected_parser, expected_return, expected_mask in cases:
        parser = NativeUpdateProbe(master, data, capacity).parser()
        checks = NativeUpdateProbe(master, data, capacity).member_checks()
        classification = NativeUpdateProbe(master, data, capacity).classify()
        require(parser['returned'] == expected_parser and
                checks['returned'] == expected_return and
                checks['member_mask'] == expected_mask and
                classification['returned'] == (1 if expected_return is None else expected_return),
                f'Unexpected native result: {label}: parser={parser["returned"]}, '
                f'member_return={checks["returned"]}, mask={checks["member_mask"]}')
        results.append(dict(case=label, input_sha256=digest(data), length=len(data),
                            image_capacity=capacity, parser=parser,
                            member_checks=checks, classification=classification))
    return dict(master_sha256=digest(master), cases=results,
                propriety=propriety_suite(master),
                directory=directory_suite(master), scanner=scan_suite(master, package, candidate),
                enumeration=enumeration_suite(master, package, candidate),
                collection=collection_suite(master, package, candidate),
                cross_version=cross_version_suite(
                    master, [('stock C 1.70', package)] + list(extra_packages)),
                primitives=primitive_suite(master), integrity=integrity_suite(master, package, candidate),
                version_service=NativeUpdateProbe(master, package).version_summary_service(),
                environment=dict(running_image='supplied stock master; zero platform tag',
                                 character_classification='host ASCII flags',
                                 component_version='synthetic all-zero descriptor; query succeeds',
                                 parameter_storage='host stores writes and supplies explicit version fixtures',
                                 other_runtime_ram='zero initialized'),
                scope='Original directory parser, file scan, classification and propriety predicates',
                actual_package_digest_verified=False, menu_dispatch_executed=False,
                native_service_methods_executed=['GetProprietyCheck'],
                storage_programmed=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--stock-package', type=Path, required=True)
    parser.add_argument('--candidate', type=Path)
    parser.add_argument('--extra-package', type=Path, action='append', default=[],
                        help='Additional stock update package for the cross-version suite')
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    require(not args.report.exists(), 'Report already exists')
    master, package = args.master.read_bytes(), args.stock_package.read_bytes()
    candidate = args.candidate.read_bytes() if args.candidate else None
    extra_packages = [(path.stem, path.read_bytes()) for path in args.extra_package]
    report = run_suite(master, package, candidate, extra_packages)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    for case in report['cases']:
        print(case['case'], 'parser=', case['parser']['returned'],
              'member_return=', case['member_checks']['returned'],
              'member_mask=', case['member_checks']['member_mask'])
    print('PASS', len(report['directory']['cases']), 'directory cases,',
          len(report['scanner']['cases']), 'scanner cases,',
          len(report['propriety']['cases']), 'propriety cases,',
          len(report['enumeration']['cases']), 'enumeration cases,',
          len(report['collection']['cases']), 'collection cases,',
          len(report['cross_version']['cases']), 'cross-version cases,',
          len(report['integrity']['cases']), 'synthetic integrity cases')


if __name__ == '__main__':
    main()
