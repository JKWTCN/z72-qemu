# SPDX-License-Identifier: GPL-2.0-or-later
"""Diagnostic capture caller executed by the native resource-8 service task.

This supplies a caller, not capture admission, hardware completion or a photo.
Non-diagnostic operations retain the original callback. All downstream APIs,
tasks and scheduling are original firmware execution.
"""
import hashlib
import struct

from analyze.decode_z72 import require
from tools.sdk_file_probe import CALLBACK, CODE, OBJECT, ORIGINAL_CALLBACK

REQUEST = OBJECT + 0x80
RESULT = OBJECT + 0x100


def caller_code():
    code, literals = bytearray(), []

    def emit(value):
        code.extend(struct.pack('<H', value))

    def literal(register, value):
        literals.append((len(code), register, value))
        emit(0)

    emit(0x680A)                 # ldr r2,[r1]
    emit(0x2A7F)                 # diagnostic operation 127
    branch = len(code)
    emit(0)
    emit(0xB510)                 # push r4,lr; retain stack alignment
    literal(4, RESULT)
    literal(0, REQUEST)
    callback_literal = len(literals)
    literal(1, 0)
    literal(3, 0x103BA6EB)       # original capture submit
    emit(0x4798)
    emit(0x6020)                 # store return status
    emit(0x2001)
    emit(0x6060)                 # mark API returned
    return_pc = CODE + len(code)
    emit(0xBD10)
    original = len(code)
    literal(3, ORIGINAL_CALLBACK)
    emit(0x4718)
    completion = CODE + len(code)
    emit(0xB510)
    literal(4, RESULT + 0x10)
    for register in range(4):
        emit(0x6000 | (register << 6) | (4 << 3) | register)
    emit(0x6920)                 # completion count
    emit(0x3001)
    emit(0x6120)
    emit(0x2000)
    emit(0xBD10)
    literals[callback_literal] = (literals[callback_literal][0], 1, completion | 1)
    struct.pack_into('<H', code, branch, 0xD100 | ((original - branch - 4) // 2 & 255))
    while len(code) % 4:
        emit(0xBF00)
    for offset, register, value in literals:
        distance = CODE + len(code) - ((CODE + offset + 4) & ~3)
        require(0 <= distance < 1024 and distance % 4 == 0, 'Capture literal out of range')
        struct.pack_into('<H', code, offset, 0x4800 | register << 8 | distance // 4)
        code.extend(struct.pack('<I', value))
    return bytes(code), return_pc, completion


class NativeCaptureCaller:
    def __init__(self, remote):
        self.remote = remote
        self.code, self.return_pc, completion = caller_code()
        self.points = {CODE + 6: 'diagnostic-capture-caller',
                       self.return_pc: 'diagnostic-capture-api-return',
                       completion: 'diagnostic-capture-completion',
                       0x103BA7B2: 'capture-busy-release-byte',
                       0x103BA7BE: 'capture-busy-first-word',
                       0x103BA7C4: 'capture-busy-second-word',
                       0x103BA7CA: 'capture-busy-third-byte',
                       0x103BA8EA: 'capture-resource-query-return',
                       0x103BA8F8: 'capture-resource-query-mode',
                       0x103BA902: 'capture-resource-query-deferred',
                       0x103BA784: 'capture-submit-return',
                       0x103BAA06: 'capture-validation-return',
                       0x103BAA70: 'capture-preparation-return'}
        remote.select_thread(1)
        require(self.word(CALLBACK) == ORIGINAL_CALLBACK, 'Unexpected resource-8 callback')
        self.saved = remote.read(OBJECT, 0x200)
        self.saved_code = remote.read(CODE, len(self.code))
        require(not any(self.saved + self.saved_code), 'Capture diagnostic memory is occupied')
        remote.write(CODE, self.code)
        # Original standard-capture defaults: one image, default target/format,
        # request flag at +4 set; no writes to release gates or completion state.
        remote.write(REQUEST, struct.pack('<5I', 0, 1, 0, 0, 1))
        remote.write(CALLBACK, struct.pack('<I', CODE | 1))
        self.report = dict(caller_fixture=True, triggered=False, caller_entered=False,
                           caller_returned=False, body_shutter_used=False,
                           hardware_completion_host_supplied=False,
                           request_words=[0, 1, 0, 0, 1],
                           code_bytes=len(self.code), code_sha256=hashlib.sha256(self.code).hexdigest())
        self.entry_sp = None
        self.native_return = None
        self.report['resources_before'] = self.resource_masks()

    def word(self, address):
        return int.from_bytes(self.remote.read(address, 4), 'little')

    def resource_masks(self):
        masks = []
        for descriptor in (0xB1869898, 0xB18698A0, 0xB18698B0):
            capacity, pointer = struct.unpack('<2I', self.remote.read(descriptor, 8))
            require(0 < capacity <= 512 and 0xB1800000 <= pointer <= 0xB5F00000 - 64,
                    'Unexpected native resource bitmap descriptor')
            data = self.remote.read(pointer, (capacity + 31) // 32 * 4)
            bits = [bit for bit in range(capacity) if data[bit // 8] & 1 << (bit % 8)]
            masks.append(dict(descriptor=hex(descriptor), capacity=capacity,
                              pointer=hex(pointer), set_bits=bits))
        common = sorted(set(masks[0]['set_bits']) & set(masks[2]['set_bits']))
        return dict(masks=masks, primary_scratch_intersection=common,
                    processing_resource_flags=[self.word(address) for address in (0xB18685B8, 0xB18685BC)],
                    ui_reason_byte=self.remote.read(0xB20A15EE, 1)[0])

    def trigger(self):
        require(not self.report['triggered'], 'Capture diagnostic already triggered')
        remote = self.remote
        remote.select_thread(3)
        ring, sequence_address = 0xC60F0000, 0xC1006F74
        written, consumed = self.word(ring + 8), self.word(ring + 16)
        require(written < 192 and consumed < 192 and (written + 1) % 192 != consumed,
                'Peer diagnostic trigger ring is full or invalid')
        sequence = self.word(sequence_address)
        remote.write(ring + 24 + written * 264, struct.pack('<IBBH', 127, 8, sequence & 255, 0))
        for address, value in ((sequence_address, (sequence + 1) & 0xFFFFFFFF),
                               (ring + 8, (written + 1) % 192), (0x20136008, 1)):
            remote.write(address, struct.pack('<I', value))
        remote.select_thread(1)
        self.report['triggered'] = True

    def observe(self, pc, registers):
        remote = self.remote
        if pc == 0x103BA8EA:
            state = self.resource_masks()
            state['query_result'] = remote.get(registers, 'r0')
            self.report['resources_at_query'] = state
            require(state['query_result'] == int(not state['primary_scratch_intersection']),
                    'Native resource query disagrees with observed bitmap intersection')
        elif pc == CODE + 6:
            self.report['caller_entered'] = True
            self.entry_sp = remote.get(registers, 'sp')
            self.native_return = remote.get(registers, 'lr') & ~1
        elif pc == self.return_pc:
            self.report['api_status'] = self.word(RESULT)
            require(self.native_return is not None, 'Missing capture caller entry')
            return self.native_return
        elif pc == self.native_return:
            self.report['caller_returned'] = remote.get(registers, 'sp') == self.entry_sp
            require(self.report['caller_returned'], 'Capture caller did not restore its task stack')
        return None

    def close(self):
        self.remote.select_thread(1)
        self.report['result_words'] = list(struct.unpack('<9I', self.remote.read(RESULT, 36)))
        self.report['api_returned'] = self.report['result_words'][1] == 1
        self.report['api_accepted'] = self.report['api_returned'] and self.report['result_words'][0] == 0
        self.report['completion_count'] = self.report['result_words'][8]
        self.remote.write(CALLBACK, struct.pack('<I', ORIGINAL_CALLBACK))
        # Retain a potentially live caller/callback until this diagnostic VM
        # closes. Clearing code under a blocked native task would corrupt it.
        pending = any(
            CODE <= self.word(0xB23F6FE4 + operation * 4) < CODE + len(self.code)
            for operation in (70, 71))
        safe = (not self.report['triggered'] or self.report['caller_returned']) and not pending
        if safe:
            self.remote.write(OBJECT, self.saved)
            self.remote.write(CODE, self.saved_code)
        self.report['scratch_restored'] = safe
        self.report['callback_restored'] = self.word(CALLBACK) == ORIGINAL_CALLBACK
        self.report['scratch_retained_until_vm_close'] = not safe
