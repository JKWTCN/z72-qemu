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

FINISH_POINTS = {0x10321EA2, 0x10322448, 0x1032A792, 0x1032A7B4,
                 0x103D0C72, 0x103CD46A, 0x102315FC, 0x102359F8, 0x10235A22}

INPUT_LEASE_POINTS = {0x1022D9E8: 'input-mask8-acquire',
                      0x1022DA1C: 'input-mask8-acquire-store',
                      0x1022D864: 'input-mask8-release',
                      0x1022D890: 'input-mask8-release-store'}

AUX_IMAGE_POINTS = {0x10236150: 'aux-image-submit',
                    0x10236198: 'aux-image-submit-return',
                    0x10244B92: 'aux-image-job-consumed',
                    0x10244CD0: 'aux-image-start',
                    0x10244CEE: 'aux-image-completion-wait',
                    0x10294364: 'aux-image-interrupt',
                    0x10235FC0: 'aux-image-completion'}

POST_SUBMIT_POINTS = {
    0x1032385A: 'capture-driver-request-consumed',
    0x10233222: 'capture-input-ready-request',
    0x10233250: 'capture-input-ready-return',
    0x103234E8: 'capture-driver-state14-entry',
    0x10322E3E: 'capture-subsystem-stop-entry',
    0x10322EF8: 'capture-local-stop-return',
    0x10322F30: 'capture-processing-stop-return',
    0x10322FD4: 'capture-subsystem-stop-return',
    0x10323500: 'capture-driver-state14-stop-return',
    0x1031DCCC: 'capture-stop-ready-update',
    0x1031DCF8: 'capture-stop-ready-flags',
    0x1031DD00: 'capture-stop-all-ready',
    0x10320220: 'capture-input-finish-job',
    0x10320264: 'capture-input-finish-state-check',
    0x10320272: 'capture-input-finish-ready',
    0x10320520: 'capture-input-idle-ready',
    0x10321EA2: 'capture-input-context-finish-check',
    0x10322448: 'capture-processing-context-finish-check',
    0x1032A792: 'capture-context-consumer-release',
    0x1032A7B4: 'capture-context-consumer-released',
    0x103D0C72: 'capture-processing-job-busy-check',
    0x103CD46A: 'capture-processing-peer-finish',
    0x102301DC: 'capture-input-drain-return',
    0x1023C82C: 'capture-input-disable-return',
    0x102300B0: 'capture-input-pending-clear',
    0x102300EC: 'capture-input-active-mask',
    0x102300FA: 'capture-input-active-cleared',
    0x102315FC: 'capture-input-worker-clear',
    0x102359F8: 'capture-input-alternate-worker-selected',
    0x10235A22: 'capture-input-alternate-worker-clear',
    0x10321A4C: 'capture-driver-notification',
    0x103E9D24: 'capture-release-notification',
    0x102389C2: 'capture-input-boundary-wait',
    0x102389C6: 'capture-input-boundary-return',
}


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
        self.ui_points = {0x1042E038: 'ui-capture-configuration',
                          0x1042E06E: 'ui-operation7-submit-return',
                          0x1042E0AE: 'ui-operation6-submit-return',
                          0x1042DDA0: 'ui-capture-operation-completion',
                          0x1020F84C: 'ui-capture-event-queued',
                          0x1020F8DC: 'ui-resource37-event-return',
                          0x1042F4DA: 'ui-capture-reason-clear',
                          0x1042F1EC: 'system-controller-configuration-entry',
                          0x1042F242: 'system-controller-configuration-status',
                          0x1042F244: 'system-controller-configuration-abort',
                          0x1042F264: 'system-controller-capability-result',
                          0x1042F26C: 'system-controller-request-result',
                          0x1042F298: 'system-controller-final-check',
                          0x1042F29E: 'system-controller-configuration-error',
                          0x1042F246: 'system-controller-configuration-return',
                          0x1042F2A8: 'nor-write-notification',
                          0x1042F2E8: 'nor-write-event-consumer',
                          0x1042F382: 'nor-controller-stage-request',
                          0x1042F434: 'nor-controller-stage-dispatch',
                          0x1042DC90: 'lens-controller-stage-request',
                          0x1042DD54: 'lens-disconnect-request',
                          0x1042DD72: 'lens-connect-request',
                          0x103BF6CC: 'storage-object-write',
                          0x103713B8: 'nor-program-request',
                          0x103713F6: 'nor-program-return',
                          0x103713F8: 'nor-erase-request',
                          0x10371436: 'nor-erase-return',
                          0x103ED6BC: 'lens-contact-notification',
                          0x1042DCDE: 'lens-board-notification',
                          0x1042E018: 'lens-connection-event-producer',
                          0x10318836: 'lens-link-state-emitter',
                          0x1034D780: 'lens-retry-query-result',
                          0x1030E3E2: 'lens-control-retry',
                          0x10311462: 'lens-control-handshake-result',
                          0x10311498: 'lens-control-response',
                          **POST_SUBMIT_POINTS, **INPUT_LEASE_POINTS, **AUX_IMAGE_POINTS}
        self.points.update(self.ui_points)
        self.ui_hits = {}
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
                           finish_observation_max_contexts=4,
                           request_words=[0, 1, 0, 0, 1],
                           code_bytes=len(self.code), code_sha256=hashlib.sha256(self.code).hexdigest())
        self.entry_sp = None
        self.native_return = None
        excluded = self.remote.read(0x118FA48B, 40)
        require(len(set(excluded)) == 40 and max(excluded) < 124,
                'Unexpected capture resource exclusion table')
        self.excluded_mask = sum(1 << bit for bit in excluded)
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
        remote.select_thread(1)
        self.report['trigger_counter_ticks'] = int.from_bytes(remote.read(0x04266008, 8), 'little')
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

    def blocking_resources(self):
        data = self.remote.read(0xB23F7E24, 32)
        intersection = (int.from_bytes(data[:16], 'little') &
                        int.from_bytes(data[16:], 'little') & ~self.excluded_mask)
        return [bit for bit in range(124) if intersection & 1 << bit]

    def ui_observation(self, pc, registers):
        r0, r1 = [self.remote.get(registers, name) for name in ('r0', 'r1')]
        consumed = None
        if pc == 0x1020F8DC:
            message = self.remote.get(registers, 'r5')
            if 0xB1800000 <= message <= 0xB5FFFFE8:
                consumed = list(struct.unpack('<2I', self.remote.read(message + 0x10, 8)))
        nor_event = None
        if pc == 0x1042F2E8 and 0xB1800000 <= r0 <= 0xB5FFFFE8:
            nor_event = list(struct.unpack('<2I', self.remote.read(r0 + 0x10, 8)))
        keep = not (pc == 0x1020F84C and r0 not in (46, 47, 51, 52, 53) or
                    pc == 0x1020F8DC and (consumed is None or consumed[0] not in (46, 47, 51, 52, 53)) or
                    pc == 0x1042F4DA and r0 != 2 or
                    pc == 0x1042F2A8 and r0 not in (0x04400041, 0x04400042) or
                    pc == 0x1042F2E8 and (nor_event is None or nor_event[0] not in (67, 68)) or
                    pc == 0x1030E3E2 and r1 != 11 or
                    pc in POST_SUBMIT_POINTS and not self.report['triggered'])
        if keep and pc in INPUT_LEASE_POINTS:
            mask = r1 if pc in (0x1022D9E8, 0x1022D864) else self.remote.get(registers, 'r7')
            keep = mask == 8
        if keep and pc in FINISH_POINTS:
            keep = (self.remote.read(0xB1868AF1, 1)[0] == 14 and
                    self.word(0xB1868B58) <= 4)
        self.ui_hits[pc] = self.ui_hits.get(pc, 0) + int(keep)
        detail = None
        if keep:
            detail = dict(mode=self.remote.read(0xB2098536, 1)[0],
                configuration_state=list(self.remote.read(0xB2098784, 3)),
                reason_byte=self.remote.read(0xB20A15EE, 1)[0],
                resource37_set=bool(self.word(0xB23F7E28) & 0x20),
                blocking_resources=self.blocking_resources(),
                callback_slots={str(operation): hex(self.word(0xB23F6FE4 + operation * 4))
                                for operation in (6, 7, 8, 9)})
            if pc in POST_SUBMIT_POINTS:
                detail['stop_ready_flags'] = hex(self.word(0xB1868B64))
                detail['driver_context_count'] = self.word(0xB1868B58)
                detail['input_runtime_states'] = list(self.remote.read(0xB1887D70, 8))
                detail['driver_finish_comparison_word'] = hex(self.word(0xB1868C34))
                detail['input_ready_fields'] = {hex(offset): hex(self.word(0xB1887D70 + offset))
                    for offset in (0x5C, 0x7C, 0x80, 0x120)}
            if pc in (0x1032A792, 0x1032A7B4):
                pointer = r0 if pc == 0x1032A792 else self.remote.get(registers, 'r5')
                if 0xB2C00000 <= pointer <= 0xB5EFFEAF:
                    detail['released_context'] = dict(address=hex(pointer),
                        consumers=self.remote.read(pointer + 0xC, 1)[0],
                        parameters=hex(self.word(pointer + 0x144)),
                        pending=hex(self.word(pointer + 0x14C)))
            if pc in (0x102300EC, 0x102300FA):
                pointer = self.remote.get(registers, 'r5')
                if 0xB2C00000 <= pointer <= 0xB5EFFEAF:
                    detail['input_pending_context'] = dict(address=hex(pointer),
                        consumers=self.remote.read(pointer + 0xC, 1)[0],
                        parameters=hex(self.word(pointer + 0x144)),
                        pending=hex(self.word(pointer + 0x14C)))
            if pc in (0x102315FC, 0x102359F8, 0x10235A22):
                pointer = self.remote.get(registers, 'r4')
                if 0xB2C00000 <= pointer <= 0xB5EFFEAF:
                    detail['input_worker_context'] = dict(address=hex(pointer),
                        consumers=self.remote.read(pointer + 0xC, 1)[0],
                        parameters=hex(self.word(pointer + 0x144)),
                        pending=hex(self.word(pointer + 0x14C)))
            if pc in INPUT_LEASE_POINTS:
                pointer = r0 if pc in (0x1022D9E8, 0x1022D864) else self.remote.get(registers, 'r4')
                detail['mask8_owner'] = hex(self.word(0xB25EF024))
                if pc in (0x1022DA1C, 0x1022D890):
                    detail['pending_to_store'] = hex(r1)
                    detail['pending_store_executed'] = False
                if 0xB2C00000 <= pointer <= 0xB5EFFEAF:
                    detail['input_lease_context'] = dict(address=hex(pointer),
                        consumers=self.remote.read(pointer + 0xC, 1)[0],
                        parameters=hex(self.word(pointer + 0x144)),
                        pending=hex(self.word(pointer + 0x14C)))
            if pc == 0x10236150 and 0xB1800000 <= r0 <= 0xB5FFFFF3:
                detail['auxiliary_request'] = dict(mode=self.remote.read(r0, 1)[0],
                    source=hex(self.word(r0 + 4)), target=hex(self.word(r0 + 8)))
            if pc == 0x10236198:
                detail['auxiliary_submit_status'] = self.remote.get(registers, 'r6')
            if pc == 0x10244B92 and 0xB1800000 <= r0 <= 0xB5FFFFE7:
                detail['auxiliary_job'] = dict(notification=hex(self.word(r0 + 0x10)),
                    configuration=hex(self.word(r0 + 0x14)), callback=hex(self.word(r0 + 0xC)))
            if pc in (0x10244CD0, 0x10244CEE):
                detail['auxiliary_current'] = hex(self.word(0xB1809630))
            if pc in (0x103D0C72, 0x103CD46A):
                pointer = self.remote.get(registers, 'r4')
                if pc == 0x103CD46A:
                    payload = self.remote.get(registers, 'r2')
                    request = self.word(payload) if 0xB1800000 <= payload <= 0xB5FFFFFC else 0
                    pointer = self.word(request) if 0xB2C00000 <= request <= 0xB5EFFFFC else 0
                if 0xB2C00000 <= pointer <= 0xB5EFC1CF:
                    detail['processing_job'] = dict(parameters=hex(pointer),
                        owner=hex(self.word(pointer + 0xC)),
                        pending=hex(self.word(pointer + 0x6C)),
                        busy=self.remote.read(pointer + 0x3E30, 1)[0])
            if pc in (0x10321A4C, 0x103E9D24):
                detail['notification'] = hex(r0)
                if 0xB1800000 <= r1 <= 0xB5FFFFFC:
                    detail['notification_first_word'] = hex(self.word(r1))
            if pc == 0x1042DDA0 and 0xB1800000 <= r1 <= 0xB5FFFFFC:
                detail['completion_status'] = self.word(r1)
            if consumed is not None:
                detail['consumed_event'] = consumed
            if nor_event is not None:
                detail['nor_event'] = nor_event
            if pc == 0x103ED6BC and 0xB1800000 <= r0 < 0xB6000000:
                detail['contact_payload_byte'] = self.remote.read(r0, 1)[0]
            if pc in (0x10318836, 0x1034D780):
                detail['lens_request_flags'] = list(struct.unpack('<14I',
                    self.remote.read(0xB295114C, 56)))
                detail['retry_count'] = self.remote.read(0xB2951190, 1)[0]
            if pc == 0x1034D780:
                sp = self.remote.get(registers, 'sp')
                detail['query_1016_result'] = self.word(sp)
            if pc == 0x1030E3E2:
                detail['retry_policy'] = list(self.remote.read(0xB2955D44, 3))
            if pc == 0x10311462:
                descriptor = self.word(0xB18A785C)
                detail['handshake_gpio_descriptor'] = hex(descriptor)
                if 0xB1800000 <= descriptor <= 0xB5FFFFDC:
                    detail['handshake_gpio_fields'] = [hex(value) for value in
                        struct.unpack('<9I', self.remote.read(descriptor, 36))]
            if pc == 0x10311498 and 0xB1800000 <= r1 <= 0xB5FFFFFD:
                detail['response_status'] = self.remote.read(r1 + 1, 1)[0]
            if pc in (0x102389C2, 0x102389C6):
                detail['input_wait_mask'] = hex(self.remote.get(registers, 'r4'))
                detail['input_state'] = list(self.remote.read(0xB1888145, 3))
                detail['input_processing_flags'] = hex(self.word(0xB26B38CC))
                detail['input_banks'] = [dict(bank=bank,
                    mask=hex(self.word(0x20068200 + bank * 32)),
                    status=hex(self.word(0x20068210 + bank * 32))) for bank in range(8)]
            if pc in (0x10318836, 0x103ED6BC):
                sp = self.remote.get(registers, 'sp')
                words = struct.unpack('<24I', self.remote.read(sp, 96))
                detail['stack_code_candidates'] = [dict(offset=hex(index * 4), value=hex(value))
                    for index, value in enumerate(words) if 0x10020000 <= value < 0x10800000]
        return detail, keep, self.ui_hits[pc] < 32

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
        if self.report['triggered']:
            ticks = int.from_bytes(self.remote.read(0x04266008, 8), 'little')
            self.report['observed_after_trigger_counter_seconds'] = round(
                (ticks - self.report['trigger_counter_ticks']) / 48000000, 6)
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
