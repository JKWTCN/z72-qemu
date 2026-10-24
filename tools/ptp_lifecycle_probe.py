# SPDX-License-Identifier: GPL-2.0-or-later
"""Trace native service messages and session cleanup on synthetic RAM.

Queues, mode replies and peripheral cleanup are explicit host boundaries.
No USB device, native menu dialog or hardware mode receiver is executed.
"""
import argparse
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import BASE, MASTER_SHA, require, validate_master
from analyze.firmware_structure import thumb_literal
from analyze.ptp_checksum_context import CONTEXT, CONTEXT_SIZE
from tools.ptp_service_probe import Probe
from unicorn import UC_HOOK_MEM_WRITE
from unicorn.arm_const import UC_ARM_REG_PC


def context_watch(probe):
    sentinel = bytes((i * 17 + 3) & 255 for i in range(CONTEXT_SIZE))
    probe.u.mem_write(CONTEXT, sentinel)
    writes = []

    def observe(u, access, address, size, value, unused):
        writes.append(dict(pc=hex(u.reg_read(UC_ARM_REG_PC)),
                           address=hex(address), bytes=size))

    probe.u.hook_add(UC_HOOK_MEM_WRITE, observe,
                     begin=CONTEXT, end=CONTEXT + CONTEXT_SIZE - 1)
    return sentinel, writes


def service_message(image, mode, reply_flag):
    probe = Probe(image)
    sentinel, writes = context_watch(probe)
    events, packets = [], []
    registry = probe.call(0x20D638, probe.INPUT + 0x4000)
    require(probe.u.mem_read(probe.INPUT + 0x4000, 1)[0] == 18,
            'Unexpected interface registry count')
    entry = registry + 15 * 16
    require(probe.word(entry) == 15 and probe.word(entry + 4) == 0x10206CBB and
            probe.word(entry + 8) == 0x10206CC5 and
            probe.word(entry + 12) == 0x10432725, 'Mode interface binding changed')
    receiver = thumb_literal(image, 0x1E55BC, 0)
    require(receiver == 0x102054FF, 'Registered receiver binding changed')
    # Restore only the registry pointer normally set by its initialization loop.
    state = thumb_literal(image, 0x1E55A6, 5) - 8
    probe.put_word(state + 4, registry)
    probe.call(0x363BBC, probe.call(0x1E6CA4))
    probe.call(0x1E6CBA, receiver, entry)

    def event(handle, mask, *args):
        events.append(dict(kind='worker_event', mask=hex(mask)))
        return 0

    def enqueue(descriptor, *args):
        header = bytes(probe.u.mem_read(descriptor, 24))
        length, source = struct.unpack_from('<II', header, 8)
        require(length == 8, 'Unexpected mode packet length')
        command, payload_mode = struct.unpack('<II', probe.u.mem_read(source, length))
        packets.append(dict(interface=header[0], channel=header[1], bytes=length,
                            command=command, mode=payload_mode))
        return 1

    probe.hooks.update({0x3406E4: event, 0x20D7A2: lambda *args: 1,
                        0x20D7AC: enqueue, 0x20D7B2: lambda *args: 0,
                        0x1E5632: lambda *args: 0})
    probe.hooks[0x4A100C] = lambda mask, *args: events.append(
        dict(kind='service_completion_event', mask=hex(mask))) or 0
    require(probe.call(0x363C26, mode, 0x104798F3) == 1, 'Mode post failed')
    probe.call(0x3638A2, 0x40)
    require(packets == [dict(interface=15, channel=1, bytes=8, command=9, mode=mode)],
            'Native mode message differs')

    # Supply a reply at the transport boundary; this is not a hardware result.
    reply = probe.INPUT + 0x3000
    output = reply + 0x100
    probe.u.mem_write(reply, struct.pack('<II', 10, reply_flag))
    require(probe.call(0x412770, reply, 8, output) == 1, 'Mode reply decode failed')
    decoded = probe.word(output)
    require(probe.u.mem_read(decoded, 1)[0] == 0x12, 'Unexpected reply event type')
    probe.call(0x1E6CC4, decoded)
    probe.call(0x3638A2, 0x80)
    acknowledgement = probe.word(probe.service + 16)
    success = probe.word(probe.service + 20)
    require(acknowledgement == 0x03010003 + mode and success == 1 - reply_flag,
            'Native completion differs')
    require(probe.word(0xB18A7B7C + 0x28) == 0, 'Pending callback was not released')
    require(bytes(probe.u.mem_read(CONTEXT, CONTEXT_SIZE)) == sentinel and not writes,
            'Covered service-message path changed context')
    return dict(mode=mode, supplied_reply_flag=reply_flag, packets=packets,
                events=events, acknowledgement=hex(acknowledgement), success=success,
                pending_callback_released=True, context_preserved=True,
                native_context_writes=writes, hardware_reply_verified=False)


def session_close(image):
    probe = Probe(image)
    sentinel, writes = context_watch(probe)
    boundaries, peer_requests = [], []
    session = thumb_literal(image, 0x4597AA, 1)
    probe.put_word(session, 7)
    probe.put_word(probe.service, 0)  # The script has already sent F002.

    def boundary(address, result=0):
        def invoke(*args):
            boundaries.append(dict(address=hex(address), first_argument=args[0]))
            return result
        probe.hooks[address - BASE] = invoke

    # Keep the outer CloseSession callback, session reset, cleanup controller
    # and service cleanup controller native. Device/task endpoints stay outside.
    for address in (0x104C0F4E, 0x104C0F20, 0x10492A46, 0x10492B4A,
                    0x1047A0AC, 0x104C7578, 0x104C7570, 0x104C7584,
                    0x104C17EA, 0x1050590C, 0x10492C50,
                    0x10478B7A, 0x10486E28, 0x10490B7C, 0x104AE666,
                    0x10478BC6, 0x104903C2, 0x104796E2, 0x104AE716,
                    0x104C78F4, 0x104C1B0A, 0x10490580, 0x104C1B22,
                    0x10490D68, 0x103BB5F6, 0x1063C59E,
                    0x104910AA, 0x10490F3E, 0x104B2C00, 0x10491990,
                    0x10491B48, 0x1049263E, 0x104B2872, 0x104C6D36,
                    0x104B2544):
        boundary(address)
    boundary(0x104828F4, 1)
    boundary(0x104C7578, 1)  # No outstanding queue items in this fixture.
    boundary(0x10361192)
    boundary(0x103610D2)

    def peer_request(resource, operation, length, payload):
        require(length == 12, 'Unexpected peer state request size')
        data = bytes(probe.u.mem_read(payload, length))
        peer_requests.append(dict(resource=resource, operation=hex(operation),
                                  bytes=length, state_argument=data[8]))
        return 1

    probe.hooks[0x368666] = peer_request
    probe.packet(0, opcode=0x1003, length=12)
    returned = probe.call(0x459890, 0, probe.INPUT)
    require(returned == 1 and probe.word(session) == 0,
            'CloseSession did not clear the session identifier')
    require(peer_requests == [dict(resource=3, operation='0x28', bytes=12, state_argument=1)],
            'CloseSession peer state request changed')
    require(bytes(probe.u.mem_read(CONTEXT, CONTEXT_SIZE)) == sentinel and not writes,
            'Covered CloseSession path changed context')
    return dict(opcode='0x1003', callback='0x10479890',
                cleanup_controller='0x10478bf2', returned=returned,
                session_identifier_cleared=True, context_preserved=True,
                native_context_writes=writes, responses=probe.vendor_responses,
                peer_state_requests=peer_requests,
                host_boundaries=boundaries, actual_ui_transition_executed=False)


def update_result_wait(image, result_bits):
    """Identify the fifth update-service function without executing an update."""
    probe = Probe(image)
    sentinel, writes = context_watch(probe)
    waits = []

    def completed(handle, output, timeout, unused):
        waits.append(dict(supplied_bits=result_bits, timeout=timeout))
        probe.put_word(output, result_bits)
        return 1

    probe.hooks[0x5012AA] = completed
    for offset in (0x4C09C6, 0x4C09FE, 0x488F3C):
        probe.hooks[offset] = lambda *args: 0
    output = probe.INPUT + 0x3000
    returned = probe.call(0x747136, 0, 0, output)
    require(waits == [dict(supplied_bits=result_bits, timeout=300)] and
            returned == (1 if result_bits == 1 else 3) and
            probe.word(output) == (0 if result_bits == 1 else 6),
            'Update-result wait binding changed')
    require(bytes(probe.u.mem_read(CONTEXT, CONTEXT_SIZE)) == sentinel and not writes,
            'Covered update-result wait changed context')
    return dict(supplied_result_bits=result_bits, waits=waits, returned=returned,
                reason=probe.word(output), context_preserved=True,
                native_context_writes=writes, native_update_executed=False)


def run(image):
    validate_master(image)
    return dict(format=1, firmware_included=False, master_sha256=MASTER_SHA,
                registered_receiver='0x102054fe', interface_registry='0x1197ffb0',
                interface_record='0x119800a0', message_encoder='0x104328ba',
                queue_sender='0x10205698', reply_decoder='0x104328de',
                message_cases=[service_message(image, mode, flag)
                               for mode in (0, 1) for flag in (0, 1)],
                session_close=session_close(image),
                update_result_wait_entry='0x10767136',
                update_result_wait_cases=[update_result_wait(image, bits) for bits in (1, 2)],
                actual_camera_access=False, menu_cancel_executed=False,
                actual_mode_change_executed=False, boot_material_recovered=False,
                limitations=[
                    'The registry pointer is restored from its original table, not full startup.',
                    'Queue capacity, queue submission, scheduling and mode replies are synthetic.',
                    'Peripheral and task cleanup endpoints in CloseSession are host boundaries.',
                    'No native menu No callback, physical USB disconnect or display output is executed.',
                    'Preservation only covers the native instructions executed by these cases.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = run(args.master.read_bytes())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('PASS four message round trips, CloseSession cleanup and two update-result waits')


if __name__ == '__main__':
    main()
