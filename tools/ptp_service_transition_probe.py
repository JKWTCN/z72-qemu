# SPDX-License-Identifier: GPL-2.0-or-later
"""Bound service-transition writes with synthetic context and task completion.

No camera access. Original service handlers run; subsystem cleanup and worker
completion are host boundaries. Preservation here does not prove retention
across the actual worker, USB reconnect, or menu cancellation.
"""
import argparse
from array import array
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import BASE, MASTER_SHA, require, validate_master
from analyze.firmware_structure import scatter_records, thumb_literal
from analyze.ptp_checksum_context import CONTEXT, CONTEXT_SIZE
from tools.ptp_service_probe import Probe
from unicorn import UC_HOOK_MEM_WRITE
from unicorn.arm_const import UC_ARM_REG_PC


def branch_candidates(image, targets):
    """Scan aligned Thumb BL/B.W encodings, including possible data matches."""
    words = array('H')
    words.frombytes(image[:len(image) // 2 * 2])
    if sys.byteorder != 'little':
        words.byteswap()
    result = {hex(target): [] for target in targets}
    for index in range(len(words) - 1):
        first, second = words[index], words[index + 1]
        if first & 0xF800 != 0xF000 or second & 0xD000 not in (0x9000, 0xD000):
            continue
        sign = first >> 10 & 1
        immediate = ((sign << 24) | ((1 ^ (second >> 13 & 1) ^ sign) << 23) |
                     ((1 ^ (second >> 11 & 1) ^ sign) << 22) |
                     ((first & 1023) << 12) | ((second & 2047) << 1))
        if sign:
            immediate -= 1 << 25
        target = (BASE + index * 2 + 4 + immediate) & 0xFFFFFFFF
        if target in targets:
            result[hex(target)].append(hex(BASE + index * 2))
    return result


def transition(image, action, initial_service=0, manager_result=0x2001,
               worker_success=True):
    probe = Probe(image)
    events, writes = [], []
    sentinel = bytes((17 * i + 3) & 255 for i in range(CONTEXT_SIZE))
    probe.u.mem_write(CONTEXT, sentinel)
    probe.put_word(probe.service, initial_service)

    def observe(u, access, address, size, value, unused):
        writes.append(dict(pc=hex(u.reg_read(UC_ARM_REG_PC)),
                           address=hex(address), bytes=size))

    probe.u.hook_add(UC_HOOK_MEM_WRITE, observe,
                     begin=CONTEXT, end=CONTEXT + CONTEXT_SIZE - 1)

    def boundary(name, value=0):
        def invoke(*args):
            events.append(dict(boundary=name, arguments=list(args)))
            return value
        return invoke

    # These subsystem routines are deliberately not represented as executed.
    cleanup = (0x4710AA, 0x470F3E, 0x492C00, 0x471990, 0x471B48,
               0x47263E, 0x492872, 0x4A6D36, 0x492544, 0x492F76,
               0x491CF2, 0x491BB8, 0x491E72, 0x7197F6)
    for offset in cleanup:
        probe.hooks[offset] = boundary(hex(BASE + offset))
    probe.hooks[0x3A09E8] = boundary('configuration 0x126', 0)
    probe.hooks[0x4E2EFA] = boundary('mode-manager request', manager_result)
    probe.hooks[0x3847AE] = boundary('object initialization', 0)
    probe.hooks[0x341034] = lambda destination, count, *args: zero(destination, count)
    probe.hooks[0x4A101C] = boundary('event reset')
    probe.hooks[0x3406E4] = boundary('worker event post')

    def zero(destination, count):
        require(count <= 0x100, 'Unexpected zero length')
        probe.u.mem_write(destination, bytes(count))
        return destination

    def completion(*args):
        events.append(dict(boundary='synthetic worker completion', success=worker_success))
        if not worker_success:
            return 1
        # Match the original completion callback and the original waiter.
        mode = probe.u.mem_read(thumb_literal(image, 0x363C2A, 2) - 8, 1)[0]
        probe.put_word(probe.service + 16, 0x03010004 if mode else 0x03010003)
        probe.put_word(probe.service + 20, 1)
        return 0

    probe.hooks[0x4A106E] = completion
    # The real request-post function executes and records mode/callback in RAM.
    if action == 'enter':
        probe.packet(0xF001, opcode=0x94FD)
        returned = probe.call(0x45994C, 0, probe.INPUT)
    else:
        probe.packet(0xF002, opcode=0x94FE)
        returned = probe.call(0x459A66, 0, probe.INPUT)
    retained = bytes(probe.u.mem_read(CONTEXT, CONTEXT_SIZE)) == sentinel
    require(retained and not writes, 'Service-handler context unexpectedly changed')
    expected = int(action == 'exit' or
                   (not initial_service and manager_result == 0x2001 and worker_success))
    require(returned == expected, 'Unexpected service transition result')
    return dict(action=action, initial_service=initial_service,
                supplied_manager_result=hex(manager_result), supplied_worker_success=worker_success,
                returned=returned, final_service=probe.word(probe.service),
                context_preserved=True, native_context_writes=writes,
                responses=probe.vendor_responses, host_calls=events)


def worker_bridge(image, mode):
    """Execute the original dispatcher and bridge up to a synthetic receiver."""
    probe = Probe(image)
    sentinel = bytes(range(1, CONTEXT_SIZE + 1))
    probe.u.mem_write(CONTEXT, sentinel)
    probe.call(0x363BBC, probe.call(0x1E6CA4))
    receiver = probe.INPUT + 0x2E000
    probe.call(0x1E6CBA, receiver | 1, 0x1234)
    messages = []

    def capture(message, cookie, *args):
        payload = probe.word(message + 4)
        messages.append(dict(request_type=probe.u.mem_read(message, 1)[0],
                             mode=probe.word(payload), cookie=cookie,
                             completion_callback=hex(probe.word(payload + 4))))
        return 1

    probe.hooks[receiver - BASE] = capture
    probe.u.mem_write(0xB18A7B7C, bytes([mode]))
    probe.call(0x3638A2, 0x40)
    require(len(messages) == 1 and messages[0]['request_type'] == 3 and
            messages[0]['mode'] == mode and messages[0]['cookie'] == 0x1234,
            'Worker-to-mode bridge binding changed')
    require(bytes(probe.u.mem_read(CONTEXT, CONTEXT_SIZE)) == sentinel,
            'Worker dispatcher changed the synthetic context')
    return dict(mode=mode, messages=messages, context_preserved=True,
                final_mode_receiver_executed=False)


def run(image):
    validate_master(image)
    initialization = [record for record in scatter_records(image)
                      if record['destination'] <= CONTEXT and
                      CONTEXT + CONTEXT_SIZE <= record['destination'] + record['size']]
    require(len(initialization) == 1 and initialization[0]['kind'] == 'zero',
            'Context initialization binding changed')
    branches = branch_candidates(image, {0x103AED1C, 0x10383C26, 0x10383BBC})
    require(branches['0x103aed1c'] == ['0x1039c66e'], 'Context-reset callers changed')
    require(branches['0x10383c26'] == ['0x10479924'], 'Service-post callers changed')
    return dict(format=1, firmware_included=False, master_sha256=MASTER_SHA,
                context_address=hex(CONTEXT), context_bytes=CONTEXT_SIZE,
                startup_initialization=initialization[0], direct_branch_candidates=branches,
                native_cases=[transition(image, 'enter'),
                              transition(image, 'enter', initial_service=1),
                              transition(image, 'enter', manager_result=0x2019),
                              transition(image, 'enter', worker_success=False),
                              transition(image, 'exit', initial_service=1),
                              transition(image, 'exit')],
                worker_bridge_cases=[worker_bridge(image, mode) for mode in (0, 1)],
                async_request=dict(entry='0x10383c26', worker_flag='0x40',
                                   state='0xb18a7b7c', vtable_slot='0x1c',
                                   bridge='0x10206e04', bridge_request_type=3),
                worker_dispatcher_executed=True, actual_mode_receiver_executed=False,
                menu_cancel_executed=False,
                actual_camera_access=False, boot_material_recovered=False,
                limitations=[
                    'Subsystem cleanup, mode-manager and worker completion are host boundaries.',
                    'A preserved synthetic context proves only the covered native handler instructions.',
                    'Aligned direct-branch scanning includes data; indirect calls and broad clears are not excluded.',
                    'The worker dispatcher and bridge execute; the final registered mode receiver is synthetic.',
                    'USB reconnect, actual menu cancellation and screen behavior remain unverified.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = run(args.master.read_bytes())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('PASS six service-handler cases and two worker bridges; final mode receiver and menu remain outside scope')


if __name__ == '__main__':
    main()
