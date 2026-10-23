# SPDX-License-Identifier: GPL-2.0-or-later
"""Run original update candidate collection through native SDK directory I/O.

A temporary resource-8 caller invokes the original collection entry on its
native task stack. Directory records, file reads, candidate classification,
allocation and release are executed by firmware. This diagnostic does not
invoke the menu, authenticate a package or program storage.
"""
import argparse
import hashlib
import re
import struct
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import require
from tools.card_slot_probe import run as run_slots
from tools.sdk_file_probe import (CODE, OBJECT, CALLBACK, ORIGINAL_CALLBACK,
                                 FS_CALLBACK, FS_WORKER, UPDATE_SELECTOR)

SUMMARY = OBJECT + 0x400
UPDATE_STATE = 0xB1887C80
PACKAGE_RECORD = 0xB25EC904 + 13 * 0x1CC


def caller_code():
    """Build the diagnostic Thumb caller; collection itself is original code."""
    code, literals = bytearray(), []

    def emit(value):
        code.extend(struct.pack('<H', value))

    def literal(register, value):
        literals.append((len(code), register, value))
        emit(0)

    emit(0x680A)                 # ldr r2,[r1]
    emit(0x2A7F)                 # diagnostic operation 127
    emit(0)                      # bne original
    emit(0xB5F0)                 # push r4-r7,lr
    emit(0xB081)                 # preserve 8-byte stack alignment
    emit(0x2000)                 # collection mode 0
    literal(1, SUMMARY)
    literal(3, 0x1039D985)
    emit(0x4798)
    literal(1, OBJECT)
    emit(0x6008)                 # store original return value
    emit(0x2001)
    emit(0x6048)                 # completion marker
    done = CODE + len(code)
    emit(0xB001)
    emit(0xBDF0)
    original = len(code)
    literal(3, ORIGINAL_CALLBACK)
    emit(0x4718)
    struct.pack_into('<H', code, 4, 0xD100 | ((original - 8) // 2))
    while len(code) % 4:
        emit(0xBF00)
    for offset, register, value in literals:
        distance = CODE + len(code) - ((CODE + offset + 4) & ~3)
        require(0 <= distance < 1024 and distance % 4 == 0, 'Caller literal is out of range')
        struct.pack_into('<H', code, offset, 0x4800 | (register << 8) | distance // 4)
        code.extend(struct.pack('<I', value))
    return bytes(code), done


def observe_collection(remote, report, expected_path):
    require(report['engine_fault_free'], 'Engine fault precedes update collection')
    code, done = caller_code()
    result = dict(caller_fixture=True, requested_mode=0, expected_path=expected_path,
        sdk_replies_host_modeled=False, directory_records_host_supplied=False,
        caller_code_sha256=hashlib.sha256(code).hexdigest(), events=[],
        caller_returned=False, collection_verified=False)
    report['collection'] = result
    report['runtime_state_written'] = True
    report['native_menu_update_verified'] = False
    report['native_package_authentication_verified'] = False
    active = set()

    def word(address):
        return struct.unpack('<I', remote.read(address, 4))[0]

    def store(address, value):
        remote.write(address, struct.pack('<I', value))

    def string(address, size=256):
        return remote.read(address, size).split(b'\0')[0].decode('ascii', errors='replace')

    def arm(pc):
        remote.breakpoint(pc)
        active.add(pc)

    remote.select_thread(1)
    require(word(CALLBACK) == ORIGINAL_CALLBACK and word(FS_CALLBACK) == 0x105BDF85 and
            word(FS_WORKER) == 0x105BDD09, 'Unexpected native service callbacks')
    saved, saved_code = remote.read(OBJECT, 0x1000), remote.read(CODE, len(code))
    selector = word(UPDATE_SELECTOR)
    require(not any(saved + saved_code), 'Diagnostic caller memory is occupied')
    require(word(UPDATE_STATE + 0x44) == word(UPDATE_STATE + 0x48) == 0,
            'Update collection already owns directory buffers')
    result['selector_before'] = selector
    result['selector_input'] = (selector & ~0xF) | 2
    result['local_volumes_before'] = [dict(index=index,
        name=string(0xB2B464C0 + index * 0x88 + 0xC, 12),
        readiness=remote.read(0xB2B464C0 + index * 0x88 + 0x38, 1)[0])
        for index in range(2)]
    try:
        remote.write(CODE, code)
        store(CALLBACK, CODE | 1)
        store(UPDATE_SELECTOR, result['selector_input'])
        # Record the first visit to each stage without changing guest registers.
        for pc in (CODE, done, 0x1039D984, 0x1039D940, 0x104D3EF0, 0x104D3E92,
                   0x1039D6B4, 0x1039D71C, 0x104D3C04, 0x1039D5BC,
                   0x1039D4D4, 0x1039DA30, 0x1039DA44, 0x1039D922):
            arm(pc)
        remote.select_thread(3)
        ring, sequence_address = 0xC60F0000, 0xC1006F74
        written, consumed = word(ring + 8), word(ring + 16)
        require(written < 192 and consumed < 192 and (written + 1) % 192 != consumed,
                'Peer trigger ring is full or invalid')
        sequence = word(sequence_address)
        remote.write(ring + 24 + written * 264,
                     struct.pack('<IBBH', 127, 8, sequence & 255, 0))
        store(sequence_address, (sequence + 1) & 0xFFFFFFFF)
        store(ring + 8, (written + 1) % 192)
        store(0x20136008, 1)
        previous, stagnant, entry_sp, return_pc = None, 0, None, None
        for _ in range(80):
            remote.sock.settimeout(12)
            try:
                response = remote.command('vCont;c')
            except TimeoutError:
                # Continue the same live instance after sampling both queues.
                remote.interrupt()
                sample = []
                for thread, base in ((1, 0xB7CF0000), (3, 0xC60F0000)):
                    remote.select_thread(thread)
                    sample.extend([word(base + 8), word(base + 16)])
                stagnant = stagnant + 1 if sample == previous else 0
                previous = sample
                result.setdefault('wait_samples', []).append(sample)
                print('WAIT native collection; message indices ' + str(sample), flush=True)
                require(stagnant < 3, 'Collection wait made no message progress across repeated observations')
                continue
            match = re.search(r'thread:([0-9a-f]+)', response)
            require(match is not None, 'Missing collection observation thread')
            thread = int(match[1], 16)
            remote.select_thread(thread)
            registers = remote.regs()
            pc, r0 = (remote.get(registers, name) for name in ('pc', 'r0'))
            require(pc in active, 'Unexpected collection observation stop')
            remote.breakpoint(pc, False)
            active.remove(pc)
            event = dict(pc=hex(pc), thread=thread, sp=hex(remote.get(registers, 'sp')),
                         r0=hex(r0), r1=hex(remote.get(registers, 'r1')))
            result['events'].append(event)
            print('COLLECT ' + str(event), flush=True)
            if pc == CODE:
                entry_sp = remote.get(registers, 'sp')
            elif pc in (0x104D3EF0, 0x104D3E92, 0x104D3C04):
                # The SDK file object stores its path pointer at offset zero.
                event['path'] = string(word(r0) if pc == 0x104D3C04 else r0)
            elif pc == 0x1039D6B4 and r0:
                event['short_name'] = string(r0, 14)
                event['file_bytes'] = struct.unpack('<Q', remote.read(r0 + 0x218, 8))[0]
                event['attributes'] = remote.read(r0 + 0x20E, 1)[0]
            elif pc in (0x1039DA30, 0x1039DA44):
                event['directory_path'] = string(0xB25EC802)
            elif pc == done:
                result['returned'] = word(OBJECT)
                result['completed'] = word(OBJECT + 4)
                result['summary_head'] = word(SUMMARY)
                result['collected_count'] = word(UPDATE_STATE + 0x60)
                result['matching_count'] = word(UPDATE_STATE + 0x4C)
                result['record_path'] = string(PACKAGE_RECORD)
                result['record_package_flag'] = word(PACKAGE_RECORD + 0x1C4)
                result['record_category'] = remote.read(PACKAGE_RECORD + 0x1C8, 1)[0]
                result['record_sha256'] = hashlib.sha256(remote.read(PACKAGE_RECORD, 0x1CC)).hexdigest()
                result['allocation_pointers_after'] = [word(UPDATE_STATE + offset) for offset in (0x44, 0x48)]
                return_pc = word(remote.get(registers, 'sp') + 20) & ~1
                arm(return_pc)
            elif pc == return_pc:
                require(remote.get(registers, 'sp') == entry_sp, 'Collection caller did not restore task stack')
                result['caller_returned'] = True
                break
        else:
            raise ValueError('Collection observation bound exceeded')
        path_matches = result['record_path'] == expected_path
        candidate_matches = (result['matching_count'] == 1 and
            result['record_package_flag'] == 1 and result['record_category'] == 4) if expected_path else (
            result['matching_count'] == 0 and result['record_package_flag'] == result['record_category'] == 0)
        stages = {int(event['pc'], 0) for event in result['events']}
        required_stages = {0x1039D984, 0x1039D940, 0x104D3EF0, 0x104D3E92,
                           0x1039D71C, 0x1039D922}
        if expected_path:
            required_stages |= {0x1039D6B4, 0x104D3C04, 0x1039D5BC, 0x1039D4D4}
        result['collection_verified'] = (result['returned'] == result['completed'] == 1 and
            result['caller_returned'] and result['summary_head'] == 19 and
            result['allocation_pointers_after'] == [0, 0] and required_stages <= stages and
            path_matches and candidate_matches)
    finally:
        remote.select_thread(1)
        store(CALLBACK, ORIGINAL_CALLBACK)
        store(UPDATE_SELECTOR, selector)
        remote.write(OBJECT, saved)
        remote.write(CODE, saved_code)
        for pc in active:
            remote.breakpoint(pc, False)
        result['selector_restored'] = word(UPDATE_SELECTOR) == selector
        result['callbacks_restored'] = (word(CALLBACK) == ORIGINAL_CALLBACK and
            word(FS_CALLBACK) == 0x105BDF85 and word(FS_WORKER) == 0x105BDD09)
        result['faults_after'] = []
        for thread in (1, 2, 3, 4):
            remote.select_thread(thread)
            result['faults_after'].append(dict(thread=thread,
                status={name: hex(remote.read_register(name)) for name in ('DFSR_S', 'IFSR_S')}))
        result['fault_free_after'] = all(int(value, 0) == 0
            for state in result['faults_after'] for value in state['status'].values())
        report['passed'] = (report['passed'] and result['collection_verified'] and
            result['callbacks_restored'] and result['selector_restored'] and result['fault_free_after'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('qemu', 'master', 'slave', 'controller', 'card-image', 'destination'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--expected-path', default='',
                        help='Expected whole-camera candidate path; default requires no matching package')
    args = parser.parse_args()
    for role, expected in (
        ('master', '478caf02dba41fa9144c0c4b6e1a051dc556d40e51a79a308bdd1169efb9dbbe'),
        ('slave', 'e0d2589cf036bbf8ce6e4c32f5f2bab61fe35e863660bf6a0ee8082d8a64e1bb')):
        require(hashlib.sha256(getattr(args, role).read_bytes()).hexdigest() == expected,
                'Collection entry addresses require the supported ' + role + ' 1.70 image')
    args.qemu = str(args.qemu.resolve())
    args.registrations, args.window = 1, 12
    args.registration_only, args.ram_dump = True, None
    args.sd_card_image, args.sd_card_engine = args.card_image, 'slave'
    with tempfile.TemporaryDirectory(prefix='update-collect-', dir=ROOT / '.local') as folder:
        args.work = Path(folder)
        run_slots(args, observe=lambda remote, report: observe_collection(remote, report, args.expected_path))
    print('PASS native update collection; menu, authentication and programming remain unverified')


if __name__ == '__main__':
    main()
