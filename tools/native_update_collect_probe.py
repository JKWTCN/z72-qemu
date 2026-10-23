# SPDX-License-Identifier: GPL-2.0-or-later
"""Run original update candidate collection through native SDK directory I/O.

A temporary resource-8 caller invokes the original collection entry on its
native task stack. Directory records, file reads, candidate classification,
allocation and release are executed by firmware. The optional service case
also checks native authentication rejection with default laboratory boot
material. It does not establish menu dispatch or installation acceptance.
"""
import argparse
import hashlib
import json
import re
import struct
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import require
from tools.card_slot_probe import linux, run as run_slots
from tools.sdk_file_probe import (CODE, OBJECT, CALLBACK, ORIGINAL_CALLBACK,
                                 FS_CALLBACK, FS_WORKER, UPDATE_SELECTOR)

SUMMARY = OBJECT + 0x400
UPDATE_STATE = 0xB1887C80
PACKAGE_RECORD = 0xB25EC904 + 13 * 0x1CC


def caller_code(execute_service=False):
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
    if execute_service:
        emit(0x2000)
        literal(3, 0x104E08C5)    # original card-log initialization
        emit(0x4798)
        literal(1, OBJECT)
        emit(0x6188)
        emit(0x200D)             # select the whole-camera record
        literal(3, 0x1039DAA5)
        emit(0x4798)
        emit(0x2000)
        emit(0x2100)
        literal(2, OBJECT + 8)
        literal(3, 0x10767049)    # original service propriety check
        emit(0x4798)
        literal(1, OBJECT)
        emit(0x60C8)
        emit(0x2801)             # execute only after the propriety check succeeds
        skip_execute = len(code)
        emit(0)
        literal(2, OBJECT + 16)
        literal(3, 0x10767109)    # original service execute request
        emit(0x4798)
        literal(1, OBJECT)
        emit(0x6148)
        struct.pack_into('<H', code, skip_execute,
                         0xD100 | ((len(code) - skip_execute - 4) // 2))
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


def observe_collection(remote, report, expected_path, execute_service=False):
    require(report['engine_fault_free'], 'Engine fault precedes update collection')
    require(not execute_service or expected_path, 'Service observation requires a candidate path')
    code, done = caller_code(execute_service)
    result = dict(caller_fixture=True, requested_mode=0, expected_path=expected_path,
        sdk_replies_host_modeled=False, directory_records_host_supplied=False,
        caller_code_sha256=hashlib.sha256(code).hexdigest(), events=[],
        caller_returned=False, collection_verified=False, service_requested=execute_service,
        authentication_rejection_verified=False)
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

    def buffer_digest(address, size, thread):
        require(0 < size <= 0x3C00000, 'Whole-file capture exceeds the native allocation')

        def monitor(command):
            # A slow monitor capture stays on the same command and connection.
            try:
                response = remote.command('qRcmd,' + command.encode().hex())
            except TimeoutError:
                response = None
            while response is None or (response.startswith('O') and response != 'OK'):
                try:
                    response = remote.receive()
                except TimeoutError:
                    print('WAIT native buffer capture', flush=True)
            require(response == 'OK', 'Native whole-file capture failed')

        with tempfile.TemporaryDirectory(prefix='service-bytes-', dir=ROOT / '.local') as folder:
            path = Path(folder) / 'buffer.bin'
            monitor(f'cpu {thread - 1}')
            digest = hashlib.sha256()
            for offset in range(0, size, 0x80000):
                count = min(0x80000, size - offset)
                monitor(f'memsave {address + offset:#x} {count:#x} ' + json.dumps(linux(path)))
                data = path.read_bytes()
                require(len(data) == count, 'Short native whole-file capture')
                digest.update(data)
                path.unlink()
            return digest.hexdigest()

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
    if execute_service:
        result['log_buffer_before'] = hex(word(0xB181A4F4))
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
        if execute_service:
            for pc in (0x1039DAA4, 0x10767048, 0x10767054, 0x10767108,
                       0x104E08C4,
                       0x103F6474, 0x103F6482, 0x103F6520, 0x103F60CA,
                       0x103F6526, 0x103F6938, 0x1039C638, 0x1039C334,
                       0x1039C64A, 0x103AD2C2, 0x1039C668, 0x103AED3E,
                       0x103AFE82, 0x1039C6A4, 0x103F6962, 0x103F6982,
                       0x103F6588, 0x103F659E):
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
        for _ in range(256 if execute_service else 80):
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
                if execute_service:
                    # Large original decode/SHA loops do not advance message queues.
                    states = []
                    for engine_thread in (1, 2, 3, 4):
                        remote.select_thread(engine_thread)
                        current = remote.regs()
                        state = dict(thread=engine_thread, pc=hex(remote.get(current, 'pc')),
                            faults={name: hex(remote.read_register(name)) for name in ('DFSR_S', 'IFSR_S')})
                        if 0x103AD2C2 <= int(state['pc'], 0) < 0x103AD360:
                            state['decode_pointer'] = hex(remote.get(current, 'r0'))
                        states.append(state)
                    result.setdefault('compute_samples', []).append(states)
                    require(all(int(value, 0) == 0 for state in states for value in state['faults'].values()),
                            'Native engine fault during service execution')
                    print('COMPUTE ' + str(states), flush=True)
                else:
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
            elif pc == 0x103F6526:
                result['native_package_buffer'] = hex(r0)
                require(not r0 or not r0 <= OBJECT < r0 + 0x3C00000,
                        'Native package allocation overlaps diagnostic scratch')
            elif pc == 0x1039C638:
                if 0x103AD2C2 not in active:
                    arm(0x103AD2C2)
            elif pc == 0x1039C334:
                count = word(remote.get(registers, 'sp'))
                result['native_whole_read'] = dict(status=hex(r0), actual_bytes=count,
                    requested_bytes=remote.get(registers, 'r5'))
                require(r0 == 0x043A0080 and count == remote.get(registers, 'r5'),
                        'Original whole-package read did not complete successfully')
                result['native_whole_read']['sha256'] = buffer_digest(remote.get(registers, 'r8'), count, thread)
            elif pc == 0x103AED3E:
                require(r0 == 0x10000088, 'Unexpected whole-package boot-material source')
                result['boot_material_zero'] = remote.read(r0, 8) == bytes(8)
            elif pc == 0x1039C6A4:
                result['native_digest_result'] = r0
            elif pc == 0x103F6962:
                result['native_package_result'] = r0
            elif pc == 0x103F6982:
                result['completion_event'] = dict(address=hex(r0), mask=hex(remote.get(registers, 'r1')))
            elif pc == 0x103F6588:
                result['consumed_event_mask'] = hex(word(remote.get(registers, 'sp') + 0x44))
            elif pc == done:
                if execute_service:
                    result['service_request'] = dict(
                        log_init_return=word(OBJECT + 24), log_buffer_after=hex(word(0xB181A4F4)),
                        propriety_return=word(OBJECT + 12), propriety_reason=word(OBJECT + 8),
                        execute_return=word(OBJECT + 20), execute_reason=word(OBJECT + 16),
                        buffer_owner_after=word(0xB1887D20 + 0x2C),
                        updater_status=int.from_bytes(remote.read(0xB1887D22, 2), 'little'))
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
        if execute_service:
            service, whole_read = result['service_request'], result.get('native_whole_read', {})
            service_stages = {0x1039DAA4, 0x10767048, 0x10767108, 0x103F60CA,
                0x104E08C4,
                0x103F6938, 0x1039C638, 0x1039C334, 0x1039C668, 0x103AED3E,
                0x103AFE82, 0x1039C6A4, 0x103F6962, 0x103F6982, 0x103F6588}
            result['authentication_rejection_verified'] = (
                service_stages <= stages and service['log_init_return'] == 1 and
                int(service['log_buffer_after'], 0) != 0 and service['propriety_return'] == 1 and
                service['propriety_reason'] == 0 and service['execute_return'] == 3 and
                service['execute_reason'] == 5 and service['buffer_owner_after'] == 0 and
                service['updater_status'] == result.get('native_package_result') == 3 and
                result.get('native_digest_result') == 0 and result.get('boot_material_zero') is True and
                result.get('completion_event') == dict(address='0xb1887d24', mask='0x20') and
                result.get('consumed_event_mask') == '0x20' and whole_read.get('status') == '0x43a0080' and
                whole_read.get('actual_bytes') == whole_read.get('requested_bytes') == word(PACKAGE_RECORD + 0x100))
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
                pc=hex(remote.get(remote.regs(), 'pc')),
                address={name: hex(remote.read_register(name)) for name in ('DFAR_S', 'IFAR_S')},
                status={name: hex(remote.read_register(name)) for name in ('DFSR_S', 'IFSR_S')}))
        result['fault_free_after'] = all(int(value, 0) == 0
            for state in result['faults_after'] for value in state['status'].values())
        report['passed'] = (report['passed'] and result['collection_verified'] and
            result['callbacks_restored'] and result['selector_restored'] and result['fault_free_after'] and
            (not execute_service or result['authentication_rejection_verified']))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('qemu', 'master', 'slave', 'controller', 'card-image', 'destination'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--expected-path', default='',
                        help='Expected whole-camera candidate path; default requires no matching package')
    parser.add_argument('--execute-service', action='store_true',
                        help='Also verify native service authentication rejection with default lab boot material')
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
        run_slots(args, observe=lambda remote, report:
                  observe_collection(remote, report, args.expected_path, args.execute_service))
    print('PASS native service authentication rejection; installation remains unverified' if args.execute_service
          else 'PASS native update collection; menu, authentication and programming remain unverified')


if __name__ == '__main__':
    main()
