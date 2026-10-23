# SPDX-License-Identifier: GPL-2.0-or-later
"""Run original SDK file open/read/close on a native task stack.

A temporary resource-8 callback supplies the diagnostic caller. Original
SDK senders, filesystem tasks and reply callbacks run without host answers.
The reference file is read only for comparison. Guest buffers are captured
through the monitor, hashed locally and removed after each block.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import require
from tools.card_slot_probe import linux, run as run_slots

CODE = 0x13F01000
OBJECT = 0xB5F00000
RESULT = OBJECT + 0x100
REQUEST = OBJECT + 0x180
ACTUAL = OBJECT + 0x18C
PATH_BUFFER = OBJECT + 0x200
READ_BUFFER = OBJECT + 0x10000
CHUNK = 0x80000
CALLBACK = 0xB1D603E0
ORIGINAL_CALLBACK = 0x10482BFD
FS_CALLBACK = 0xB1D27D30
FS_WORKER = 0xB1D1B08C
SDK_SUCCESS = 0x043A0080
UPDATE_SELECTOR = 0xB1887D10
UPDATE_ENTRY = OBJECT + 0x800


def caller_code(find_update=False):
    """Build a small Thumb caller; all file operations use firmware APIs."""
    code, literals, branches, labels = bytearray(), [], [], {}

    def emit(value):
        code.extend(struct.pack('<H', value))

    def literal(register, value):
        literals.append((len(code), register, value))
        emit(0)

    def branch(label, condition=1):
        branches.append((len(code), label, condition))
        emit(0)

    def label(name):
        labels[name] = len(code)

    def store_result(offset):
        emit(0x6000 | ((offset // 4) << 6) | (6 << 3))

    emit(0x680A)                  # ldr r2,[r1]
    emit(0x2A7F)                  # diagnostic operation 127
    branch('original')
    emit(0xB5F0)                  # push r4-r7,lr
    emit(0xB081)                  # preserve 8-byte stack alignment
    literal(4, OBJECT)
    literal(6, RESULT)
    if find_update:
        literal(0, 0x120A680C)    # original Z7_2_???.BIN pattern
        emit(0x2104)
        literal(2, UPDATE_ENTRY)
        literal(3, 0x1039C237)    # original update filename lookup
        emit(0x4798)
        store_result(24)
        emit(0x2801)
        branch('cleanup')
        literal(0, PATH_BUFFER + 3)
        literal(1, UPDATE_ENTRY)
        literal(3, 0x1039C219)    # original filename conversion
        emit(0x4798)
    emit(0x4620)
    literal(1, PATH_BUFFER)
    literal(3, 0x104D3C01)        # SDK object initializer
    emit(0x4798)
    store_result(0)
    emit(0x4620)
    emit(0x2100)
    emit(0x2200)
    literal(3, 0x104D3C05)        # SDK open
    emit(0x4798)
    store_result(4)
    literal(1, SDK_SUCCESS)
    emit(0x4288)
    branch('cleanup')
    emit(0x68A0)
    store_result(20)             # native file handle before close
    label('read')
    literal(3, ACTUAL)
    emit(0x2000)
    emit(0x6018)                 # clear actual count before each call
    emit(0x4620)
    literal(1, REQUEST)
    literal(2, CHUNK)
    literal(5, 0x104D3D83)        # SDK read
    emit(0x47A8)
    store_result(8)
    label('block')
    emit(0xBF00)
    label('continue')
    emit(0xBF00)
    literal(1, SDK_SUCCESS)
    emit(0x4288)
    branch('close')
    literal(0, ACTUAL)
    emit(0x6800)
    emit(0x2800)
    branch('read')
    label('close')
    emit(0x4620)
    literal(3, 0x104D3C91)        # SDK close
    emit(0x4798)
    store_result(12)
    label('cleanup')
    literal(0, READ_BUFFER)
    literal(1, CHUNK)
    literal(3, 0x10361035)        # native zeroing of the diagnostic buffer
    emit(0x4798)
    emit(0x2001)
    store_result(16)
    label('return')
    emit(0xB001)
    emit(0xBDF0)
    label('original')
    literal(3, ORIGINAL_CALLBACK)
    emit(0x4718)
    while len(code) % 4:
        emit(0xBF00)
    for offset, register, value in literals:
        distance = CODE + len(code) - ((CODE + offset + 4) & ~3)
        require(0 <= distance < 1024 and distance % 4 == 0, 'Caller literal is out of range')
        struct.pack_into('<H', code, offset, 0x4800 | (register << 8) | distance // 4)
        code.extend(struct.pack('<I', value))
    for offset, name, condition in branches:
        distance = labels[name] - offset - 4
        require(-256 <= distance <= 254 and distance % 2 == 0, 'Caller branch is out of range')
        struct.pack_into('<H', code, offset, 0xD000 | (condition << 8) | ((distance // 2) & 255))
    return bytes(code), {name: CODE + offset for name, offset in labels.items()}


def observe_sdk(remote, report, camera_path, reference, work, find_update=False):
    require(report['engine_fault_free'], 'Engine fault precedes SDK diagnostic')
    path = b'B:\\\0' if find_update else camera_path.encode('ascii') + b'\0'
    require(len(path) <= 128 and '\0' not in camera_path, 'Unsupported camera path')
    with reference.open('rb') as source:
        expected_sha256 = hashlib.file_digest(source, 'sha256').hexdigest()
    reference_size = reference.stat().st_size
    code, labels = caller_code(find_update)
    result = dict(caller_fixture=True, camera_path='B:\\' if find_update else camera_path,
        sdk_send_receive_native=True,
        sdk_replies_host_modeled=False, reference_bytes=reference_size,
        reference_sha256=expected_sha256, chunk_capacity=CHUNK, blocks=[], events=[],
        caller_code_bytes=len(code), caller_code_sha256=hashlib.sha256(code).hexdigest(),
        sdk_file_verified=False, eof_observed=False, caller_returned=False)
    result['update_lookup_requested'] = find_update
    report['sdk_file'] = result
    report['runtime_state_written'] = True
    report['native_menu_update_verified'] = False
    active = set()
    dump = Path(work) / 'sdk-block.bin'
    require(not dump.exists(), 'Diagnostic dump path is occupied')

    def word(address):
        return struct.unpack('<I', remote.read(address, 4))[0]

    def store(address, value):
        remote.write(address, struct.pack('<I', value))

    def monitor(command):
        response = remote.command('qRcmd,' + command.encode().hex())
        while response.startswith('O') and response != 'OK':
            response = remote.receive()
        require(response == 'OK', 'Monitor capture failed')

    def capture(address, size):
        require(not dump.exists(), 'Previous diagnostic dump was not removed')
        monitor('cpu 0')
        monitor(f'memsave {address:#x} {size:#x} ' + json.dumps(linux(dump)))
        try:
            data = dump.read_bytes()
            require(len(data) == size, 'Short monitor capture')
            return data
        finally:
            if dump.exists():
                dump.unlink()

    def arm(pc):
        remote.breakpoint(pc)
        active.add(pc)

    def disarm(pc):
        remote.breakpoint(pc, False)
        active.remove(pc)

    def resume():
        previous, stagnant = None, 0
        while True:
            remote.sock.settimeout(8)
            try:
                return remote.command('vCont;c')
            except TimeoutError:
                remote.interrupt()
                remote.select_thread(1)
                master = [word(0xB7CF0000 + offset) for offset in (8, 16)]
                remote.select_thread(3)
                slave = [word(0xC60F0000 + offset) for offset in (8, 16)]
                state = master + slave
                stagnant = stagnant + 1 if state == previous else 0
                previous = state
                result.setdefault('wait_samples', []).append(state)
                print('WAIT native SDK; message indices ' + str(state), flush=True)
                require(stagnant < 3, 'SDK wait made no message progress across repeated observations')

    remote.select_thread(1)
    require(word(CALLBACK) == ORIGINAL_CALLBACK and word(FS_CALLBACK) == 0x105BDF85 and
            word(FS_WORKER) == 0x105BDD09, 'Unexpected native service callbacks')
    saved, saved_code = remote.read(OBJECT, 0x1000), remote.read(CODE, len(code))
    selector = word(UPDATE_SELECTOR)
    require(not any(saved + saved_code), 'Diagnostic caller memory is occupied')
    require(not any(capture(READ_BUFFER, CHUNK)), 'Diagnostic read buffer is occupied')
    digest, total = hashlib.sha256(), 0
    stream_matches = True
    restored_sp = None
    closing = False
    try:
        remote.write(CODE, code)
        remote.write(REQUEST, struct.pack('<3I', 1, READ_BUFFER, CHUNK))
        remote.write(PATH_BUFFER, path)
        if find_update:
            result['update_selector_before'] = selector
            # Select SD while retaining the original other-root fallback flag.
            # A successful stream must still match the supplied reference file.
            result['update_selector_input'] = (selector & ~0xF) | 2
            store(UPDATE_SELECTOR, result['update_selector_input'])
            result['local_volumes_before'] = []
            for index in range(2):
                base = 0xB2B464C0 + index * 0x88
                result['local_volumes_before'].append(dict(index=index,
                    name=remote.read(base + 0xC, 12).split(b'\0')[0].decode('ascii', errors='replace'),
                    readiness=remote.read(base + 0x38, 1)[0],
                    filesystem_kind=remote.read(base + 0x3A, 1)[0]))
        store(CALLBACK, CODE | 1)
        for pc in (CODE, 0x104D3C04, 0x104D3D82, 0x104D3C90, 0x105BDF84,
                   labels['block'], labels['return']):
            arm(pc)
        if find_update:
            for pc in (0x1039C236, 0x1049D2E6, 0x1039C268, 0x1047E2FC):
                arm(pc)
        remote.select_thread(3)
        ring, sequence_address = 0xC60F0000, 0xC1006F74
        written, consumed = word(ring + 8), word(ring + 16)
        require(written < 192 and consumed < 192 and (written + 1) % 192 != consumed,
                'Peer trigger ring is full or invalid')
        sequence = word(sequence_address)
        remote.write(ring + 24 + written * 264, struct.pack('<IBBH', 127, 8, sequence & 255, 0))
        store(sequence_address, (sequence + 1) & 0xFFFFFFFF)
        store(ring + 8, (written + 1) % 192)
        store(0x20136008, 1)
        with reference.open('rb') as source:
            for _ in range(2 * (reference_size // CHUNK + 3) + 16):
                response = resume()
                match = re.search(r'thread:([0-9a-f]+)', response)
                require(match is not None, 'Missing SDK observation thread')
                thread = int(match[1], 16)
                remote.select_thread(thread)
                registers = remote.regs()
                pc = remote.get(registers, 'pc')
                require(pc in active, 'Unexpected SDK observation stop')
                disarm(pc)
                if pc == labels['block']:
                    status, count = word(RESULT + 8), word(ACTUAL)
                    require(count <= CHUNK, 'SDK read count exceeds capacity')
                    data = capture(READ_BUFFER, count) if count else b''
                    matches = data == source.read(count)
                    stream_matches &= matches
                    digest.update(data)
                    result['blocks'].append(dict(offset=total, bytes=count, sdk_status=hex(status),
                        sha256=hashlib.sha256(data).hexdigest(), reference_matches=matches))
                    total += count
                    closing = status != SDK_SUCCESS or count == 0
                    result['eof_observed'] = status == SDK_SUCCESS and count == 0
                    arm(labels['continue'])
                elif pc == labels['continue']:
                    if not closing:
                        arm(labels['block'])
                else:
                    result['events'].append(dict(pc=hex(pc), thread=thread,
                        sp=hex(remote.get(registers, 'sp')), lr=hex(remote.get(registers, 'lr'))))
                    if pc == CODE:
                        restored_sp = remote.get(registers, 'sp')
                    elif pc in (0x1039C236, 0x1049D2E6, 0x1039C268):
                        result['events'][-1]['r0'] = hex(remote.get(registers, 'r0'))
                    elif pc == 0x1047E2FC:
                        result['unregistered_volume_name'] = remote.read(
                            remote.get(registers, 'r6'), 12).split(b'\0')[0].decode('ascii')
                    elif pc == 0x105BDF84:
                        message = remote.get(registers, 'r1')
                        result['native_open_reply_operation'] = word(message)
                    elif pc == labels['return']:
                        result['sdk_results'] = list(struct.unpack('<6I', remote.read(RESULT, 24)))
                        if find_update:
                            result['update_lookup_result'] = word(RESULT + 24)
                            result['selected_path'] = remote.read(PATH_BUFFER, 128).split(b'\0')[0].decode('ascii')
                            result['selected_file_bytes'] = word(UPDATE_ENTRY + 0x218)
                        result['handle_after_close'] = word(OBJECT + 8)
                        result['read_buffer_cleared'] = not any(capture(READ_BUFFER, CHUNK))
                        return_pc = word(remote.get(registers, 'sp') + 20) & ~1
                        arm(return_pc)
                    elif pc not in (0x104D3C04, 0x104D3D82, 0x104D3C90):
                        require(remote.get(registers, 'sp') == restored_sp,
                                'SDK diagnostic caller did not restore its native task stack')
                        result['caller_returned'] = True
                        break
            else:
                raise ValueError('SDK read observation bound exceeded')
        result['actual_bytes'] = total
        result['actual_sha256'] = digest.hexdigest()
        result['stream_matches'] = stream_matches and total == reference_size
        statuses = result.get('sdk_results', [])
        result['sdk_file_verified'] = (result['caller_returned'] and result['eof_observed'] and
            len(statuses) == 6 and statuses[1:4] == [SDK_SUCCESS] * 3 and statuses[4] == 1 and
            result['handle_after_close'] == 0xFFFFFFFF and result['read_buffer_cleared'] and
            result['stream_matches'] and digest.hexdigest() == expected_sha256 and
            result.get('native_open_reply_operation') == 14)
        if find_update:
            result['sdk_file_verified'] &= result.get('update_lookup_result') == 1
    finally:
        remote.select_thread(1)
        store(CALLBACK, ORIGINAL_CALLBACK)
        if find_update:
            store(UPDATE_SELECTOR, selector)
            result['update_selector_restored'] = word(UPDATE_SELECTOR) == selector
        remote.write(OBJECT, saved)
        remote.write(CODE, saved_code)
        for pc in active:
            remote.breakpoint(pc, False)
        result['callbacks_restored'] = (word(CALLBACK) == ORIGINAL_CALLBACK and
            word(FS_CALLBACK) == 0x105BDF85 and word(FS_WORKER) == 0x105BDD09)
        result['faults_after'] = []
        for thread in (1, 2, 3, 4):
            remote.select_thread(thread)
            result['faults_after'].append(dict(thread=thread,
                status={name: hex(remote.read_register(name)) for name in ('DFSR_S', 'IFSR_S')}))
        result['fault_free_after'] = all(int(value, 0) == 0
            for state in result['faults_after'] for value in state['status'].values())
        report['passed'] = report['passed'] and result['sdk_file_verified'] and result['fault_free_after']
        if dump.exists():
            dump.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('qemu', 'master', 'slave', 'controller', 'card-image', 'reference', 'destination'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--camera-path', default='B:\\PROBE.TXT')
    parser.add_argument('--find-update', action='store_true',
                        help='Select the SD root and use the original update filename lookup')
    args = parser.parse_args()
    require(hashlib.sha256(args.master.read_bytes()).hexdigest() ==
            '478caf02dba41fa9144c0c4b6e1a051dc556d40e51a79a308bdd1169efb9dbbe',
            'SDK entry addresses require the supported master 1.70 image')
    require(hashlib.sha256(args.slave.read_bytes()).hexdigest() ==
            'e0d2589cf036bbf8ce6e4c32f5f2bab61fe35e863660bf6a0ee8082d8a64e1bb',
            'SDK entry addresses require the supported slave 1.70 image')
    args.qemu = str(args.qemu.resolve())
    args.registrations, args.window = 1, 12
    args.registration_only, args.ram_dump = True, None
    args.sd_card_image, args.sd_card_engine = args.card_image, 'slave'
    with tempfile.TemporaryDirectory(prefix='sdk-file-', dir=ROOT / '.local') as folder:
        args.work = Path(folder)
        report = run_slots(args, observe=lambda remote, result:
            observe_sdk(remote, result, args.camera_path, args.reference, args.work, args.find_update))
    require(report['sdk_file']['sdk_file_verified'], 'Native SDK file verification failed')
    print('PASS native SDK file open/read/EOF/close; menu and package authentication remain unverified')


if __name__ == '__main__':
    main()
