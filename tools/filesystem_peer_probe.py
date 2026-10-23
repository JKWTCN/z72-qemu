# SPDX-License-Identifier: GPL-2.0-or-later
"""Check native peer file open/read with explicit message-queue inputs.

The SDK sender and menu caller are absent. Queue requests are synthetic;
native peer tasks, card access and data transfer run in the dual machine.
The local reference supplies comparison bytes only, never guest file data.
Open/read replies belong to the host client fixture. The original master
dispatcher handles the peer's data-copy request and its acknowledgement.
"""
import argparse
import hashlib
from pathlib import Path
import re
import struct
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import require
from tools.card_slot_probe import run as run_slots

RING = 0xB7CF0000
SEQUENCE = 0xB1808934
PATH_BUFFER = 0xB5F00200
READ_BUFFER = 0xB5F00400
PEER_DISPATCH = 0x1006323C
PEER_OPEN = 0x10065074
MASTER_REPLY = 0x105BDF84
PEER_SEND = 0x100677DA
COPY_MEMORY = 0x105BC398
COPY_RETURN = 0x105BC452


def observe_file(remote, report, camera_path, reference):
    require(report['engine_fault_free'], 'Engine fault precedes file request')
    encoded = camera_path.encode('ascii') + b'\0'
    require(len(encoded) <= 128 and '\0' not in camera_path, 'Unsupported camera path')
    with reference.open('rb') as source:
        expected = source.read(64)
    require(bool(expected), 'Reference must contain at least one byte')
    result = dict(input_frames_synthetic=True, sdk_sender_executed=False,
        menu_caller_executed=False, open_reply_client_host_modeled=True,
        read_reply_observation='Native sender entry; reply not yet queued',
        read_reply_consumed_by_sdk=False,
        camera_path=camera_path, expected_bytes=len(expected),
        expected_sha256=hashlib.sha256(expected).hexdigest(), events=[],
        file_prefix_verified=False)
    report['file_service'] = result
    report['native_menu_update_verified'] = False
    report['runtime_state_written'] = True
    active = set()

    def word(address):
        return struct.unpack('<I', remote.read(address, 4))[0]

    def store(address, value):
        remote.write(address, struct.pack('<I', value))

    def memory_channels():
        return [list(struct.unpack('<13I', remote.read(0x20070000 + channel * 0x40, 0x34)))
                for channel in range(2)]

    def arm(address):
        remote.breakpoint(address)
        active.add(address)

    def disarm(address):
        remote.breakpoint(address, False)
        active.remove(address)

    def submit(operation, payload):
        remote.select_thread(1)
        written, consumed = word(RING + 8), word(RING + 16)
        require(written < 192 and consumed < 192 and (written + 1) % 192 != consumed,
                'Peer request ring is full or invalid')
        sequence = word(SEQUENCE)
        frame = struct.pack('<IBBH', operation, 9, sequence & 255, len(payload)) + payload
        remote.write(RING + 24 + written * 264, frame)
        store(SEQUENCE, (sequence + 1) & 0xFFFFFFFF)
        store(RING + 8, (written + 1) % 192)
        store(0x20136008, 1)

    def resume(command):
        remote.sock.settimeout(8)
        try:
            response = remote.command(command)
        except TimeoutError:
            remote.interrupt()
            raise ValueError('Native peer file response timed out')
        match = re.search(r'thread:([0-9a-f]+)', response)
        require(match is not None, 'Missing response execution thread')
        thread = int(match[1], 16)
        remote.select_thread(thread)
        registers = remote.regs()
        pc = remote.get(registers, 'pc')
        event = dict(thread=thread, pc=hex(pc),
                     arguments=[remote.get(registers, f'r{i}') for i in range(4)])
        result['events'].append(event)
        require(pc in active, 'Unexpected native response stop')
        disarm(pc)
        return pc, thread, event['arguments']

    remote.select_thread(1)
    saved_path = remote.read(PATH_BUFFER, 128)
    saved_buffer = remote.read(READ_BUFFER, 128)
    require(not any(saved_path + saved_buffer), 'Diagnostic RAM buffers are occupied')
    try:
        remote.write(PATH_BUFFER, encoded.ljust(128, b'\0'))
        result['indices_before'] = [word(RING + 8), word(RING + 16)]
        for address in (PEER_DISPATCH, PEER_OPEN, MASTER_REPLY):
            arm(address)
        submit(13, struct.pack('<7I', 0, 0, PATH_BUFFER, 0, 0, 0, 0))
        for _ in range(3):
            pc, thread, arguments = resume('vCont;c')
            if pc in (PEER_DISPATCH, MASTER_REPLY):
                words = struct.unpack('<5I', remote.read(arguments[1], 20))
                result['events'][-1]['message_words'] = list(words)
                require(arguments[0] == 0x42070001, 'Unexpected resource message identity')
                require(words[0] == (14 if pc == MASTER_REPLY else 13),
                        'Unexpected peer file operation')
            if pc == MASTER_REPLY:
                handle = words[4]
                result['open_reply_handle'] = handle
                require(handle < 0x80000000, 'Native peer file open failed')
                reply_thread = thread
                break
        else:
            raise ValueError('Native open reply was not observed')

        # This queue client has no SDK request context. Consume its open
        # reply at the callback boundary, preserving the real return stack.
        # Data-copy messages below still execute the original dispatcher.
        remote.select_thread(reply_thread)
        registers = remote.regs()
        return_pc = remote.get(registers, 'lr')
        cpsr = (remote.get(registers, 'cpsr') & ~0x20) | ((return_pc & 1) << 5)
        remote.set(pc=return_pc & ~1, cpsr=cpsr)
        arm(PEER_SEND)
        arm(MASTER_REPLY)
        submit(15, struct.pack('<4I', READ_BUFFER, 0, 64, handle))
        for _ in range(6):
            pc, thread, arguments = resume('vCont;c')
            if pc == PEER_SEND and arguments[:3] == [9, 19, 12]:
                result['copy_request_words'] = list(struct.unpack(
                    '<3I', remote.read(arguments[3], 12)))
                source = result['copy_request_words'][1]
                result['peer_source_sha256'] = hashlib.sha256(
                    remote.read(source, len(expected))).hexdigest()
            elif pc == MASTER_REPLY:
                words = struct.unpack('<2I', remote.read(arguments[1], 8))
                require(arguments[0] == 0x42070001 and words[0] == 19,
                        'Unexpected master data-copy request')
                result['native_copy_dispatch_entered'] = True
                arm(PEER_SEND)
                arm(COPY_MEMORY)
            elif pc == COPY_MEMORY:
                result['native_copy_arguments'] = arguments[:3]
                result['memory_channels_before'] = memory_channels()
                try:
                    source = remote.read(arguments[1], len(expected))
                except ValueError:
                    # A DMA bus address need not be mapped by the CPU MMU.
                    result['translated_source_debug_readable'] = False
                else:
                    result['translated_source_debug_readable'] = True
                    result['translated_source_sha256'] = hashlib.sha256(source).hexdigest()
                arm(PEER_DISPATCH)
                arm(COPY_RETURN)
            elif pc == COPY_RETURN:
                result['memory_transfer_status'] = arguments[0]
                result['memory_channels_after'] = memory_channels()
            elif pc == PEER_DISPATCH:
                words = struct.unpack('<5I', remote.read(arguments[1], 20))
                require(arguments[0] == 0x42070001 and words[0] == 20,
                        'Unexpected peer data-copy acknowledgement')
                result['copy_ack_status'] = struct.unpack('<i', struct.pack('<I', words[4]))[0]
            else:
                require(pc == PEER_SEND and arguments[:3] == [9, 16, 16],
                        'Unexpected native read response sender')
                break
        else:
            raise ValueError('Native read response was not observed')
        words = struct.unpack('<4I', remote.read(arguments[3], 16))
        result['read_reply_words'] = list(words)
        result['read_status'] = struct.unpack('<i', struct.pack('<I', words[2]))[0]
        remote.select_thread(1)
        result['indices_after'] = [word(RING + 8), word(RING + 16)]
        if result['read_status'] == 0:
            require(words[3] <= 64, 'Native read count exceeds the requested capacity')
            data = remote.read(READ_BUFFER, words[3])
            result['actual_bytes'] = len(data)
            result['actual_sha256'] = hashlib.sha256(data).hexdigest()
            result['file_bytes_match'] = data == expected
            result['file_prefix_verified'] = data == expected and result.get('copy_ack_status') == 0
        report['passed'] = report['passed'] and result['file_prefix_verified']
    finally:
        remote.select_thread(1)
        remote.write(PATH_BUFFER, saved_path)
        remote.write(READ_BUFFER, saved_buffer)
        for address in active:
            remote.breakpoint(address, False)
        result['buffers_restored'] = True
        result['faults_after'] = []
        for thread in (1, 2, 3, 4):
            remote.select_thread(thread)
            result['faults_after'].append(dict(thread=thread,
                status={name: hex(remote.read_register(name))
                        for name in ('DFSR_S', 'IFSR_S')}))
        result['fault_free_after'] = all(
            int(value, 0) == 0 for state in result['faults_after']
            for value in state['status'].values())
        report['passed'] = report['passed'] and result['fault_free_after']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('qemu', 'master', 'slave', 'controller', 'card-image', 'reference', 'destination'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--camera-path', default='B:\\PROBE.TXT')
    args = parser.parse_args()
    require(hashlib.sha256(args.master.read_bytes()).hexdigest() ==
            '478caf02dba41fa9144c0c4b6e1a051dc556d40e51a79a308bdd1169efb9dbbe',
            'Peer entry addresses require the supported master 1.70 image')
    require(hashlib.sha256(args.slave.read_bytes()).hexdigest() ==
            'e0d2589cf036bbf8ce6e4c32f5f2bab61fe35e863660bf6a0ee8082d8a64e1bb',
            'Peer entry addresses require the supported slave 1.70 image')
    args.qemu = str(args.qemu.resolve())
    args.registrations, args.window = 1, 12
    args.registration_only, args.ram_dump = True, None
    args.sd_card_image, args.sd_card_engine = args.card_image, 'slave'
    with tempfile.TemporaryDirectory(prefix='filesystem-peer-', dir=ROOT / '.local') as folder:
        args.work = Path(folder)
        report = run_slots(args, observe=lambda remote, result:
            observe_file(remote, result, args.camera_path, args.reference))
    require(report['file_service']['file_prefix_verified'], 'Native file prefix comparison failed')
    require(report['file_service']['fault_free_after'], 'Native file check recorded an engine fault')
    print('PASS native peer file prefix; SDK sender and menu remain outside this check')


if __name__ == '__main__':
    main()
