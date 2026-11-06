# SPDX-License-Identifier: GPL-2.0-or-later
"""Exercise stock audio requests on a native task stack after full startup.

A temporary resource-8 callback supplies two diagnostic buffers. Firmware
owns message dispatch, event waits, DMA binding, refill and explicit stop.
This is an opaque-word device check, not file playback or audible PCM.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import require
from analyze.qemu_display import Remote
from tools.web_console import Machine, LIVE_VIEW_OPTIONS

CODE = 0x13F01000
DATA = 0xB5F00000
RESULT = DATA + 0x100
CALLBACK = 0xB1D603E0
ORIGINAL_CALLBACK = 0x10482BFD
PRODUCER = 0x102DEAA6
WORDS = [0x11110001, 0x22220002, 0x33330003, 0x44440004,
         0x55550005, 0x66660006, 0x77770007, 0x88880008]


def caller_code(channel, looping):
    code, literals, labels = bytearray(), [], {}

    def emit(value):
        code.extend(struct.pack('<H', value))

    def literal(register, value):
        literals.append((len(code), register, value))
        emit(0)

    def label(name):
        labels[name] = CODE + len(code)
        emit(0xBF00)

    emit(0x680A)                 # ldr r2,[r1]
    emit(0x2A7F)                 # diagnostic operation 127
    branch = len(code)
    emit(0)
    emit(0xB5F0)                 # push r4-r7,lr
    emit(0xB083)                 # three arguments; preserve stack alignment
    literal(6, RESULT)
    emit(0x2000 | channel)
    literal(1, DATA)
    emit(0x2210)                 # bytes per buffer
    emit(0x2302)                 # buffer count
    emit(0x2400)
    emit(0x9400)                 # first index
    emit(0x2400 | int(looping))
    emit(0x9401)
    emit(0x2404)
    emit(0x9402)                 # block-count configuration
    literal(5, 0x1036F99B)
    emit(0x47A8)
    emit(0x6030)
    label('configured')
    emit(0x2000 | channel)
    emit(0x2100)
    emit(0x2204)
    emit(0x2301)
    emit(0x2400)
    emit(0x9400)                 # ordinary output, not dual-channel blocks
    emit(0x9401)
    literal(5, 0x1036F947)
    emit(0x47A8)
    emit(0x6070)
    label('started')
    emit(0x2064)
    literal(5, 0x103DC539)       # native delay; other tasks continue running
    emit(0x47A8)
    label('observed')
    emit(0x2000 | channel)
    literal(5, 0x1036FA15)
    emit(0x47A8)
    emit(0x60B0)
    label('stopped')
    emit(0xB003)
    emit(0xBDF0)
    fallback = len(code)
    literal(3, ORIGINAL_CALLBACK)
    emit(0x4718)
    distance = fallback - branch - 4
    require(0 <= distance <= 254, 'Diagnostic branch out of range')
    struct.pack_into('<H', code, branch, 0xD100 | (distance // 2))
    while len(code) % 4:
        emit(0xBF00)
    for offset, register, value in literals:
        distance = CODE + len(code) - ((CODE + offset + 4) & ~3)
        require(0 <= distance < 1024 and distance % 4 == 0, 'Literal out of range')
        struct.pack_into('<H', code, offset, 0x4800 | (register << 8) | distance // 4)
        code.extend(struct.pack('<I', value))
    return bytes(code), labels


def observe(remote, channel, looping, report):
    code, labels = caller_code(channel, looping)
    report.update(channel=channel, looping=looping, events=[], producer_entries=[],
                  caller_sha256=hashlib.sha256(code).hexdigest(),
                  source_words=[hex(word) for word in WORDS], caller_returned=False)
    active = set()
    state = 0xB1CF7468 + channel * 56
    audio = 0x2C080100 + channel * 256

    def word(address):
        return int.from_bytes(remote.read(address, 4), 'little')

    def store(address, value):
        remote.write(address, struct.pack('<I', value))

    def arm(pc):
        remote.breakpoint(pc)
        active.add(pc)

    def disarm(pc):
        remote.breakpoint(pc, False)
        active.remove(pc)

    remote.select_thread(1)
    require(word(CALLBACK) == ORIGINAL_CALLBACK, 'Unexpected resource-8 callback')
    saved_code, saved_data = remote.read(CODE, len(code)), remote.read(DATA, 0x200)
    require(not any(saved_code + saved_data), 'Diagnostic memory is occupied')
    remote.write(CODE, code)
    remote.write(DATA, struct.pack('<8I', *WORDS))
    store(CALLBACK, CODE | 1)
    for pc in (CODE, *labels.values(), PRODUCER):
        arm(pc)
    remote.select_thread(3)
    ring, sequence_address = 0xC60F0000, 0xC1006F74
    written, consumed = word(ring + 8), word(ring + 16)
    require(written < 192 and consumed < 192 and (written + 1) % 192 != consumed,
            'Diagnostic trigger ring is full or invalid')
    sequence = word(sequence_address)
    remote.write(ring + 24 + written * 264, struct.pack('<IBBH', 127, 8, sequence & 255, 0))
    store(sequence_address, (sequence + 1) & 0xFFFFFFFF)
    store(ring + 8, (written + 1) % 192)
    store(0x20136008, 1)
    original_sp = None
    return_pc = None
    try:
        for _ in range(24):
            remote.sock.settimeout(30)
            try:
                reply = remote.command('vCont;c')
            except TimeoutError:
                remote.interrupt()
                raise ValueError('Audio request did not reach the next observation point')
            match = re.search(r'thread:([0-9a-f]+)', reply)
            require(match is not None, 'Missing diagnostic stop thread')
            thread = int(match[1], 16)
            remote.select_thread(thread)
            registers = remote.regs()
            pc = remote.get(registers, 'pc')
            require(pc in active, f'Unexpected audio stop {pc:#x}')
            disarm(pc)
            if pc == PRODUCER:
                require(remote.get(registers, 'r0') == state, 'Unexpected audio producer')
                report['producer_entries'].append(word(state + 0x24))
                # Re-arm only after leaving this instruction, using its next instruction.
                if len(report['producer_entries']) < (6 if looping else 2):
                    arm(PRODUCER + 2)
                continue
            if pc == PRODUCER + 2:
                arm(PRODUCER)
                continue
            name = next((name for name, address in labels.items() if address == pc),
                        'entry' if pc == CODE else 'return')
            event = dict(stage=name, pc=hex(pc), thread=thread,
                         sp=hex(remote.get(registers, 'sp')), result=remote.get(registers, 'r0'),
                         buffer=[hex(word(state + i * 4)) for i in range(14)],
                         audio=[hex(word(audio + offset)) for offset in
                                (8, 12, 16, 20, 32, 0x5c, 0x60)])
            report['events'].append(event)
            print('Audio ' + name + ': ' + json.dumps(event), flush=True)
            if pc == CODE:
                original_sp = remote.get(registers, 'sp')
            elif pc == labels['stopped']:
                return_pc = word(remote.get(registers, 'sp') + 28) & ~1
                arm(return_pc)
            elif pc == return_pc:
                require(remote.get(registers, 'sp') == original_sp, 'Native task stack mismatch')
                report['caller_returned'] = True
                break
        require(report['caller_returned'], 'Diagnostic caller did not return')
        stages = {event['stage']: event for event in report['events']}
        require(all(stages[name]['result'] == 0 for name in ('configured', 'started', 'stopped')),
                'Original audio request returned an error')
        require(stages['stopped']['buffer'][11] == '0x1' and
                not int(stages['stopped']['audio'][0], 0) & 0x2000, 'Audio output did not stop')
        if looping:
            require(report['producer_entries'] == [0, 1, 0, 1, 0, 1], 'Circular refill did not repeat')
        else:
            require(report['producer_entries'] == [0, 1] and
                    stages['observed']['audio'][4:] == ['0x0', '0x8', '0x8888'],
                    'Both buffers were not consumed')
        report['cores'] = []
        for thread in (1, 2, 3, 4):
            remote.select_thread(thread)
            report['cores'].append(dict(thread=thread, faults={name: hex(remote.read_register(name))
                for name in ('DFAR_S', 'IFAR_S', 'DFSR_S', 'IFSR_S')}))
        require(all(value == '0x0' for core in report['cores'] for value in core['faults'].values()),
                'Core fault after audio diagnostic')
        report['passed'] = True
    finally:
        for pc in active:
            remote.breakpoint(pc, False)
        # The owner terminates the VM on failure; do not overwrite an active caller.
        if report['caller_returned']:
            remote.select_thread(1)
            store(CALLBACK, ORIGINAL_CALLBACK)
            remote.write(CODE, saved_code)
            remote.write(DATA, saved_data)
            report['diagnostic_restored'] = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', required=True)
    for name in ('master', 'slave', 'controller', 'sd-card', 'destination'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--wsl', action='store_true')
    parser.add_argument('--channel', type=int, choices=(0, 1), default=0)
    parser.add_argument('--loop', action='store_true')
    args = parser.parse_args()
    digest = hashlib.sha256(args.master.read_bytes()).hexdigest()
    require(digest == '478caf02dba41fa9144c0c4b6e1a051dc556d40e51a79a308bdd1169efb9dbbe',
            'Audio entry addresses require master C1.70')
    card_digest = hashlib.sha256(args.sd_card.read_bytes()).hexdigest()
    report = dict(passed=False, firmware_sha256=digest,
                  scope='Diagnostic caller on a native task; original queue, event and DMA execution. No file playback or host sound.')
    args.realtime = False
    args.display_complete = args.processing_resource_header = args.audio_output = True
    for name in LIVE_VIEW_OPTIONS:
        setattr(args, name, True)
    (ROOT / '.local').mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='audio-task-', dir=ROOT / '.local') as folder:
        args.update_store = Path(folder) / 'store'
        machine = Machine(args)
        remote = None
        try:
            require(machine.restart(), 'Could not start audio diagnostic')
            deadline = time.monotonic() + 180
            while True:
                require(time.monotonic() < deadline, 'Startup timed out')
                status = machine.status()
                require(not status.get('error'), str(status.get('error')))
                if status.get('ready') and status.get('input_ready'):
                    break
                time.sleep(1)
            report['boot_status'] = status
            with machine.io:
                machine.qmp.command('stop')
                remote = Remote(machine.gdb_port)
                observe(remote, args.channel, args.loop, report)
        except Exception as error:
            report['passed'] = False
            report['error'] = str(error)
            raise
        finally:
            if remote is not None:
                remote.sock.close()
            machine.close()
            report['source_card_unchanged'] = hashlib.sha256(args.sd_card.read_bytes()).hexdigest() == card_digest
            report['passed'] &= report['source_card_unchanged']
            args.destination.mkdir(parents=True, exist_ok=True)
            (args.destination / 'report.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    require(report['passed'], 'Audio diagnostic failed')
    print('PASS native audio task requests, refill and explicit stop')


if __name__ == '__main__':
    main()
