# SPDX-License-Identifier: GPL-2.0-or-later
"""Verify diagnostic log retention offline using synthetic memory contents.

Original command dispatch, dump formatting, log records, output selection and
flush logic execute. Console consumption, kernel services and serial output
are supplied. This does not prove that a camera consumes queued PTP text.
"""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import MASTER_SHA, require, validate_master
from tools.usb_debug_probe import Probe
from tools.ptp_service_probe import Probe as ServiceProbe
from tools.ptp_service_transition_probe import branch_candidates
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from tools.ptp_log_read_probe import (GATES, COMMANDS, RAM, BOOT, OBJECT8_RECORD,
                                     OBJECT8_REGION, record_line)


def dynamic_guard(master):
    probe = ServiceProbe(master)
    probe.put_word(probe.service, 1)
    descriptor = probe.call(0x2286F6, 8)
    region = probe.call(0x2286E4, probe.word(descriptor + 20))
    require(descriptor == OBJECT8_RECORD and region == OBJECT8_REGION and
            probe.word(region + 8) == 0x20000, 'Object 8 metadata binding differs')
    cases = []
    fixtures = (('uninitialized', 0, 0), ('synthetic_initialized', 0xB20C0000, 0x20000),
                ('observed_camera_range', 0xB20D2894, 0x1FFFC))
    for fixture, base, length in fixtures:
        # Observed metadata is replayed offline; no camera state is changed.
        probe.put_word(descriptor + 8, base)
        probe.put_word(descriptor + 12, length)
        for name, address in GATES:
            accepted = base == 0 or name != 'diagnostic_configuration'
            for opcode, command, prepare in ((0x94FF, 0xF032, 0x75230C),
                                              (0x94FE, 0xF033, 0x752300)):
                probe.packet(command, address, 1, opcode=opcode)
                require(probe.call(prepare, 0, probe.INPUT) == int(accepted),
                        'Runtime object guard result differs')
                if not accepted:
                    require(probe.vendor_responses[0]['parameters'][0] == 0x201D,
                            'Runtime guard rejection status differs')
                cases.append(dict(fixture=fixture, supplied_cached_base=hex(base),
                                  supplied_cached_bytes=length, gate=name,
                                  command=hex(command), accepted=accepted))
        for address, size in ((OBJECT8_RECORD, 28), (OBJECT8_REGION, 36)):
            probe.packet(0xF032, address, size)
            require(probe.prepare() == 1 and probe.execute() == 1,
                    'Fixed guard metadata inspection rejected')
    return dict(descriptor_address=hex(descriptor), region_address=hex(region),
                region_bytes=0x20000, cases=cases, actual_runtime_base_observed=True,
                observed_inclusive_end='0xb20f288f',
                metadata_read_ranges_accepted_in_all_fixtures=True)


def configuration_setter(master):
    """Bound direct setter callers and its notification with synthetic RAM."""
    setter = 0x103C0A12
    callers = branch_candidates(master, {setter})[hex(setter)]
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    indexes = []
    for caller in callers:
        address = int(caller, 16)
        candidates = []
        for distance in (2, 4, 6, 8):
            instructions = list(decoder.disasm(master[address - 0x10020000 - distance:
                                                      address - 0x10020000], address - distance))
            if instructions and instructions[0].mnemonic in ('movw', 'movs') and instructions[0].op_str.startswith('r0, #'):
                candidates.append(instructions[0])
        require(bool(candidates), 'Setter caller index is not an immediate')
        instruction = candidates[0]
        indexes.append(dict(caller=caller, index=hex(int(instruction.op_str.split('#')[1], 0))))
    require(len(indexes) == 13 and all(row['index'] != '0x4d6' for row in indexes),
            'Configuration setter caller coverage changed')
    probe, notifications = ServiceProbe(master), []
    probe.hooks[0x39FAF2] = lambda context, object_id, *args: notifications.append(object_id) or 0
    address = dict(GATES)['diagnostic_configuration']
    original = probe.u.mem_read(address, 1)[0]
    probe.call(setter - 0x10020000, 0x4D6, 1)
    require(probe.u.mem_read(address, 1)[0] == 1 and notifications == [8],
            'Native configuration setter notification differs')
    probe.call(setter - 0x10020000, 0x4D6, original)
    return dict(entry=hex(setter), direct_callers=indexes,
                supplied_setter_index='0x4d6', notification_object=8,
                notification_boundary_supplied=True, actual_camera_execution=False,
                limitation='Direct branch scan does not exclude indirect calls or other setters; no usable PTP entry for 0x4d6 is established.')


def gate_writes(master):
    probe = ServiceProbe(master)
    probe.put_word(probe.service, 1)  # Explicit service-mode fixture.
    source = probe.INPUT + 0x6000
    probe.hooks[0x61C384] = lambda *args: source
    cases = []
    for name, address in GATES:
        original = probe.u.mem_read(address, 1)[0]
        for value in (1, original):
            probe.packet(0xF033, address, 1, opcode=0x94FE)
            require(probe.call(0x752300, 0, probe.INPUT) == 1,
                    'Gate write preparation rejected')
            buffer_pointer, limit_pointer = source + 0x100, source + 0x104
            require(probe.call(0x7522F0, 0, probe.INPUT, buffer_pointer, limit_pointer) == 1 and
                    probe.word(buffer_pointer) == source and probe.word(limit_pointer) == 0x1FFFF8,
                    'Original outer data-out buffer binding differs')
            probe.u.mem_write(source, bytes([value]))
            require(probe.call(0x752306, 0, probe.INPUT) == 1 and
                    probe.u.mem_read(address, 1)[0] == value,
                    'Original gate write did not copy its data byte')
            require(probe.vendor_responses[0]['parameters'][:2] == [0x2001, 1],
                    'Gate write acknowledgement differs')
        cases.append(dict(name=name, address=hex(address), bytes=1,
                          original_value=original, enabled_and_restored=True))
    return cases


def queued_dump(master, address):
    probe = Probe(master)
    probe.call(0x39CBCC, 0)
    probe.u.mem_write(probe.OUTPUT_SELECT, b'\1')
    probe.call(0x3BA664, 2)
    payload = bytes(range(16))
    probe.u.mem_write(address, payload)
    probe.u.mem_write(probe.INPUT, COMMANDS[address])
    probe.u.mem_write(dict(GATES)['diagnostic_configuration'], b'\1')
    require(probe.call(0x42415E, 0, probe.INPUT) == 1, 'Original diagnostic preparation rejected')
    probe.responses.clear()
    require(probe.call(0x42418A, 0, probe.INPUT) == 1 and probe.responses == [0x2001],
            'Original diagnostic command failed')
    length = probe.word(probe.QUEUE + 0x18)
    queued = bytes(probe.u.mem_read(probe.LINE_BUFFER, length))
    require(queued == COMMANDS[address][len(b'debug '):-1] + b'\n' and
            probe.word(probe.QUEUE + 8) == 1, 'Original diagnostic admission differs')
    # Only the missing console scheduler and initial name/argument split are supplied.
    del probe.hooks[0x103DA804]
    probe.consume(queued.rstrip(b'\n').decode('ascii'))
    require(probe.word(probe.QUEUE + 8) == 0, 'Consumer did not release its queue')
    record = bytes(probe.u.mem_read(0xB18B9DA8 + 128, 128))
    require(record_line(record, address) == payload, 'Live-tool log parser rejected the native record')
    return dict(address=hex(address), supplied_data_is_synthetic=True, command_bytes=len(COMMANDS[address]),
                queue_busy_before_consumer=True, queue_busy_after_consumer=False,
                original_record_parsed=True, consumer_scheduling_supplied=True)


def log_case(master, native_selection):
    probe = Probe(master)
    probe.call(0x39CBCC, 0)
    probe.u.mem_write(probe.SAMPLE, bytes(range(16)))
    probe.u.mem_write(probe.OUTPUT_SELECT, b'\x01')
    probe.u.mem_write(probe.LOG_GATE, b'\x00')
    if native_selection:
        probe.call(0x3BA664, 2)
    del probe.hooks[0x103DA804]  # Execute the original print route and record formatter.
    probe.consume('memdump 0x%08x 8' % probe.SAMPLE)
    written, read_before = (probe.word(probe.LOG_GATE + offset) for offset in (4, 8))
    require(written == 2 and read_before == 0, 'Expected two unread dump records')
    records = [bytes(probe.u.mem_read(0xB18B9DA8 + index * 128, 128))
               for index in range(written)]
    lengths = [int.from_bytes(record[12:14], 'little') for record in records]
    texts = [record[16:16 + size].decode('ascii') for record, size in zip(records, lengths)]
    require('00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f' in texts[1],
            'Original log record omitted the synthetic dump bytes')
    serial = []
    probe.hooks[0x100201EC] = lambda value, *args: serial.append(value & 255) or 0
    probe.call(0x3655F8, 1)
    read_after = probe.word(probe.LOG_GATE + 8)
    require(read_after == (0 if native_selection else 2) and
            bool(serial) == (not native_selection), 'Log flush did not follow its separate gate')
    result = dict(selection='original output-selection function' if native_selection else 'admission byte only',
                  admission_byte=probe.u.mem_read(probe.OUTPUT_SELECT, 1)[0],
                  log_gate=probe.u.mem_read(probe.LOG_GATE, 1)[0],
                  write_sequence=written, read_sequence_before=read_before,
                  read_sequence_after=read_after, serial_output_observed=bool(serial),
                  record_bytes=128, text_offset=16, text_lengths=lengths,
                  synthetic_dump_text=texts[1], records_retained=read_after == 0)
    if native_selection:
        probe.call(0x3BA664, 1)
        probe.call(0x3655F8, 1)
        require(probe.word(probe.LOG_GATE + 8) == written,
                'Restoring serial selection did not drain pending records')
        result['serial_restore_drains_pending_records'] = True
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    master = args.master.read_bytes()
    validate_master(master)
    report = dict(format=1, master_sha256=MASTER_SHA, firmware_included=False,
                  cases=[log_case(master, False), log_case(master, True)],
                  fixed_gate_writes=gate_writes(master),
                  fixed_gate_writes_fixture='Object 8 cache base is uninitialized (zero); not live write permission.',
                  dynamic_object8_guard=dynamic_guard(master),
                  configuration_setter=configuration_setter(master),
                  queued_dumps=[queued_dump(master, address) for address in (RAM, BOOT)],
                  actual_camera_access=False, queued_ptp_line_consumer_verified=False,
                  limitations=['Dump contents are synthetic RAM, not boot material.',
                               'Command-name splitting and invocation of the consumer are supplied.',
                               'Kernel services report success; serial bytes are captured by the host.'])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('PASS diagnostic admission, separate log-retention gate and serial restoration')


if __name__ == '__main__':
    main()
