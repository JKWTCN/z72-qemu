# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute F044 failure branches offline with explicit completion fixtures.

Original reply validation, completion callback, request guard and F044 handler
run locally. Kernel events and waits are supplied. No camera or real peer is used.
"""
import argparse
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import MASTER_SHA, require, validate_master
from tools.ptp_service_probe import Probe
from tools.ptp_async_ram_probe import STATE_REGIONS
from unicorn import UC_HOOK_CODE


def case(image, name, missing_output=False, wait=0, reply_status=0, reply_size=None, wrong_code=False,
         request_size=32):
    probe = Probe(image)
    output, worker, header = probe.INPUT + 0x6000, 0xB18A7B7C, 0xB2B3A444
    completion, target = 0xB188BC98, 0xB1809888
    reply_size = request_size if reply_size is None else reply_size
    payload = bytes(range(request_size))
    probe.put_word(worker + 0x20, 0x104AF52F)
    probe.put_word(worker + 0x54, output)
    probe.put_word(worker + 0x68, target)
    probe.put_word(worker + 0x6C, request_size)
    probe.u.mem_write(header, bytes([reply_status]) + bytes(3) +
                       struct.pack('<II', reply_size, target) + payload)
    probe.hooks[0x340F44] = probe.copy
    # Execute native reply validation and its completion callback separately.
    # The later F044 call observes this supplied state; it is not a task trace.
    probe.call(0x3640C8)
    native_completion = [probe.word(completion), probe.word(completion + 4)]
    expected_result = output if reply_status == 0 and reply_size == request_size else 0
    require(native_completion == [0x03010001, expected_result],
            'Native reply acceptance differs')
    if wrong_code:
        probe.put_word(completion, 0x03010003)
    waits, requests = [], []

    def zero(address, size, *args):
        probe.u.mem_write(address, bytes(size))
        return address

    def submit(u, location, size, unused):
        address, size, buffer, callback = (u.reg_read(reg) for reg in probe.regs)
        requests.append(dict(address=hex(address), bytes=size,
                             output=hex(buffer), callback=hex(callback)))

    def waited(mask, result, timeout, *args):
        waits.append(timeout)
        return wait

    probe.hooks.update({0x341034: zero, 0x61C384: lambda *args: 0 if missing_output else output,
                        0x3406E4: lambda *args: 0, 0x4A101C: lambda *args: 0,
                        0x4A1048: waited})
    probe.u.hook_add(UC_HOOK_CODE, submit, begin=0x10383BC4, end=0x10383BC4)
    probe.packet(0xF044, target, request_size)
    returned = probe.call(0x490D7E, 0, probe.INPUT)
    success = not missing_output and wait == 0 and not wrong_code and expected_result != 0
    expected = 0x2001 if success else 0xA001
    require(returned == int(success) and len(probe.vendor_responses) == 1 and
            probe.vendor_responses[0]['outer'] == 0x2001 and
            probe.vendor_responses[0]['parameters'][0] == expected,
            'Original F044 response differs')
    require(waits == ([] if missing_output else [7000]) and len(requests) == 1,
            'Original F044 request/wait sequence differs')
    require(bool(probe.submissions) == success, 'Failed F044 submitted a data phase')
    if success:
        require(bytes(probe.u.mem_read(output, request_size)) == payload, 'Native reply copy differs')
    return dict(name=name, supplied_output_buffer_is_null=missing_output, supplied_wait_result=wait,
                supplied_reply_status=reply_status, supplied_reply_bytes=reply_size,
                native_reply_completion=[hex(value) for value in native_completion],
                wrong_completion_code_supplied=wrong_code, requests=requests,
                wait_arguments=waits, returned=returned,
                response=probe.vendor_responses[0], data_phase_submitted=bool(probe.submissions))


def wire_reply(image, status):
    """Decode a synthetic peer reply and execute its native completion handler."""
    probe = Probe(image)
    worker, completion = 0xB18A7B7C, 0xB188BC98
    source, decoded, output = (probe.INPUT + offset for offset in (0x3000, 0x4000, 0x6000))
    target, count = 0xB1809888, 16
    payload = bytes(range(count))
    packet = bytearray(16 + count)
    packet[0], packet[4], packet[5] = 2, status, count
    struct.pack_into('<I', packet, 8, target)
    packet[16:] = payload
    probe.u.mem_write(source, bytes(packet))
    probe.put_word(worker + 0x20, 0x104AF52F)
    probe.put_word(worker + 0x54, output)
    probe.put_word(worker + 0x68, target)
    probe.put_word(worker + 0x6C, count)
    probe.hooks[0x340F44] = probe.copy
    # Register the reply callback through the native request interface;
    # its outbound transport is supplied and no peer is contacted.
    probe.hooks[0x1E54FE] = lambda *args: 1
    probe.call(0x1E6CBA, 0x102054FF, 0)
    require(probe.call(0x1E6D9E, worker + 0x68, 0x1038368D) == 1,
            'Native reply callback registration failed')
    require(probe.call(0x412770, source, len(packet), decoded) == 1,
            'Native peer reply decoding failed')
    event = probe.word(decoded)
    header = probe.word(event + 4)
    require(probe.u.mem_read(event, 1)[0] == 15,
            'Native read reply binding differs')
    normalized = probe.u.mem_read(header, 1)[0]
    require(normalized == int(status != 0) and probe.word(header + 4) == count and
            probe.word(header + 8) == target, 'Native read reply fields differ')
    events = []
    probe.hooks[0x3406E4] = lambda handle, mask, *args: events.append(mask) or 0
    probe.call(0x1E6CC4, event)
    require(events == [8] and bytes(probe.u.mem_read(0xB2B3A444, 12)) ==
            bytes(probe.u.mem_read(header, 12)), 'Native reply dispatch differs')
    probe.call(0x3638A2, events[0])
    result = probe.word(completion + 4)
    require(probe.word(completion) == 0x03010001 and
            result == (0 if status else output), 'Native peer completion differs')
    if not status:
        require(bytes(probe.u.mem_read(output, count)) == payload, 'Decoded payload differs')
    return dict(supplied_wire_command=2, supplied_wire_status=status,
                normalized_status=normalized, reply_bytes=count, reply_address=hex(target),
                decoded_header=hex(header), worker_header='0xb2b3a444', worker_events=events,
                completion_code=hex(probe.word(completion)), completion_result=hex(result),
                synthetic_payload_copied=status == 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    image = args.master.read_bytes()
    validate_master(image)
    admission = Probe(image)
    admission.put_word(admission.service, 1)  # Synthetic service-mode fixture.
    ranges = []
    for name, address, size in STATE_REGIONS:
        admission.packet(0xF032, address, size)
        require(admission.prepare() == 1 and admission.execute() == 1 and
                len(admission.submissions) == 1 and
                admission.submissions[0]['source'] == address and
                admission.submissions[0]['bytes'] == size,
                'Diagnostic region failed the original F032 route')
        ranges.append(dict(name=name, address=hex(address), bytes=size,
                           original_f032_read_accepted=True))
    report = dict(format=1, firmware_included=False, master_sha256=MASTER_SHA,
                  diagnostic_ranges=ranges,
                  cases=[case(image, 'request_rejected', missing_output=True),
                         case(image, 'wait_failed', wait=1),
                         case(image, 'unexpected_completion_code', wrong_code=True),
                         case(image, 'reply_status_nonzero', reply_status=1),
                         case(image, 'reply_length_mismatch', reply_size=31),
                         case(image, 'successful_read'),
                         case(image, 'short_successful_read', request_size=16)],
                  wire_reply_cases=[wire_reply(image, status) for status in (0, 1, 7, 255)],
                  actual_camera_access=False, actual_failure_cause_identified=False,
                  limitations=['Completion fixtures are prepared before the F044 handler; task scheduling is not executed.',
                               'The original request guard executes; kernel event submission and waits are supplied.',
                               'The same A001 reply covers all five failure cases; the reply alone cannot select one.',
                               'The successful payload is synthetic and does not verify the peer address space.',
                               'Wire replies are synthetic; nonzero peer status is normalized and loses its original value.'])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('PASS five F044 failure branches, two successful reads and four wire status cases')


if __name__ == '__main__':
    main()
