# SPDX-License-Identifier: GPL-2.0-or-later
"""Check fixed read scope, comparison evidence and transport-failure cleanup."""
import struct
import unittest
from types import SimpleNamespace

from checks.test_ptp_checksum_context import device_info
from tools.ptp_async_ram_probe import TARGETS, STATE_REGIONS, observe, plan, interpret_state
from tools.ptp_checksum_context_probe import UsbCamera


class Camera:
    def __init__(self, mode='match'):
        self.mode, self.events, self.synchronized = mode, [], True
        self.counts = {}
        self.async_seen = False
        self.async_size = 0

    def read(self, opcode, args):
        self.events.append((opcode, args))
        if opcode == 0x1001:
            return device_info(), (0x2001, [])
        command, address, size = args[:3]
        if command == 0xF044:
            self.async_seen = True
            self.async_size = size
        if address in [source for _, source, count in STATE_REGIONS]:
            if self.mode == 'diagnostic_failure' and self.async_seen and address == STATE_REGIONS[1][1]:
                return b'', (0x2001, [0x201D])
            data = bytearray(size)
            if self.async_seen:
                if address == STATE_REGIONS[0][1]:
                    struct.pack_into('<II', data, 0, 0x03010001, 0 if self.mode == 'a001' else 0xB180A000)
                elif address == STATE_REGIONS[1][1]:
                    for offset, value in ((0x20, 0x104AF52F), (0x54, 0xB180A000),
                                          (0x68, TARGETS[0][1]), (0x6C, self.async_size)):
                        struct.pack_into('<I', data, offset, value)
                else:
                    data[0] = int(self.mode == 'a001')
                    struct.pack_into('<II', data, 4, self.async_size, TARGETS[0][1])
            return bytes(data), (0x2001, [0x2001])
        self.counts[address] = self.counts.get(address, 0) + 1
        if command == 0xF044 and self.mode == 'timeout':
            self.synchronized = False
            raise TimeoutError('synthetic timeout')
        if command == 0xF044 and self.mode == 'rejected':
            return b'', (0x2001, [0x201D])
        if command == 0xF044 and self.mode in ('a001', 'diagnostic_failure'):
            return b'', (0x2001, [0xA001])
        data = bytes(range(size))
        if address == TARGETS[0][1]:
            data = (b'\x12\x01' + bytes(6) + struct.pack('<HH', 0x04B0, 0x044B) + bytes(range(20)))[:size]
        if self.mode == 'zero':
            data = bytes(size)
        if self.mode == 'wrong_descriptor':
            data = bytes(range(size))
        if self.mode == 'unstable' and self.counts[address] == 3:
            data = bytes([255]) + data[1:]
        return data, (0x2001, [0x2001])

    def send(self, opcode, args):
        self.events.append((opcode, args))
        return 0x2001, [0x2001]


class AsyncRamTests(unittest.TestCase):
    def report(self):
        return dict(targets=[], fixed_ram_comparison_passed=False)

    def test_success_requires_fixed_nonzero_stable_references(self):
        camera, report, saved = Camera(), self.report(), {}
        observe(camera, report, saved.__setitem__)
        self.assertTrue(report['fixed_ram_comparison_passed'])
        self.assertEqual(len(saved), 6)
        self.assertEqual([args[0] for op, args in camera.events if op == 0x94FF],
                         [0xF032, 0xF044, 0xF032] * 2)
        for op, args in camera.events:
            self.assertIn(op, (0x1001, 0x94FD, 0x94FF, 0x94FE))
            if op == 0x94FF:
                self.assertIn(tuple(args[1:3]), [(address, size) for _, address, size in TARGETS])
                self.assertGreaterEqual(args[1], 0xB1800000)

    def test_changing_reference_is_inconclusive(self):
        report = self.report()
        observe(Camera('unstable'), report, lambda *args: None)
        self.assertFalse(report['fixed_ram_comparison_passed'])

    def test_invalid_reference_stops_before_f044(self):
        for mode in ('zero', 'wrong_descriptor'):
            camera, report = Camera(mode), self.report()
            with self.assertRaisesRegex(ValueError, 'F044 not sent'):
                observe(camera, report, lambda *args: None)
            self.assertFalse(report['fixed_ram_comparison_passed'])
            self.assertNotIn(0xF044, [args[0] for op, args in camera.events if op == 0x94FF])

    def test_inner_rejection_stops_reads_and_exits_service(self):
        camera, report = Camera('rejected'), self.report()
        with self.assertRaisesRegex(ValueError, 'Nested service response failed'):
            observe(camera, report, lambda *args: None)
        self.assertEqual(len([op for op, args in camera.events if op == 0x94FF]), 2)
        self.assertEqual(camera.events[-1][0], 0x94FE)

    def test_ambiguous_transport_failure_sends_no_cleanup_command(self):
        camera, report = Camera('timeout'), self.report()
        with self.assertRaises(TimeoutError):
            observe(camera, report, lambda *args: None)
        self.assertEqual(camera.events[-1][1][0], 0xF044)
        self.assertTrue(report['service_exit_skipped_unsynchronized'])

    def test_plan_contains_no_write_or_boot_read(self):
        data = plan()
        self.assertFalse(data['writes_camera_memory'])
        self.assertFalse(data['reads_boot_memory'])
        self.assertFalse(data['camera_read_executed'])

    def test_diagnosis_adds_only_fixed_state_reads_and_one_async_request(self):
        for mode in ('match', 'a001'):
            camera, report, saved = Camera(mode), self.report(), {}
            if mode == 'a001':
                with self.assertRaisesRegex(ValueError, '40961'):
                    observe(camera, report, saved.__setitem__, diagnose=True)
                self.assertIn('reply_status_nonzero', report['diagnosis']['observations'])
            else:
                observe(camera, report, saved.__setitem__, diagnose=True)
                self.assertTrue(report['fixed_ram_comparison_passed'])
            self.assertEqual(sum(op == 0x94FF and args[0] == 0xF044 for op, args in camera.events), 1)
            self.assertEqual(sum(name.startswith('state-') for name in saved), 6)
            self.assertTrue(report['diagnosis']['request_fields_match'])
            self.assertFalse(report['diagnosis']['cause_confirmed'])
            self.assertEqual(camera.events[-1][0], 0x94FE)
            self.assertEqual(len(report['targets']), 1)

    def test_failed_state_read_preserves_original_service_error(self):
        report = self.report()
        with self.assertRaisesRegex(ValueError, '40961') as caught:
            observe(Camera('diagnostic_failure'), report, lambda *args: None, diagnose=True)
        self.assertIn('diagnostic_read_error', report)
        self.assertTrue(caught.exception.__notes__)

    def test_diagnostic_timeout_does_not_query_more_state(self):
        camera, report, saved = Camera('timeout'), self.report(), {}
        with self.assertRaises(TimeoutError):
            observe(camera, report, saved.__setitem__, diagnose=True)
        self.assertEqual(camera.events[-1][1][0], 0xF044)
        self.assertEqual(sum(name.startswith('state-after') for name in saved), 0)
        self.assertNotIn('async_state_after', report)

    def test_stale_success_state_does_not_confirm_a_failure_cause(self):
        state = dict(completion=dict(code='0x3010001', result='0xb180a000'),
                     worker=dict(callback='0x104af52f', output='0xb180a000',
                                 requested_address=hex(TARGETS[0][1]), requested_bytes=16),
                     reply_header=dict(status=0, bytes=16, address=hex(TARGETS[0][1])))
        result = interpret_state(state, state, TARGETS[0][1], 16)
        self.assertTrue(result['request_fields_match'])
        self.assertFalse(result['cause_confirmed'])
        self.assertFalse(result['completion_changed'])
        self.assertIn('state_unchanged_or_stale', result['observations'])

    def test_usb_timeout_marks_stream_unusable_and_skips_session_close(self):
        camera = UsbCamera.__new__(UsbCamera)
        writes, timeouts = [], []

        def write(endpoint, packet, timeout):
            writes.append(packet)
            timeouts.append(timeout)
            return len(packet)

        def read(*args, **kwargs):
            timeouts.append(kwargs['timeout'])
            raise TimeoutError('synthetic USB timeout')

        camera.device = SimpleNamespace(write=write, read=read)
        camera.util = SimpleNamespace(dispose_resources=lambda *args: None)
        camera.input, camera.output, camera.transaction = 0x81, 2, 0
        camera.session, camera.synchronized, camera.claimed = True, True, False
        camera.pending, camera.timeout_ms = bytearray(), 20000
        with self.assertRaises(TimeoutError) as caught:
            camera.transact(0x94FF, [0xF044], True)
        self.assertFalse(camera.synchronized)
        camera.__exit__(TimeoutError, caught.exception, None)
        self.assertEqual(len(writes), 1)
        self.assertEqual(struct.unpack_from('<H', writes[0], 6)[0], 0x94FF)
        self.assertEqual(timeouts, [20000, 20000])
        with self.assertRaisesRegex(ValueError, 'unsynchronized'):
            camera.transact(0x1003, [], False)
        self.assertEqual(len(writes), 1)


if __name__ == '__main__':
    unittest.main()
