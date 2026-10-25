# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic log freshness, gate restoration and bounded upload controls."""
import struct
import unittest
from unittest.mock import patch

from checks.test_ptp_checksum_context import device_info
from checks.test_ptp_usb_transport import camera as usb_camera, container
from tools.ptp_log_read_probe import (BOOT, COMMANDS, GATES, LOG_SEQUENCE, QUEUE,
    RAM, RING, RING_COUNT, OBJECT8_RECORD, OBJECT8_REGION,
    LogCamera, observe, inspect_guard, record_line, main)


def record(address, data):
    text = (' [%08x] ' % address + ' '.join('%02x' % value for value in data) + '  [                ]').encode()
    block = bytearray(128)
    struct.pack_into('<H', block, 12, len(text))
    block[16:16 + len(text)] = text
    return bytes(block)


class Camera:
    def __init__(self, mode='match', cursor=0):
        self.mode, self.cursor, self.synchronized = mode, cursor, True
        self.events, self.gates, self.records = [], {address: 0 for _, address in GATES}, {}
        self.submissions = 0
        self.reference = b'prefix00' + b'\x12\x01' + bytes(6) + struct.pack('<HH', 0x04B0, 0x044B) + bytes(12)
        self.original = dict(self.gates)

    def read(self, opcode, args):
        self.events.append(('read', opcode, list(args)))
        if opcode == 0x1001:
            return device_info('other' if self.mode == 'wrong_model' else 'Z 7_2'), (0x2001, [])
        command, address, count = args[:3]
        assert opcode == 0x94FF and command == 0xF032
        if address == RAM:
            data = self.reference
        elif address in self.gates:
            if self.mode == 'protected_configuration' and address == dict(GATES)['diagnostic_configuration']:
                return b'', (0x2001, [0x201D, 0, 0, 0, 0])
            data = bytes([self.gates[address]])
        elif address == OBJECT8_RECORD:
            data = bytearray(28)
            data[0] = 7 if self.mode == 'invalid_descriptor' else 8
            struct.pack_into('<II', data, 8, 0xB20C0000, 0x20000)
            struct.pack_into('<I', data, 20, 8)
        elif address == OBJECT8_REGION:
            data = struct.pack('<9I', 0x12A20000, 0, 0x20000, 0x1FFFC, 0, 0, 0, 0, 1)
        elif address == LOG_SEQUENCE:
            data = struct.pack('<I', self.cursor)
        elif address == QUEUE + 8:
            data = struct.pack('<I', int(self.mode == 'busy'))
        elif address == QUEUE:
            data = bytes(28)
        elif RING <= address < RING + RING_COUNT * 128:
            data = self.records.get((address - RING) // 128, bytes(128))
            if self.mode == 'changing_baseline':
                self.cursor += 1
        else:
            assert address == 0xB1800060
            data = bytes(4)
        return data[:count], (0x2001, [0x2001])

    def send(self, opcode, args):
        self.events.append(('send', opcode, list(args)))
        return 0x2001, [0x2001]

    def upload(self, opcode, args, data):
        self.events.append(('upload', opcode, list(args), data))
        if opcode == 0x94FE:
            assert args[0] == 0xF033 and args[1] in self.gates and args[2:] == [1, 0, 0]
            self.gates[args[1]] = data[0]
            if self.mode == 'write_failed' and sum(self.gates.values()) == 2:
                self.mode = 'missing'
                return 0x2001, [0xA001]
            return 0x2001, [0x2001, 1]
        assert opcode == 0x92F0 and data in COMMANDS.values() and not args
        self.submissions += 1
        if self.mode == 'timeout':
            self.synchronized = False
            raise TimeoutError('synthetic upload timeout')
        if self.mode == 'missing':
            return 0x2001, []
        address = next(address for address in COMMANDS if COMMANDS[address] == data)
        payload = self.reference[:16] if address == RAM else bytes(range(16))
        if self.mode == 'mismatch':
            payload = bytes(16)
        self.records[self.cursor % RING_COUNT] = record(address, payload)
        self.cursor = (self.cursor + 1) & 0xFFFFFFFF
        if self.mode == 'overflow':
            self.cursor += 32
        return 0x2001, []


class LogReadTests(unittest.TestCase):
    def test_suspended_experiment_stops_before_camera_construction(self):
        for extra in ([], ['--read-boot']):
            with patch('sys.argv', ['probe', '--execute', *extra]), \
                    patch('tools.ptp_log_read_probe.LogCamera') as connected:
                with self.assertRaisesRegex(ValueError, 'experiments are suspended'):
                    main()
                connected.assert_not_called()

    def report(self):
        return dict(original_gates={}, gate_writes_attempted=[], restoration=[],
                    dumps=[], cleanup_notes=[], ram_comparison_passed=False,
                    boot_read_attempted=False)

    def run_observation(self, camera, boot=False):
        report, saved = self.report(), {}
        observe(camera, report, saved.__setitem__, boot, pause=lambda seconds: None)
        return report, saved

    def test_fresh_matching_ram_and_boot_then_original_gates_restored(self):
        for cursor in (0, 4095, 0xFFFFFFFF):
            with self.subTest(cursor=cursor):
                camera = Camera(cursor=cursor)
                report, saved = self.run_observation(camera, boot=True)
                self.assertTrue(report['ram_comparison_passed'])
                self.assertTrue(report['boot_material_candidate_saved'])
                self.assertEqual(saved['boot-material.bin'], bytes(range(8, 16)))
                self.assertEqual(camera.gates, camera.original)
                self.assertTrue(report['gates_restored'] and report['service_exit_completed'])
                self.assertEqual(camera.submissions, 2)
                self.assertEqual([args[1] for kind, opcode, args, *tail in camera.events
                                  if kind == 'upload' and opcode == 0x94FE],
                                 [address for _, address in GATES] + [address for _, address in reversed(GATES)])

    def test_default_never_submits_boot_command_and_preserves_enabled_gates(self):
        camera = Camera()
        camera.gates[GATES[0][1]] = 1
        original = dict(camera.gates)
        report, saved = self.run_observation(camera)
        self.assertEqual(camera.submissions, 1)
        self.assertFalse(report['boot_read_attempted'])
        self.assertNotIn('boot-material.bin', saved)
        self.assertEqual(camera.gates, original)

    def test_mismatch_and_missing_consumer_restore_gates_without_boot(self):
        for mode in ('mismatch', 'missing'):
            camera, report = Camera(mode), self.report()
            with self.assertRaises(ValueError):
                observe(camera, report, lambda *args: None, True, pause=lambda seconds: None)
            self.assertFalse(report['ram_comparison_passed'])
            self.assertFalse(report['boot_read_attempted'])
            self.assertTrue(report['gates_restored'])
            self.assertEqual(camera.gates, camera.original)
            self.assertEqual(camera.submissions, 1)
            if mode == 'missing':
                self.assertEqual(report['dumps'][0]['queue_after'], dict(busy=0, line_length=0))

    def test_partial_gate_failure_restores_even_the_failed_write(self):
        camera, report = Camera('write_failed'), self.report()
        with self.assertRaises(ValueError):
            observe(camera, report, lambda *args: None)
        self.assertTrue(report['gates_restored'])
        self.assertEqual(camera.gates, camera.original)
        self.assertEqual(camera.submissions, 0)

    def test_unsynchronized_upload_stops_all_further_usb_operations(self):
        camera, report = Camera('timeout'), self.report()
        with self.assertRaises(TimeoutError):
            observe(camera, report, lambda *args: None)
        self.assertFalse(report['gates_restored'])
        self.assertEqual(camera.events[-1][1], 0x92F0)
        self.assertEqual(camera.submissions, 1)

    def test_wrong_model_busy_queue_and_unexpected_gate_stop_before_writes(self):
        for mode in ('wrong_model', 'busy', 'bad_gate'):
            camera, report = Camera(mode), self.report()
            if mode == 'bad_gate':
                camera.gates[GATES[1][1]] = 2
            with self.assertRaises(ValueError):
                observe(camera, report, lambda *args: None)
            self.assertFalse(any(event[0] == 'upload' for event in camera.events))

    def test_protected_configuration_records_exact_failure_without_writes(self):
        camera, report = Camera('protected_configuration'), self.report()
        with self.assertRaisesRegex(ValueError, 'F032 read rejected at 0xb20d2d6a'):
            observe(camera, report, lambda *args: None)
        self.assertEqual(report['stage'], 'read_gate:diagnostic_configuration')
        self.assertEqual(len(report['original_gates']), 2)
        self.assertEqual(report['gate_writes_attempted'], [])
        self.assertTrue(report['gates_restored'] and report['service_exit_completed'])
        self.assertFalse(any(event[0] == 'upload' for event in camera.events))

    def test_guard_inspection_only_reads_fixed_metadata_and_reports_overlap(self):
        camera, report, saved = Camera(), self.report(), {}
        inspect_guard(camera, report, saved.__setitem__)
        self.assertTrue(report['guard_inspection']['configuration_overlaps_cached_object'])
        self.assertEqual(report['guard_inspection']['cached_bytes'], 0x20000)
        self.assertTrue(report['service_exit_completed'])
        self.assertEqual([args[1:3] for kind, opcode, args in camera.events if opcode == 0x94FF],
                         [[OBJECT8_RECORD, 28], [OBJECT8_REGION, 36]])
        self.assertFalse(any(event[0] == 'upload' for event in camera.events))
        self.assertEqual(len(saved), 2)

    def test_invalid_guard_binding_stops_before_second_record(self):
        camera, report = Camera('invalid_descriptor'), self.report()
        with self.assertRaisesRegex(ValueError, 'descriptor binding'):
            inspect_guard(camera, report, lambda *args: None)
        self.assertTrue(report['service_exit_completed'])
        self.assertFalse(any(event[0] == 'upload' for event in camera.events))
        self.assertEqual(len([event for event in camera.events if event[1] == 0x94FF]), 1)

    def test_old_matching_record_is_not_evidence_of_new_execution(self):
        camera = Camera('missing')
        camera.records[0] = record(RAM, camera.reference[:16])
        report = self.report()
        with self.assertRaisesRegex(ValueError, 'No fresh'):
            observe(camera, report, lambda *args: None, pause=lambda seconds: None)
        self.assertFalse(report['ram_comparison_passed'])
        self.assertTrue(report['gates_restored'])

    def test_log_churn_aborts_without_command_retry_and_restores(self):
        for mode, submissions in (('changing_baseline', 0), ('overflow', 1)):
            camera, report = Camera(mode), self.report()
            with self.assertRaises(ValueError):
                observe(camera, report, lambda *args: None, True, pause=lambda seconds: None)
            self.assertEqual(camera.submissions, submissions)
            self.assertFalse(report['boot_read_attempted'])
            self.assertTrue(report['gates_restored'])

    def test_log_parser_rejects_other_addresses_binary_and_partial_lines(self):
        line = record(RAM, bytes(range(16)))
        self.assertEqual(record_line(line, RAM), bytes(range(16)))
        self.assertIsNone(record_line(line, BOOT))
        binary = bytearray(line)
        binary[14] = 1
        self.assertIsNone(record_line(binary, RAM))
        partial = bytearray(line)
        struct.pack_into('<H', partial, 12, 30)
        self.assertIsNone(record_line(partial, RAM))

    def test_upload_frames_and_fixed_write_scope(self):
        connected = usb_camera([container(3, 0x2001, 0),
                                container(3, 0x2001, 1, struct.pack('<II', 0x2001, 1))])
        connected.__class__ = LogCamera
        args = [0xF033, GATES[0][1], 1, 0, 0]
        self.assertEqual(connected.upload(0x94FE, args, b'\1'), (0x2001, [0x2001, 1]))
        command, data = connected.device.writes[-2:]
        self.assertEqual(struct.unpack('<IHHI', command[:12]), (32, 1, 0x94FE, 1))
        self.assertEqual(struct.unpack('<IHHI', data[:12]), (13, 2, 0x94FE, 1))
        self.assertEqual(data[12:], b'\1')
        for opcode, args, data in ((0x94FE, [0xF033, BOOT, 1, 0, 0], b'\1'),
                                   (0x92F0, [], b'debug mem w 0x10000088 1\0'),
                                   (0x94FE, [0xF033, GATES[0][1], 1, 0, 0], b'\2')):
            count = len(connected.device.writes)
            with self.assertRaisesRegex(ValueError, 'fixed diagnostic scope'):
                connected.upload(opcode, args, data)
            self.assertEqual(len(connected.device.writes), count)

    def test_upload_framing_error_prevents_restore_or_other_commands(self):
        connected = usb_camera([container(3, 0x2001, 0), container(3, 0x2001, 99)])
        connected.__class__ = LogCamera
        with self.assertRaisesRegex(ValueError, 'Malformed upload'):
            connected.upload(0x92F0, [], COMMANDS[RAM])
        self.assertFalse(connected.synchronized)
        count = len(connected.device.writes)
        with self.assertRaisesRegex(ValueError, 'unsynchronized'):
            connected.upload(0x92F0, [], COMMANDS[RAM])
        self.assertEqual(len(connected.device.writes), count)


if __name__ == '__main__':
    unittest.main()
