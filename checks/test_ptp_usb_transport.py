# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic USB framing and session controls; no device access."""
import struct
import unittest

from tools.ptp_checksum_context_probe import UsbCamera


def container(kind, code, transaction, payload=b''):
    return struct.pack('<IHHI', 12 + len(payload), kind, code, transaction) + payload


class Device:
    def __init__(self, chunks):
        self.chunks, self.writes = list(chunks), []

    def read(self, *args, **kwargs):
        return self.chunks.pop(0)

    def write(self, endpoint, packet, **kwargs):
        self.writes.append(packet)
        return len(packet)


def camera(chunks):
    result = UsbCamera.__new__(UsbCamera)
    result.device = Device(chunks)
    result.pending = bytearray()
    result.input, result.output = 0x81, 2
    result.session, result.session_attempted, result.transaction = False, False, 0
    result.timeout_ms, result.synchronized = 5000, True
    return result


class UsbTransportTests(unittest.TestCase):
    def test_partial_and_coalesced_containers(self):
        stream = container(2, 0x1001, 0, b'synthetic identity') + container(3, 0x2001, 0)
        connected = camera([stream[:5], stream[5:17], stream[17:]])
        self.assertEqual(connected.read(0x1001, []), (b'synthetic identity', (0x2001, [])))
        self.assertEqual(connected.pending, b'')

    def test_mismatched_transaction_and_bad_length_stop(self):
        for reply in (container(3, 0x2005, 99), struct.pack('<IHHI', 8, 3, 0x2001, 0)):
            connected = camera([reply])
            with self.assertRaises(ValueError):
                connected.read(0x1001, [])
            self.assertEqual(len(connected.device.writes), 1)

    def test_nested_rejection_without_data_keeps_both_statuses(self):
        connected = camera([container(3, 0x2001, 0, struct.pack('<I', 0x201D))])
        self.assertEqual(connected.transact(0x94FF, [0xF032, 1, 52, 0, 0], True),
                         (b'', (0x2001, [0x201D])))
        connected = camera([container(3, 0x2001, 0)])
        with self.assertRaisesRegex(ValueError, 'data phase'):
            connected.read(0x1001, [])

    def test_session_open_once_then_transaction_ids_advance(self):
        connected = camera([container(3, 0x2001, 0),
                            container(3, 0x2001, 1, struct.pack('<I', 0x2001)),
                            container(3, 0x2001, 2, struct.pack('<I', 0x2001))])
        connected.send(0x94FD, [0xF001, 0, 0, 0, 0])
        connected.send(0x94FE, [0xF002, 0, 0, 0, 0])
        self.assertEqual([(struct.unpack_from('<H', p, 6)[0], struct.unpack_from('<I', p, 8)[0])
                          for p in connected.device.writes],
                         [(0x1002, 0), (0x94FD, 1), (0x94FE, 2)])

    def test_existing_session_is_not_taken_over_or_retried(self):
        connected = camera([container(3, 0x201E, 0)])
        for _ in range(2):
            with self.assertRaises(ValueError):
                connected.send(0x94FD, [0xF001, 0, 0, 0, 0])
        self.assertEqual(len(connected.device.writes), 1)


if __name__ == '__main__':
    unittest.main()
