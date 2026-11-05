# SPDX-License-Identifier: GPL-2.0-or-later
"""Read matrix state from both parameter RAM and the observed graphics pool."""
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.body_shutter_gate_probe import playback_transform_snapshot


class Remote:
    def __init__(self, context):
        self.reads = []
        self.data = {
            0xb1800c38: struct.pack('<I', context),
            0x50000000: bytes(0x60),
            context + 0x104: struct.pack('<I', 0x1401),
            context + 0x348: struct.pack('<9i', 65536, 0, 0, 0, -65536, 0, 0, 682 * 65536, 65536),
            context + 0x29c: bytes(4),
        }

    def get(self, registers, name):
        return registers[name]

    def read(self, address, size):
        self.reads.append(address)
        data = self.data[address]
        assert len(data) == size
        return data


class TransformSnapshotTests(unittest.TestCase):
    def test_supported_pools_preserve_signed_matrix(self):
        for context in (0xb1900000, 0xbc010b20):
            with self.subTest(context=hex(context)):
                remote = Remote(context)
                result = playback_transform_snapshot(remote, dict(sp=0x50000000, r4=0))
                self.assertEqual(result['matrix_q16'][4], -65536)
                self.assertEqual(result['matrix_address'], hex(context + 0x348))
                self.assertEqual(result['mode'], '0x1401')

    def test_outside_pool_is_explicit_without_pointer_dereference(self):
        for context in (0, 0xbc09fa04, 0x20144000):
            remote = Remote(context)
            result = playback_transform_snapshot(remote, dict(sp=0x50000000, r4=0))
            self.assertIn('matrix_unavailable', result)
            self.assertNotIn('matrix_q16', result)
            self.assertEqual(remote.reads, [0xb1800c38, 0x50000000])


if __name__ == '__main__':
    unittest.main()
