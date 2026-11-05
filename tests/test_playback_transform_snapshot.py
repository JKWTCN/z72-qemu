# SPDX-License-Identifier: GPL-2.0-or-later
"""Read matrix state from both parameter RAM and the observed graphics pool."""
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.body_shutter_gate_probe import playback_transform_snapshot, playback_surface_snapshot


class Remote:
    def __init__(self, context):
        self.reads = []
        self.data = {
            0xb1800c38: struct.pack('<I', context),
            0x50000000: bytes(0x60),
            context + 0x104: struct.pack('<I', 0x1401),
            context + 0x348: struct.pack('<9i', 65536, 0, 0, 0, -65536, 0, 0, 682 * 65536, 65536),
            context + 0x29c: bytes(4),
            context + 0x28: struct.pack('<I', 0),
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
                self.assertNotIn(context + 0x28, remote.reads)

    def test_surface_fields_and_pointer_bounds(self):
        for surface in (0xb1900000, 0xb5efff10, 0xbb300000, 0xbc09ff10,
                        0, 0xb5efff14, 0xbc09ff14, 0x20144000):
            with self.subTest(surface=hex(surface)):
                context = 0xbc010b20
                remote = Remote(context)
                remote.data[context + 0x28] = struct.pack('<I', surface)
                valid = surface in (0xb1900000, 0xb5efff10, 0xbb300000, 0xbc09ff10)
                if valid:
                    data = bytearray(0xf0)
                    struct.pack_into('<I', data, 0xdc, 0x3fde)
                    struct.pack_into('<I', data, 0xe8, 1)
                    remote.data[surface] = bytes(data)
                result = playback_surface_snapshot(remote, dict(r4=context))
                self.assertEqual(result['address'], hex(surface))
                if valid:
                    self.assertEqual(result['words']['0xdc'], '0x3fde')
                    self.assertEqual(result['words']['0xe8'], '0x1')
                else:
                    self.assertIn('unavailable', result)
                    self.assertNotIn(surface, remote.reads)

    def test_invalid_submission_context_is_not_dereferenced(self):
        for context in (0, 0xb5efffd8, 0xbc09ffd8, 0x20144000):
            remote = Remote(context)
            result = playback_surface_snapshot(remote, dict(r4=context))
            self.assertIn('unavailable', result)
            self.assertEqual(remote.reads, [])

    def test_surface_handle_cache_and_bounds(self):
        context, surface = 0xb1800c1c, 0xbbfcc000
        for handle, cached in ((0xbbfcbe50, 0xcc18b000), (0xbbfcbe50, 0),
                               (0xb5effff4, 0xcc18b000), (0xbc09fff4, 0xcc18b000),
                               (0xb5effff8, None), (0xbc09fff8, None), (0x20144000, None)):
            with self.subTest(handle=hex(handle), cached=cached):
                remote = Remote(context)
                remote.data[context + 0x28] = struct.pack('<I', surface)
                data = bytearray(0xf0)
                struct.pack_into('<I', data, 0x74, handle)
                remote.data[surface] = bytes(data)
                if cached is not None:
                    remote.data[handle] = struct.pack('<3I', 0x1234, cached, 0x5678)
                result = playback_surface_snapshot(remote, dict(r4=context))
                item = result['memory_handles']['0x74']
                if cached is None:
                    self.assertIn('unavailable', item)
                    self.assertNotIn(handle, remote.reads)
                else:
                    self.assertEqual(item['cached_address'], hex(cached))
                    self.assertEqual('unavailable' in item, cached == 0)
                    self.assertNotIn(0x5678, remote.reads)

    def test_outside_pool_is_explicit_without_pointer_dereference(self):
        for context in (0, 0xbc09fa04, 0x20144000):
            remote = Remote(context)
            result = playback_transform_snapshot(remote, dict(sp=0x50000000, r4=0))
            self.assertIn('matrix_unavailable', result)
            self.assertNotIn('matrix_q16', result)
            self.assertEqual(remote.reads, [0xb1800c38, 0x50000000])


if __name__ == '__main__':
    unittest.main()
