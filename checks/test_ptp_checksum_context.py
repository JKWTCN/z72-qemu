# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic controls for the fixed-context read and material verification."""
import struct
import unittest

from analyze.ptp_checksum_context import (CALLBACK, CONTEXT, CONTEXT_SIZE,
    TRANSFORMED_SEED, capture, inspect_context, parameters)
from analyze.upgrade_signature import appended_key, assemble_update
from checks.test_update_container import build_container
from checks.test_upgrade_signature import table_master


def text(value):
    data = (value + '\0').encode('utf-16-le')
    return bytes([len(data) // 2]) + data


def device_info(model='Z 7_2'):
    return (struct.pack('<HIH', 100, 10, 100) + text('vendor') + bytes(2) +
            bytes(5 * 4) + text('Nikon Corporation') + text(model) +
            text('V1.70') + text('private serial'))


class Camera:
    def __init__(self, model='Z 7_2', response=(0x2001, [0x2001]), fail=False):
        self.model, self.response, self.fail = model, response, fail
        self.events = []

    def read(self, opcode, args):
        self.events.append((opcode, args))
        if opcode == 0x1001:
            return device_info(self.model), (0x2001, [])
        if self.fail:
            raise RuntimeError('synthetic transport failure')
        return bytes(CONTEXT_SIZE), self.response

    def send(self, opcode, args):
        self.events.append((opcode, args))
        return 0x2001, [0x2001]


class ChecksumContextTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.master = table_master()
        cls.boot = bytes(range(8))
        cls.body = build_container([('synthetic', b'\0\0')])
        cls.package = assemble_update(cls.body[32:], cls.boot, cls.master)

    def context(self, transformed=True):
        return struct.pack('<III8sI8s20s', 0x52000000,
            len(self.body) + (8 if transformed else 0), CALLBACK,
            appended_key(self.boot, self.master) if transformed else self.boot,
            TRANSFORMED_SEED if transformed else 0x44B,
            b'Z_7_2\0\0\0', self.package[:20])

    def test_raw_and_transformed_snapshots_require_the_package_digest(self):
        for transformed in (False, True):
            report, material = inspect_context(self.context(transformed), self.package, self.master)
            self.assertTrue(report['package_digest_verified'])
            self.assertEqual(material['boot_key'], self.boot.hex())
            self.assertNotIn('boot_key', report)
            self.assertNotIn('appended_key', report)
        changed = bytearray(self.context())
        changed[12] ^= 1
        report, material = inspect_context(changed, self.package, self.master)
        self.assertFalse(report['package_digest_verified'])
        self.assertIsNone(material)

    def test_uninitialized_or_unbound_state_is_not_material(self):
        for snapshot in (bytes(CONTEXT_SIZE), self.context()[:-1], b''):
            if len(snapshot) == CONTEXT_SIZE:
                report, material = inspect_context(snapshot, self.package, self.master)
                self.assertFalse(report['context_binding_valid'])
                self.assertIsNone(material)
            else:
                with self.assertRaises(ValueError):
                    inspect_context(snapshot, self.package, self.master)
        for offset in (4, 8, 20, 24, 32):
            changed = bytearray(self.context())
            changed[offset] ^= 1
            report, material = inspect_context(changed, self.package, self.master)
            self.assertFalse(report['context_binding_valid'])
            self.assertIsNone(material)

    def test_live_transaction_set_is_fixed_and_exits_service(self):
        camera = Camera()
        data, identity = capture(camera)
        self.assertEqual(len(data), CONTEXT_SIZE)
        self.assertEqual(identity['model'], 'Z 7_2')
        self.assertNotIn('serial', identity)
        self.assertEqual(camera.events, [
            (0x1001, []), (0x94FD, parameters(0xF001)),
            (0x94FF, parameters(0xF032, CONTEXT, CONTEXT_SIZE)),
            (0x94FE, parameters(0xF002))])

    def test_inner_failure_and_transport_error_still_exit(self):
        for camera in (Camera(response=(0x2001, [0x201D])), Camera(fail=True)):
            with self.assertRaises((ValueError, RuntimeError)):
                capture(camera)
            self.assertEqual(camera.events[-1], (0x94FE, parameters(0xF002)))

    def test_wrong_model_never_enters_service(self):
        camera = Camera(model='other')
        with self.assertRaisesRegex(ValueError, 'Z7 II'):
            capture(camera)
        self.assertEqual(camera.events, [(0x1001, [])])


if __name__ == '__main__':
    unittest.main()
