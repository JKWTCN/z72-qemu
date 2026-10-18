# SPDX-License-Identifier: GPL-2.0-or-later
"""Firmware-free checks for the console update store and its acceptance."""
from pathlib import Path
import struct
import tempfile
import unittest

from analyze.decode_z72 import crc
from analyze.update_store import UpdateStore, installable_master
from checks.synthetic_master import build


class InstallableMasterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = build()
        cls.identity = installable_master(cls.image)

    def test_accepts_stock_shaped_and_appended_images(self):
        self.assertEqual(self.identity['role'], 'master')
        self.assertEqual(self.identity['length'], len(self.image))
        self.assertEqual(self.identity['version'], 'Ver.01.70.02')
        longer = build(extra=68)
        self.assertEqual(installable_master(longer)['length'], len(longer))

    def test_rejects_shorter_and_overlong_images(self):
        with self.assertRaisesRegex(ValueError, 'memory window'):
            installable_master(self.image[:-4])
        huge = build(extra=1)
        with self.assertRaisesRegex(ValueError, 'memory window'):
            installable_master(huge + bytes(0x14000000 - 0x10020000))

    def test_rejects_broken_member_crc(self):
        image = bytearray(self.image)
        image[0x2000] ^= 0xFF
        with self.assertRaisesRegex(ValueError, 'CRC'):
            installable_master(bytes(image))

    def test_rejects_malformed_version_records(self):
        image = bytearray(self.image[:-2])
        image[0x20:0x2C] = b'NO.VERSION.9'
        image += struct.pack('>H', crc(bytes(image)))
        with self.assertRaisesRegex(ValueError, 'Ver'):
            installable_master(bytes(image))

    def test_rejects_changed_boot_layout(self):
        image = bytearray(self.image[:-2])
        image[0] ^= 0x04
        image += struct.pack('>H', crc(bytes(image)))
        with self.assertRaisesRegex(ValueError, '[Bb]ranch'):
            installable_master(bytes(image))


class UpdateStoreTests(unittest.TestCase):
    def setUp(self):
        self.image = build()
        self.directory = Path(tempfile.mkdtemp(prefix='update-store-'))
        self.store = UpdateStore(self.directory)

    def tearDown(self):
        for item in self.directory.iterdir():
            item.unlink()
        self.directory.rmdir()

    def test_empty_store_reads_absent(self):
        self.assertIsNone(self.store.installed())

    def test_install_commit_and_reload(self):
        manifest = self.store.install(self.image, note='candidate')
        self.assertEqual(manifest['sha256'], installable_master(self.image)['sha256'])
        identity, image = self.store.load()
        self.assertEqual(identity['sha256'], manifest['sha256'])
        self.assertEqual(image, self.image)

    def test_image_without_manifest_is_not_installed(self):
        self.store.install(self.image)
        self.store.manifest_path.unlink()
        self.assertIsNone(self.store.installed())

    def test_tampered_image_fails_verification(self):
        self.store.install(self.image)
        stored = bytearray(self.store.image_path.read_bytes())
        stored[0x2000] ^= 0xFF
        self.store.image_path.write_bytes(bytes(stored))
        with self.assertRaises(ValueError):
            self.store.installed()

    def test_remove_rolls_back(self):
        self.store.install(self.image)
        self.store.remove()
        self.assertIsNone(self.store.installed())
        self.assertFalse(self.store.image_path.exists())

    def test_install_replaces_previous_update(self):
        self.store.install(self.image)
        replacement = build(extra=68)
        self.store.install(replacement, note='newer')
        identity, image = self.store.load()
        self.assertEqual(image, replacement)
        self.assertEqual(identity['note'], 'newer')


if __name__ == '__main__':
    unittest.main()
