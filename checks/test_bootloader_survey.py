# SPDX-License-Identifier: GPL-2.0-or-later
"""Firmware-independent checks for the bootloader survey decoder."""
import importlib.util
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    'bootloader_survey', ROOT / 'tools' / 'bootloader_survey.py')
survey = importlib.util.module_from_spec(spec)
sys.modules['bootloader_survey'] = survey
spec.loader.exec_module(survey)


def image_with_templates():
    """Build a synthetic master-like buffer with two templates and records."""
    image = bytearray(0x1000)
    image[0x100:0x10C] = b'NKLD????.BIN'
    image[0x200:0x20C] = b'Z7_2_???.BIN'
    # Scan-style record: category 7, pointer, no condition.
    struct.pack_into('<IIII', image, 0x400, 7,
                     survey.BASE + 0x100, 0, 0)
    # Enumeration-style record: category 4, pointer, code condition.
    struct.pack_into('<IIII', image, 0x420, 4,
                     survey.BASE + 0x200, survey.BASE + 0x10, 0)
    return bytes(image)


class TemplateRecordTests(unittest.TestCase):
    def test_template_offsets(self):
        offsets = survey.template_offsets(image_with_templates())
        self.assertEqual(offsets['NKLD????.BIN'], 0x100)
        self.assertEqual(offsets['Z7_2_???.BIN'], 0x200)
        self.assertLess(offsets['LF??????.BIN'], 0)

    def test_update_records_recover_both_tables(self):
        image = image_with_templates()
        records = survey.update_records(image, survey.template_offsets(image))
        self.assertEqual([r['category'] for r in records['NKLD????.BIN']], [7])
        self.assertEqual(records['NKLD????.BIN'][0]['condition'], 0)
        self.assertEqual([r['category'] for r in records['Z7_2_???.BIN']], [4])
        self.assertEqual(records['Z7_2_???.BIN'][0]['condition'], survey.BASE + 0x10)

    def test_pointer_without_record_is_ignored(self):
        image = bytearray(image_with_templates())
        # A bare pointer outside a record-shaped window must not be reported.
        struct.pack_into('<I', image, 0x800, survey.BASE + 0x100)
        records = survey.update_records(bytes(image),
                                        survey.template_offsets(bytes(image)))
        self.assertEqual(len(records['NKLD????.BIN']), 1)


class TbbTests(unittest.TestCase):
    def test_tbb_targets_are_halfword_offsets(self):
        image = bytearray(0x40)
        image[0x04:0x0A] = bytes([2, 4, 8, 16, 0xFF])
        targets = survey.tbb_targets(bytes(image), 0, 5)
        self.assertEqual(targets, [8, 12, 20, 36, 514])


def synthetic_nkld(data_offset, total, major, minor, entries, magic, data_length):
    payload = bytearray(0x100)
    struct.pack_into('>HHBBH', payload, 0, data_offset, total, major, minor, entries)
    struct.pack_into('>I', payload, 8, magic)
    struct.pack_into('>H', payload, 12, data_length)
    return payload


class NkldHeaderTests(unittest.TestCase):
    def write(self, payload):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / 'nkld.bin'
        path.write_bytes(payload)
        return path

    def test_known_header_parses(self):
        path = self.write(synthetic_nkld(0x20, 0x80, 1, 4, 3, 0x87C7CAAC, 0x40))
        header = survey.nkld_header(path)
        self.assertTrue(header['magic_known'])
        self.assertTrue(header['bounds_sane'])
        self.assertEqual(header['entry_count'], 3)
        self.assertEqual(header['data_length'], 0x40)
        self.assertEqual((header['major_version'], header['minor_version']), (1, 4))

    def test_unknown_magic_flagged(self):
        path = self.write(synthetic_nkld(0x20, 0x80, 1, 4, 0, 0x12345678, 0x40))
        self.assertFalse(survey.nkld_header(path)['magic_known'])

    def test_bad_bounds_rejected(self):
        path = self.write(synthetic_nkld(0x20, 0x10, 1, 4, 0, 0x87C7CAAC, 0x40))
        self.assertFalse(survey.nkld_header(path)['bounds_sane'])


class NegativeScanTests(unittest.TestCase):
    def test_hits_and_negatives(self):
        data = b'xxxxBOOTDISKyyyyautoexeczz' + b'BOOT' * 3
        result = survey.negative_scan('synthetic', data)
        self.assertEqual(result['keyword_hits']['BOOTDISK']['count'], 1)
        self.assertEqual(result['keyword_hits']['autoexec']['count'], 1)
        self.assertEqual(result['keyword_hits']['BOOT']['count'], 4)
        self.assertNotIn('bootdisk', result['keyword_hits'])


if __name__ == '__main__':
    unittest.main()
