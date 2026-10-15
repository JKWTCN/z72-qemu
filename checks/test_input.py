# SPDX-License-Identifier: GPL-2.0-or-later
"""Firmware-free input-guard checks: wrong size and wrong content rejection."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import MASTER_SIZE, MASTER_SHA, validate_master

class InputGuards(unittest.TestCase):
    def test_wrong_content_rejected(self):
        with self.assertRaisesRegex(ValueError, 'stock'):
            validate_master(b'not a firmware')

    def test_wrong_size_rejected(self):
        with self.assertRaisesRegex(ValueError, 'stock'):
            validate_master(b'\0' * (MASTER_SIZE + 1))

    def test_declared_identity_is_the_stock_master(self):
        # The recorded identity must stay the studied C 1.70 master; guards
        # compare against it, so a silent change would repoint every probe.
        self.assertEqual(MASTER_SIZE, 38239098)
        self.assertEqual(len(MASTER_SHA), 64)

if __name__ == '__main__':
    unittest.main()
