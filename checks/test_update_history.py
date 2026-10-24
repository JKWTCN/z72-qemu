# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic instruction and digest controls for the history audit."""
import hashlib
import struct
import unittest

from tools.update_history_probe import BOOT_ADDRESS, boot_readers, compare_candidate


class UpdateHistoryTests(unittest.TestCase):
    def test_literal_reader_requires_the_complete_argument_sequence(self):
        image = bytearray(64)
        # Synthetic Thumb: LDR r0, literal; MOV r2, sp; MOVW r1, 0x44b;
        # BL 0x30; BL 0x40. The literal lies at member offset 0x20.
        struct.pack_into('<8H', image, 0,
                         0x4807, 0x466A, 0xF240, 0x414B,
                         0xF000, 0xF812, 0xF000, 0xF818)
        struct.pack_into('<I', image, 32, BOOT_ADDRESS)
        self.assertEqual(boot_readers(image), [dict(
            offset=0, literal_offset=32, address=BOOT_ADDRESS, seed=0x44B,
            setup_target=0x30, check_target=0x40)])
        for pos, value in ((0, 0x4907), (2, 0x4602), (6, 0x424B), (12, 0xBF00)):
            changed = bytearray(image)
            struct.pack_into('<H', changed, pos, value)
            with self.subTest(pos=pos):
                self.assertEqual(boot_readers(changed), [])
        self.assertEqual(boot_readers(image[:15]), [])
        struct.pack_into('<I', image, 32, BOOT_ADDRESS + 4)
        self.assertEqual(boot_readers(image), [])

    def test_digest_oracle_distinguishes_raw_and_final_bytes(self):
        body, raw, stream = b'synthetic marked body', b'12345678', b'abcdefgh'
        final = bytes(a ^ b for a, b in zip(raw, stream))
        expected = hashlib.sha1(body + final).digest()
        state = hashlib.sha1(body)
        self.assertEqual(compare_candidate(raw, state, expected, stream), ['B8'])
        self.assertEqual(compare_candidate(final, state, expected, stream), ['K8'])
        self.assertEqual(compare_candidate(b'87654321', state, expected, stream), [])
        self.assertEqual(state.digest(), hashlib.sha1(body).digest())


if __name__ == '__main__':
    unittest.main()
