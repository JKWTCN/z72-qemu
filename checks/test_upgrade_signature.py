# SPDX-License-Identifier: GPL-2.0-or-later
"""Firmware-free checks for the recovered update-file digest scheme."""
import hashlib
import struct
import unittest

from analyze.upgrade_signature import (HEADER_LENGTH, assemble_update, decode,
                                       encode, key_stream, update_digest,
                                       verify_update)


def table_master(seed=1):
    """Build an image carrying deterministic tables at the pinned offsets.

    The update check reads its three table regions from the supplied master
    image; a synthetic image with synthetic tables exercises the whole
    scheme without any firmware content.
    """
    from analyze.upgrade_signature import ENCODE_TABLES, INDEX_TABLE, STREAM_TABLE
    size = max(STREAM_TABLE, INDEX_TABLE, ENCODE_TABLES + 0x300) + 16
    image = bytearray(size)
    state = seed

    def filler(length):
        nonlocal state
        out = bytearray(length)
        for i in range(length):
            state = (state * 1103515245 + 12345) & 0x7FFFFFFF
            out[i] = (state >> 16) & 0xFF
        return bytes(out)

    image[STREAM_TABLE:STREAM_TABLE + 0x100] = filler(0x100)
    image[INDEX_TABLE:INDEX_TABLE + 0x100] = filler(0x100)
    image[ENCODE_TABLES:ENCODE_TABLES + 0x300] = filler(0x300)
    return bytes(image)


class UpdateSignatureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.master = table_master()
        cls.key = bytes.fromhex('0011223344556677')
        cls.member = bytes((i * 13 + 7) & 0xFF for i in range(4096))

    def test_stream_matches_the_recovered_formula(self):
        # The seed folds through the first table, the model string through
        # the second. Model the two accumulating registers independently.
        from analyze.upgrade_signature import MODEL, SEED, STREAM_PERIOD, STREAM_TABLE, INDEX_TABLE
        challenge = struct.unpack('>I', struct.pack('<I', ~SEED & 0xFFFFFFFF))[0]
        folded = 0
        for shift in (0, 8, 16, 24):
            folded ^= challenge >> shift & 0xFF
        index = 0
        for char in MODEL.encode('ascii'):
            digit = char - 0x30 if 0x30 <= char <= 0x39 else char % 10
            index = index * 10 + digit
        base = self.master[STREAM_TABLE + folded]
        multiplier = self.master[INDEX_TABLE + (index & 0xFF)]
        increment = STREAM_PERIOD * multiplier
        expected = bytearray()
        for _ in range(8):
            base += increment
            increment += multiplier
            expected.append(base & 0xFF)
        self.assertEqual(key_stream(self.master), bytes(expected))

    def test_stream_accumulates_before_each_byte(self):
        from analyze.upgrade_signature import STREAM_TABLE, INDEX_TABLE
        image = bytearray(self.master)
        image[STREAM_TABLE:STREAM_TABLE + 0x100] = bytes([0x12]) * 0x100
        image[INDEX_TABLE:INDEX_TABLE + 0x100] = bytes([3]) * 0x100
        self.assertEqual(key_stream(image), bytes.fromhex('32557ba4 d0ff3166'))

    def test_decode_is_stream_inverse_and_offset_aligned(self):
        blob = self.member * 3
        for index in (0, 1, 0x20, 0xFF, 0x137):
            self.assertEqual(encode(self.master, decode(self.master, blob, index),
                                    index), blob)

    def test_decode_of_short_and_empty_inputs(self):
        self.assertEqual(decode(self.master, b''), b'')
        self.assertEqual(len(decode(self.master, b'\x01\x02\x03', 0x20)), 3)

    def test_digest_covers_marker_body_and_key(self):
        payload = encode(self.master, self.member, HEADER_LENGTH)
        digest = update_digest(b' ' * HEADER_LENGTH, payload, self.key, self.master)
        body = b' ' * HEADER_LENGTH + self.member
        appended = bytes(a ^ b for a, b in zip(self.key, key_stream(self.master)))
        self.assertEqual(digest, hashlib.sha1(body + appended).digest())

    def test_assemble_then_verify_round_trip(self):
        update_file = assemble_update(self.member, self.key, self.master)
        self.assertTrue(update_file.startswith(
            update_digest(b' ' * HEADER_LENGTH,
                          update_file[HEADER_LENGTH * 2:], self.key, self.master)))
        described = verify_update(update_file, self.key, self.master)
        self.assertEqual(described['payload'], self.member)
        self.assertEqual(described['length'], len(update_file))
        self.assertEqual(described['digest'], update_file[:0x14].hex())

    def test_verify_rejects_other_boot_key(self):
        update_file = assemble_update(self.member, self.key, self.master)
        with self.assertRaisesRegex(ValueError, 'digest'):
            verify_update(update_file, bytes(8), self.master)

    def test_verify_rejects_modified_body_and_header(self):
        update_file = bytearray(assemble_update(self.member, self.key, self.master))
        update_file[HEADER_LENGTH * 2 + 5] ^= 0x40
        with self.assertRaisesRegex(ValueError, 'digest'):
            verify_update(bytes(update_file), self.key, self.master)
        update_file = bytearray(assemble_update(self.member, self.key, self.master))
        update_file[0] ^= 1
        with self.assertRaisesRegex(ValueError, 'digest'):
            verify_update(bytes(update_file), self.key, self.master)

    def test_verify_rejects_missing_marker_and_truncated_files(self):
        update_file = assemble_update(self.member, self.key, self.master)
        unmarked = bytearray(update_file)
        unmarked[HEADER_LENGTH:HEADER_LENGTH + 4] = b'XXXX'
        with self.assertRaisesRegex(ValueError, 'prefix'):
            verify_update(bytes(unmarked), self.key, self.master)
        with self.assertRaisesRegex(ValueError, 'shorter'):
            verify_update(update_file[:0x30], self.key, self.master)

    def test_boot_key_must_hold_eight_bytes(self):
        from analyze.upgrade_signature import appended_key
        with self.assertRaisesRegex(ValueError, 'eight'):
            appended_key(bytes(9), self.master)

    def test_table_master_must_cover_the_tables(self):
        with self.assertRaisesRegex(ValueError, 'too short'):
            key_stream(b'0' * 16)
        from analyze.upgrade_signature import INDEX_TABLE
        with self.assertRaisesRegex(ValueError, 'too short'):
            key_stream(self.master[:INDEX_TABLE + 0xFF])


if __name__ == '__main__':
    unittest.main()
