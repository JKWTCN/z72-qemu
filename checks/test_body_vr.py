# SPDX-License-Identifier: GPL-2.0-or-later
"""Firmware-free checks for the body VR member structure parser."""
import struct
import unittest

from analyze.decode_z72 import crc
from analyze.body_vr import LABEL, RECORD_LENGTH, describe_member


def build(pages, version=(4, 0x0100, 1, 0)):
    """Assemble a synthetic body VR member from (address, data) pages."""
    header = bytearray(RECORD_LENGTH)
    header[:2] = b'\x04\x01'
    struct.pack_into('<4H', header, 2, *version)
    header[0xA:0xA + len(LABEL)] = LABEL
    body = bytearray(header)
    for address, data in pages:
        require_page = bytearray(RECORD_LENGTH)
        require_page[:2] = b'\x04\x01'
        struct.pack_into('<I', require_page, 2, address)
        data = (data + b'\xff' * 0x100)[:0x100]
        require_page[6:] = data
        body += require_page
    return bytes(body) + struct.pack('>H', crc(bytes(body)))


class BodyVrTests(unittest.TestCase):
    def test_describes_the_page_window(self):
        member = build([(0xFFF00000, b'\x01\x02'), (0xFFF00100, b'')])
        described = describe_member(member)
        self.assertEqual(described['records'], 3)
        self.assertEqual(described['pages'], 2)
        self.assertEqual(described['base'], 0xFFF00000)
        self.assertEqual(described['limit'], 0xFFF00200)
        self.assertEqual(described['filled_pages'], 1)
        self.assertEqual(described['header_words'], (4, 0x0100, 1, 0))

    def test_rejects_broken_crc_and_header(self):
        member = bytearray(build([(0xFFF00000, b'x')]))
        member[7] ^= 0x40
        with self.assertRaisesRegex(ValueError, 'CRC'):
            describe_member(bytes(member))
        member = build([(0xFFF00000, b'x')])
        headerless = bytearray(member)[:-2]
        headerless[0xA] = ord('X')
        headerless += struct.pack('>H', crc(bytes(headerless)))
        with self.assertRaisesRegex(ValueError, 'label'):
            describe_member(bytes(headerless))

    def test_rejects_nonconsecutive_or_unaligned_pages(self):
        with self.assertRaisesRegex(ValueError, 'consecutive'):
            describe_member(build([(0xFFF00000, b'a'), (0xFFF00300, b'b')]))
        with self.assertRaisesRegex(ValueError, 'aligned'):
            describe_member(build([(0xFFF00010, b'a')]))

    def test_rejects_wrong_lengths(self):
        with self.assertRaisesRegex(ValueError, 'records'):
            describe_member(b'\x04\x01' + b'\x00' * 8)
        member = build([(0xFFF00000, b'a')])
        with self.assertRaisesRegex(ValueError, 'records'):
            describe_member(member[:-1])


if __name__ == '__main__':
    unittest.main()
