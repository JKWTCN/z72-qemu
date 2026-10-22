# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic update directories exercise bounds and independent CRC checks."""
import struct
import unittest

from analyze.decode_z72 import crc
from analyze.update_container import describe_container, master_member


def build_container(members):
    """Build a decoded body from caller-supplied CRC-bearing members."""
    header = 0x30 + len(members) * 0x20
    directory = bytearray(b' ' * 0x20 + struct.pack('>4I', len(members), header, 0, 0))
    offset = header
    for name, member in members:
        directory += struct.pack('>16s4I', name.encode('ascii'), offset, len(member), 0, 0)
        offset += len(member)
    body = bytes(directory) + b''.join(member for _, member in members)
    return body + crc(body).to_bytes(2, 'big') + bytes(14)


class UpdateContainerTests(unittest.TestCase):
    def setUp(self):
        data = b'synthetic master'
        self.member = data + crc(data).to_bytes(2, 'big')
        self.body = build_container([('eg1840_mas_01700', self.member),
                                     ('_tpj01_v140.bin', b'\0\0')])

    def test_directory_offsets_include_marker(self):
        described = describe_container(self.body)
        self.assertEqual(described['header_length'], 0x70)
        self.assertEqual(described['members'][0]['offset'], 0x70)
        self.assertEqual(master_member(self.body[0x20:]), self.member)

    def test_rejects_directory_bounds_and_reserved_fields(self):
        for offset, value in ((0x20, 65), (0x24, 0x80), (0x28, 1),
                              (0x40, 0x71), (0x44, 0xffffffff), (0x48, 1)):
            with self.subTest(offset=offset):
                body = bytearray(self.body)
                struct.pack_into('>I', body, offset, value)
                with self.assertRaises(ValueError):
                    describe_container(body)
        for size in (0, 0x2F, 0x6F, len(self.body) - 1):
            with self.assertRaises(ValueError):
                describe_container(self.body[:size])

    def test_checks_member_crc_even_when_container_crc_is_valid(self):
        body = bytearray(self.body[:-16])
        body[-1] ^= 1
        body += crc(body).to_bytes(2, 'big') + bytes(14)
        with self.assertRaisesRegex(ValueError, 'member CRC'):
            describe_container(body)

    def test_rejects_bad_container_crc_or_padding(self):
        for offset in (-16, -1):
            body = bytearray(self.body)
            body[offset] ^= 1
            with self.assertRaises(ValueError):
                describe_container(body)

    def test_rejects_duplicate_names_and_missing_or_multiple_masters(self):
        duplicate = build_container([('same', b'\0\0'), ('same', b'\0\0')])
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            describe_container(duplicate)
        for members in ([('other', b'\0\0')],
                        [('eg1840_mas_01700', b'\0\0'), ('eg1840_mas_01610', b'\0\0')]):
            with self.assertRaisesRegex(ValueError, 'exactly one master'):
                master_member(build_container(members)[0x20:])


if __name__ == '__main__':
    unittest.main()
