# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic master-shaped images for firmware-free structure checks.

The builder fabricates only the structural fields the update acceptance
executes or decodes (version record, reset branch, initialization table,
communication window, boot prefix and identity page-table descriptors).
Every byte comes from this file; no firmware content is used. The member
CRC is recomputed so the residue reads zero like a real rebuild.
"""
import struct

from analyze.decode_z72 import BASE, crc
from analyze.firmware_structure import PROFILES


def _descriptor(image, section):
    struct.pack_into('<I', image, 0x10000 + (section >> 20) * 4, section | 2)


def build(extra=0, version=b'Ver.01.70.02'):
    """Return a minimal image that passes the installed-update checks."""
    profile = PROFILES['master']
    image = bytearray(profile.size + extra)
    image[0x20:0x2C] = version
    # Reset branch straight to the recorded boot continuation.
    struct.pack_into('<I', image, 0, 0xEA000000 | ((profile.boot - 8) >> 2))
    # Scatter table: nineteen copies plus the communication zero record.
    position = 0x14000
    for index in range(19):
        struct.pack_into('<4I', image, position + index * 16,
                         BASE + 0x1000 + index * 4, 0xB1800000 + index * 4,
                         4, BASE + 0x6C)
    struct.pack_into('<4I', image, position + 19 * 16,
                     BASE, 0xB7CF0000, 0xC618, BASE + 0x88)
    # Communication header store block and its literal pool.
    entry = 0x367E20
    struct.pack_into('<8H', image, entry,
                     0x4804, 0x2100, 0x4A02, 0x4B04, 0x6002, 0xE9C0, 0x3101, 0x6101)
    struct.pack_into('<3I', image, 0x367E30,
                     0x00C00108, 0xB7CF0000, 0xAA550001)
    # Boot prefix: mov r1,#0x21; str r1,[r0] with r0 loaded from a literal.
    struct.pack_into('<3I', image, profile.literals, 0, 0, 0)
    stacks = profile.literals + 16
    for index in range(6):
        struct.pack_into('<I', image, stacks + index * 4, 0x04009FFC + index * 0x4000)
    struct.pack_into('<I', image, 0xBD9C, 0xE59F000C)
    struct.pack_into('<I', image, 0xBDA0, 0xE3A01021)
    struct.pack_into('<I', image, 0xBDA4, 0xE5801000)
    struct.pack_into('<I', image, 0xBDB0, 0x04264000)
    for section in (0x04000000, 0x04200000, 0x10000000, 0x10100000):
        _descriptor(image, section)
    # Member CRC: appending the big-endian CRC yields a zero residue.
    residue = crc(bytes(image[:-2]))
    image[-2:] = struct.pack('>H', residue)
    return bytes(image)
