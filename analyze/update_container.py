# SPDX-License-Identifier: GPL-2.0-or-later
"""Describe a locally supplied decoded update body without writing members.

Offsets in the big-endian directory include the 32-byte body marker. CRC
checks establish structural integrity only; they do not verify the separate
whole-file SHA-1 digest or establish that a camera will accept an update.
"""
import re
import struct

from analyze.decode_z72 import crc, digest, require


def describe_container(body):
    """Validate the directory, member CRCs and observed CRC/padding trailer."""
    require(len(body) >= 0x30 and body[:0x20] == b' ' * 0x20,
            'Invalid update body marker or length')
    count, header, reserved1, reserved2 = struct.unpack_from('>4I', body, 0x20)
    require(0 < count <= 64 and header == 0x30 + count * 0x20,
            'Invalid update directory length or member count')
    require(reserved1 == reserved2 == 0 and header <= len(body),
            'Invalid update directory reserved fields or bounds')
    members = []
    names = set()
    end = header
    for index in range(count):
        raw, start, size, r1, r2 = struct.unpack_from('>16s4I', body, 0x30 + index * 0x20)
        name = raw.rstrip(b'\0')
        require(re.fullmatch(rb'[A-Za-z0-9_.-]+', name) is not None
                and name not in (b'.', b'..') and name not in names,
                'Invalid or duplicate update member name')
        require(r1 == r2 == 0, 'Invalid update member reserved fields')
        require(size >= 2 and start == end and start + size <= len(body) - 2,
                'Invalid update member bounds')
        member = body[start:start + size]
        require(crc(member) == 0, 'Update member CRC mismatch')
        members.append(dict(name=name.decode('ascii'), offset=start, length=size,
                            sha256=digest(member), crc=member[-2:].hex()))
        names.add(name)
        end = start + size
    # The CRC immediately follows the last member; zero padding follows it.
    # Requiring the observed trailer size prevents zero padding from making
    # a truncated body look like a valid zero-residue stream.
    require(len(body) - end == 16 and body[end + 2:] == bytes(14),
            'Invalid update container trailer')
    require(crc(body[:end + 2]) == 0, 'Update container CRC mismatch')
    return dict(length=len(body), sha256=digest(body), header_length=header,
                members=members, trailer_offset=end, container_crc=body[end:end + 2].hex())


def master_member(payload):
    """Select one master from an authenticated decoded container payload.

    verify_update returns the bytes after the body marker. Only the master
    is installed by the console; the other members are validated here.
    """
    body = b' ' * 0x20 + payload
    described = describe_container(body)
    masters = [m for m in described['members'] if m['name'].startswith('eg1840_mas_')]
    require(len(masters) == 1, 'Expected exactly one master update member')
    member = masters[0]
    return body[member['offset']:member['offset'] + member['length']]


def pack_member(payload):
    """Append the big-endian zero-residue CRC to one member payload."""
    require(isinstance(payload, (bytes, bytearray)) and len(payload) >= 0,
            'Invalid member payload')
    return bytes(payload) + crc(payload).to_bytes(2, 'big')


def pack_container(entries):
    """Pack (name, payload) pairs, payload without its CRC, into a body.

    The result carries the 32-space marker, the big-endian directory, each
    member with its zero-residue CRC, and the container trailer; it must
    pass describe_container unchanged.
    """
    require(0 < len(entries) <= 64, 'Invalid update member count')
    names = set()
    for name, _ in entries:
        require(isinstance(name, (bytes, bytearray)) and
                re.fullmatch(rb'[A-Za-z0-9_.-]+', bytes(name)) is not None
                and bytes(name) not in (b'.', b'..') and bytes(name) not in names
                and len(bytes(name)) <= 16,
                'Invalid or duplicate member name: ' + repr(name))
        names.add(bytes(name))
    count = len(entries)
    header = 0x30 + count * 0x20
    packed = [pack_member(payload) for _, payload in entries]
    directory = struct.pack('>4I', count, header, 0, 0)
    offset = header
    rows = []
    for (name, _), member in zip(entries, packed):
        rows.append(struct.pack('>16s4I', bytes(name).ljust(16, b'\0'),
                                offset, len(member), 0, 0))
        offset += len(member)
    body = b' ' * 0x20 + directory + b''.join(rows) + b''.join(packed)
    trailer = crc(body).to_bytes(2, 'big') + bytes(14)
    result = body + trailer
    describe_container(result)
    return result
