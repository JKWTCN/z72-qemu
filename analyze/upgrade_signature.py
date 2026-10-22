# SPDX-License-Identifier: GPL-2.0-or-later
"""Update-file integrity check recovered from the stock menu update path.

Firmware analysis recovered the whole-file check the menu update runs before
anything is programmed into the body: the first twenty bytes of the update
file are the expected digest, and the accepted digest is SHA-1 over the
marked body plus eight appended key bytes. The appended bytes are the engine
boot-window key material combined with a fixed stream derived from a seed,
the model string and two 256-byte tables that live inside the supplied
master image. This module takes the raw boot-window bytes as a separate
local input. Reading them from that window does not establish where the
boot code originally obtains them, or exclude construction from immediates.

The file layout this module expects:

| Region | Content |
| --- | --- |
| `+0x00..+0x14` | expected SHA-1 digest |
| `+0x14..+0x20` | ignored padding |
| `+0x20..+0x40` | the marked body prefix (enters the digest verbatim) |
| `+0x40..` | encoded payload (three-table stream from index `0x20`) |

This module verifies update files and recomputes digests so a locally built
custom update can carry a recomputed digest; it never writes decoded firmware
anywhere.
"""
import hashlib
import struct

from analyze.decode_z72 import BASE, require

# Check parameters recovered from the stock whole-file update check.
HEADER_LENGTH = 0x20
DIGEST_LENGTH = 0x14
SEED = 0x44B
MODEL = 'Z_7_2'
STREAM_TABLE = 0x12068276 - BASE   # seed-derived table inside the image
INDEX_TABLE = 0x12068376 - BASE    # model-derived table inside the image
ENCODE_TABLES = 0x119800D0 - BASE  # three consecutive 0x100-byte streams
STREAM_PERIOD = 0x260
KEY_LENGTH = 8
BOOT_KEY_LENGTH = KEY_LENGTH


def _tables(master):
    """Return (stream_table, index_table, encode_tables) from the image."""
    require(len(master) >= max(STREAM_TABLE + 0x100, INDEX_TABLE + 0x100,
                               ENCODE_TABLES + 0x300),
            'Master image is too short for the update-check tables')
    return (master[STREAM_TABLE:STREAM_TABLE + 0x100],
            master[INDEX_TABLE:INDEX_TABLE + 0x100],
            master[ENCODE_TABLES:ENCODE_TABLES + 0x300])


def key_stream(master):
    """Return the eight derived bytes appended to the body.

    The seed is complemented and byte-reversed, folded into one table index;
    the model string collapses to a decimal index into the second table.
    Each round adds the current increment to an accumulator, then advances
    the increment by the multiplier (member offsets 0x39C376..0x39C382).
    """
    stream_table, index_table, _ = _tables(master)
    challenge = struct.unpack('>I', struct.pack('<I', ~SEED & 0xFFFFFFFF))[0]
    folded = ((challenge & 0xFF) ^ (challenge >> 8 & 0xFF) ^
              (challenge >> 16 & 0xFF) ^ (challenge >> 24 & 0xFF))
    index = 0
    for char in MODEL.encode('ascii'):
        digit = char - 0x30 if 0x30 <= char <= 0x39 else char % 10
        index = index * 10 + digit
    base = stream_table[folded]
    multiplier = index_table[index & 0xFF]
    return bytes((base + multiplier *
                  ((i + 1) * STREAM_PERIOD + i * (i + 1) // 2)) & 0xFF
                 for i in range(KEY_LENGTH))


def decode(master, data, index=0):
    """Decode an encoded payload region with the in-image byte streams.

    The three stream bytes depend on the position modulo 0x100 and the two
    higher index bytes; segments are cut where those higher bytes change so
    each segment is one wide XOR against a precomputed rotation.
    """
    *_, tables = _tables(master)
    low, middle, high = tables[:0x100], tables[0x100:0x200], tables[0x200:0x300]
    rotations = [bytes(low[r:]) + bytes(low[:r]) for r in range(0x100)]
    out = bytearray()
    position = index
    while position - index < len(data):
        start = position - index
        run = min(0x100 - (position & 0xFF), len(data) - start)
        block = int.from_bytes(data[start:start + run], 'big')
        block ^= int.from_bytes(rotations[position & 0xFF][:run], 'big')
        block ^= int.from_bytes(
            bytes((middle[position >> 8 & 0xFF] ^ high[position >> 16 & 0xFF],)) * run,
            'big')
        out += block.to_bytes(run, 'big')
        position += run
    return bytes(out)


def encode(master, data, index=0):
    """Encode a payload region with the same in-image byte streams."""
    return decode(master, data, index)


def appended_key(boot_key, master):
    """Combine the boot-window key material with the derived stream."""
    require(len(boot_key) == BOOT_KEY_LENGTH,
            'Expected exactly eight boot-window key bytes')
    return bytes(key ^ stream for key, stream in zip(boot_key, key_stream(master)))


def update_digest(prefix, payload, boot_key, master):
    """Return the digest the whole-file check computes for an update file."""
    body = prefix + decode(master, payload, HEADER_LENGTH)
    return hashlib.sha1(body + appended_key(boot_key, master)).digest()


def assemble_update(member, boot_key, master):
    """Return a digest-bearing update file carrying the supplied payload.

    The payload is encoded with the in-image streams from index 0x20 and the
    recomputed digest lands in the file header, so the result passes the
    recovered digest check. This does not establish container validity or
    camera acceptance. A real package payload includes its directory,
    members and trailer, excluding the marker added here.
    """
    require(HEADER_LENGTH <= len(member), 'Payload member is too short')
    payload = encode(master, member, HEADER_LENGTH)
    digest = update_digest(b' ' * HEADER_LENGTH, payload, boot_key, master)
    return digest + bytes(HEADER_LENGTH - DIGEST_LENGTH) + \
        b' ' * HEADER_LENGTH + payload


def verify_update(update_file, boot_key, master):
    """Describe and verify one update file; raise when a binding fails.

    Returns the decoded payload together with the digest comparison. The
    structural expectations (marker, length) match the analyzed check; the
    payload's own member checks belong to the caller.
    """
    require(len(update_file) > HEADER_LENGTH * 2,
            'Update file is shorter than its header and marker')
    expected = update_file[:DIGEST_LENGTH]
    prefix = update_file[HEADER_LENGTH:HEADER_LENGTH * 2]
    require(prefix == b' ' * HEADER_LENGTH,
            'Update file lacks the marked body prefix')
    payload = update_file[HEADER_LENGTH * 2:]
    computed = update_digest(prefix, payload, boot_key, master)
    require(computed == expected, 'Update digest mismatch')
    return dict(digest=expected.hex(), length=len(update_file),
                payload=decode(master, payload, HEADER_LENGTH))
