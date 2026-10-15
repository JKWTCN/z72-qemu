# SPDX-License-Identifier: GPL-2.0-or-later
"""Decode the original parameter-block restore that follows the snapshot."""
from analyze.decode_z72 import BASE, digest, require
from analyze.firmware_structure import u32
from analyze.snapshot_boot import DEREF_ADDRESSES

PARAM_BASE = 0x20013000
MIRROR_BASE = 0x20016000
POLL = 0x20010038
TRIGGER = 0x20010060
RESTORE_COUNT = 19
MIRROR_DEST = 0x24074000
MIRROR_WORDS = 512
MIRROR_WINDOW = (0x24074000, 0x800)
FINAL_WORDS = (0x20015010, 0x20015014, 0x20015018, 0x2001501C, 0x20010034)
SECOND_POLL_TRIGGER = 0x20010034

def block_words():
    """Consecutive nine-word rows written twice per base register block."""
    words = []
    for base in (0x20012000, 0x20012100):
        for row in (0x00, 0x40):
            words += [base+row+offset for offset in range(0, 0x24, 4)]
    return words

# (destination, source word index from the pointer-table tail) per role.
_SCATTER_MASTER = ((0x20012648, 1), (0x20012490, 2), (0x200124A0, 2),
                   (0x20012790, 3), (0x20012798, 4), (0x20012628, 5),
                   (0x20012658, 6), (0x20012660, 6), (0x200127B0, 7),
                   (0x20012618, 8))
_SCATTER_SLAVE = ((0x20012648, 1), (0x20012490, 2), (0x200124A0, 2),
                  (0x20012790, 3), (0x20012798, 4), (0x20012628, 5),
                  (0x20012658, 6), (0x20012660, 6), (0x20012638, 7),
                  (0x20012640, 8), (0x200127B0, 9), (0x200127A8, 10))

# (source offset, destination offset, word count) within the tail copy.
SEGMENTS = ((0x000, 0x000, 23), (0x05C, 0x0BC, 8), (0x07C, 0x100, 23),
            (0x0D8, 0x1BC, 8), (0x0F8, 0x200, 23), (0x154, 0x2BC, 8),
            (0x174, 0x300, 23), (0x1D0, 0x3BC, 8))
MIRRORS = ((0x1F0, 0xA00, 8), (0x210, 0xA20, 8), (0x230, 0xA40, 8),
           (0x250, 0xA60, 8))

# Verified stock code windows are pinned by file offset, length and SHA-256.
# The original instruction bytes are not redistributed with this project.
_MASTER = dict(
    entry=0x1E70C0, source=0xB18A97F0, pointer=0xB18A96AC, snapshot=0xB2B40C10,
    scatter=_SCATTER_MASTER, chain_return=0x1E0042, function_end=0x1E730C,
    staging=dict(copy_return=0x3482A4, dest=0xBAB00000, source_file=0xE0000,
                 length=0x21538, window=0x100000),
    boundary_store=0x1E7222,
    windows=(
        (0x1E70C0, 0x166, 'd99aa6bb18dc2f7ee273267a8512fabe85ad55a8374e8e06fb43e87234c463bf'),))

_SLAVE = dict(
    entry=0x338B0, source=0xC1013E18, pointer=0xC1013C8C, snapshot=0xC18B164C,
    scatter=_SCATTER_SLAVE, chain_return=0x32F82, function_end=0x33B14,
    boundary_store=0x33A16,
    windows=(
        (0x338B0, 0x16A, '59bcd25179246a7ca906c7bb3b82e49f269b8fb5ed0ec91292dee290f40df54a'),))


def parameter_words(role):
    """Destination words written by the tail copy, in segment order."""
    profile = _MASTER if role == 'master' else _SLAVE
    words = {}
    for source, offset, count in SEGMENTS:
        for index in range(count):
            words[PARAM_BASE+offset+index*4] = profile['source']+source+index*4
    for source, offset, count in MIRRORS:
        for index in range(count):
            words[MIRROR_BASE+offset+index*4] = profile['source']+source+index*4
    words[TRIGGER] = 1
    return words


def parameter_profile(image, structure, role):
    require(role in ('master', 'slave'), 'Unsupported firmware role')
    profile = _MASTER if role == 'master' else _SLAVE
    for offset, length, window_sha in profile['windows']:
        require(digest(image[offset:offset + length]) == window_sha,
                'Unsupported parameter restore code window')
    table = None
    for record in structure['startup']['early_copies']:
        destination, size = record['destination'], record['size']
        if size and destination <= profile['source'] and \
                profile['source']+0x280 <= destination + size:
            table = record
        if size and destination <= profile['pointer'] and \
                profile['pointer']+4 <= destination + size:
            require(u32(image, record['source'] - BASE +
                        (profile['pointer'] - destination)) == profile['source'],
                    'Unsupported parameter source pointer')
    require(table is not None, 'Parameter source block not covered by an early copy')
    return dict(base=PARAM_BASE, entry=profile['entry'], source=profile['source'],
                pointer=profile['pointer'],
                first_store=profile['entry'] + (0x1E if role == 'master' else 0x22),
                pointers=DEREF_ADDRESSES,
                snapshot=profile['snapshot'], poll=POLL, trigger=TRIGGER,
                scatter=profile['scatter'], chain_return=profile['chain_return'],
                function_end=profile['function_end'],
                segments=SEGMENTS, mirrors=MIRRORS,
                restore_count=RESTORE_COUNT, mirror_dest=MIRROR_DEST,
                mirror_words=MIRROR_WORDS, mirror_window=MIRROR_WINDOW,
                staging=profile.get('staging'),
                final_words=FINAL_WORDS, block_words=block_words(),
                boundary_store=profile['boundary_store'],
                next_fault_address=MIRROR_DEST, words=parameter_words(role))
