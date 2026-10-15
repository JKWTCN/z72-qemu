# SPDX-License-Identifier: GPL-2.0-or-later
"""Decode the original pin-group configuration and its next controller boundary."""
from analyze.decode_z72 import BASE, digest, require
from analyze.firmware_structure import u32

PIN_BASE = 0x04282000
PIN_BANK_STRIDE = 0x100
PIN_GROUP_COUNT = 12
PIN_FIRST_WORD_MASK = 0xFFFF0000
NEXT_BASE = 0x04281000

# Verified stock code windows are pinned by file offset, length and SHA-256.
# The original instruction bytes are not redistributed with this project.
_MASTER = dict(
    entry=0x1E0EE4, call_site=0x1E0036, call_return=0x1E003A, return_offset=0x1E0F66,
    value=0x410, table_source=0xB18AA51C, pool=dict(r3=0x1E0F68, mask=0x1E0F6C, r4=0x1E0F70),
    windows=(
        (0x1E0EE4, 0x84, '350e6c307b0d9b3e12cb03e46d09949c401a8510c613c9656218fbfb637b9ee8'),
        (0x1E0036, 4, '2a2f64e2c9b38d574b83f10ebfad93b5010cf00d34a24026d990c8ed4592fcc7')),
    rmw=((0x34, 0x30000000, 0x10000000), (0x34, 0xC0000000, 0x40000000),
         (0x38, 0x00030000, 0x00020000), (0x38, 0x00300000, 0x00200000),
         (0x38, 0x00C00000, 0x00400000)))

_SLAVE = dict(
    entry=0x33BC4, call_site=0x32F76, call_return=0x32F7A, return_offset=0x33C0A,
    value=0xCB7, table_source=0xC1014B5C, pool=dict(r3=0x33C0C, mask=0x33C10, r4=0x33C14),
    windows=(
        (0x33BC4, 0x50, '9bd0bf8dbdc727136538038c0031166d4d48a802054f41556946ef29807f14d7'),
        (0x32F76, 4, 'a2adbe30f9be150cd857c7412f00d6089d27de011a47d3fc196625f8bab90c96')),
    rmw=())


def library_table(image, structure, role):
    """Recover the twelve five-word groups from their early-copy destination."""
    profile = library_profile(image, role)
    for record in structure['startup']['early_copies']:
        destination, size = record['destination'], record['size']
        if size and destination <= profile['table_source'] and \
                profile['table_source'] + PIN_GROUP_COUNT * 20 <= destination + size:
            source = record['source'] - BASE + (profile['table_source'] - destination)
            return dict(source=source, words=tuple(u32(image, source + index * 4)
                for index in range(PIN_GROUP_COUNT * 5)))
    raise ValueError('Pin table source not covered by an original early copy')


def pin_words(words):
    """Spread the recovered groups over the five configuration banks."""
    expected = {}
    for bank in range(5):
        for group in range(PIN_GROUP_COUNT):
            value = words[group * 5 + bank]
            if bank == 0:
                value |= PIN_FIRST_WORD_MASK
            expected[PIN_BASE + bank * PIN_BANK_STRIDE + group * 4] = value
    return expected


def library_profile(image, role):
    require(role in ('master', 'slave'), 'Unsupported firmware role')
    profile = _MASTER if role == 'master' else _SLAVE
    for offset, length, window_sha in profile['windows']:
        require(digest(image[offset:offset + length]) == window_sha,
                'Unsupported pin configuration code window')
    pool = profile['pool']
    require(u32(image, pool['r3']) == profile['table_source'] and
            u32(image, pool['mask']) == PIN_FIRST_WORD_MASK and
            u32(image, pool['r4']) == PIN_BASE,
            'Unsupported pin configuration table literals')
    result = ((0x50000000, 0x620000) if role == 'master' else (0, 0))
    return dict(base=0x04280000, value=profile['value'], entry=profile['entry'],
                table_source=profile['table_source'],
                config_store=profile['entry'] + (0xC if role == 'master' else 0x10),
                call_site=profile['call_site'], call_return=profile['call_return'],
                return_offset=profile['return_offset'], rmw=profile['rmw'],
                final_control=result[0], final_mux=result[1],
                next_entry=0x1E0DAC if role == 'master' else 0x337A4,
                next_store=0x1E0DBE if role == 'master' else 0x337B6)
