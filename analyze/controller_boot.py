# SPDX-License-Identifier: GPL-2.0-or-later
"""Decode the original controller chain executed after the pin-group stage."""
from analyze.decode_z72 import BASE, digest, require
from analyze.firmware_structure import u32

CHAIN_BASE = 0x04281000
CHAIN_DELAY = (0x04266000, 8, 0x12C0)
GATE_BASE = 0x04287000

# Address/value pairs written by the shared controller sequence, in order.
CHAIN_WORDS = ((0x138, 0x00860B70), (0x13C, 0x1F1F0051), (0x140, 0xDD9B6B7F),
               (0x144, 0xBB7DB08A), (0x148, 0x30004480), (0x14C, 0x30BBBBBB))
CHAIN_SETUP = ((0x00, 0x00508880), (0x04, 0x80808888), (0x08, 0x80300000),
               (0x0C, 0x00008008), (0x10, 0xB0100010), (0x14, 0x00980009))
PIN_EXTRA = ((0x78, 0x73FFFFFF), (0x7C, 0xFFFFFFFF), (0x80, 0x01FFC1FF),
             (0x84, 0x31FFFFFF), (0x88, 0x000004EE))

# Verified stock code windows are pinned by file offset, length and SHA-256.
# The original instruction bytes are not redistributed with this project;
# each digest was computed from the verified C 1.70 stock image.
_MASTER = dict(
    entry=0x1E0DAC, call_site=0x1E003A, call_return=0x1E003E, gate_entry=0x1E0E56,
    pool=dict(base=0x1E0E6C, mask=0x1E0E88, counter=0x1E0E8C, setup0=0x1E0E90,
              setup1=0x1E0E94, setup2=0x1E0E98, pin10=0x1E0E9C, pin14=0x1E0EA0,
              pin80=0x1E0EA4, gate=0x1E0EA8),
    windows=(
        (0x1E0DAC, 0xC0, '1ed21af6d631ef9c98ef309751ba3d7d2f0c8c8fb8fef7017840ea86f4b02cef'),
        (0x1E003A, 4, '150a12c7919681cdbf7327c9766c84744720171c76fee1b69151777c0296dc30')))

_SLAVE = dict(
    entry=0x337A4, call_site=0x32F7A, call_return=0x32F7E, gate_entry=0x3385A,
    pool=dict(base=0x33870, mask=0x3388C, counter=0x33890, setup0=0x33894,
              setup1=0x33898, setup2=0x3389C, pin10=0x338A0, pin14=0x338A4,
              pin80=0x338A8, gate=0x338AC),
    windows=(
        (0x337A4, 0xCC, 'bfc9e059c52bb190488ebb9fff2a2ae04248e8bee542b27e79ffe65f95517bee'),
        (0x32F7A, 4, 'f019bc6dcd40e0db2309fdbc0254b2735689184f834b171fd7b1e4def54f4d5e')))


def controller_words(role):
    """Expected storage after the original controller sequence completes."""
    words = {CHAIN_BASE+offset: value for offset, value in CHAIN_WORDS}
    words.update({CHAIN_BASE+offset: value for offset, value in CHAIN_SETUP})
    words[CHAIN_BASE+0x24] = 1
    words[CHAIN_BASE+0x28] = 0
    words.update({0x04280000+offset: value for offset, value in PIN_EXTRA})
    words[GATE_BASE+0x00] = 0x3000 if role == 'master' else 0x4000
    words[GATE_BASE+0x04] = 1
    words[GATE_BASE+0x10] = 0xA1
    return words


def controller_profile(image, role):
    require(role in ('master', 'slave'), 'Unsupported firmware role')
    profile = _MASTER if role == 'master' else _SLAVE
    for offset, length, window_sha in profile['windows']:
        require(digest(image[offset:offset + length]) == window_sha,
                'Unsupported controller chain code window')
    pool = profile['pool']
    require(u32(image, pool['base']) == CHAIN_BASE and
            u32(image, pool['mask']) == 0xFFFCFFFD and
            u32(image, pool['counter']) == CHAIN_DELAY[0] and
            (u32(image, pool['setup0']), u32(image, pool['setup1']),
             u32(image, pool['setup2'])) == tuple(v for _, v in CHAIN_SETUP[:3]) and
            (u32(image, pool['pin10']), u32(image, pool['pin14'])) ==
            (CHAIN_SETUP[4][1], CHAIN_SETUP[5][1]) and
            u32(image, pool['pin80']) == 0x01FFC1FF and
            u32(image, pool['gate']) == GATE_BASE,
            'Unsupported controller chain literals')
    return dict(base=CHAIN_BASE, entry=profile['entry'],
                call_site=profile['call_site'], call_return=profile['call_return'],
                gate_entry=profile['gate_entry'], delay=CHAIN_DELAY,
                gate_calls=(0, 1, 3) if role == 'master' else (0, 1, 2, 3, 4),
                next_fault_address=0x20010044,
                next_store=0x1E7318 if role == 'master' else 0x33B20,
                first_store=profile['entry']+0x12,
                words=controller_words(role))
