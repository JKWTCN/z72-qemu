# SPDX-License-Identifier: GPL-2.0-or-later
"""Decode the stock bootstrap ranges and initial RTOS configuration objects."""
from analyze.decode_z72 import BASE, require
from analyze.firmware_structure import literal, thumb_literal, u32

PRIVATE_BASE = 0x04000000  # Laboratory CBAR; hardware base is unconfirmed.


def runtime_profile(image, role):
    if role == 'master':
        app, bounds, library, rng, control = 0x416C60, 0xD780, 0x1E0000, 0x3647B4, 0x3C49B0
        defaults, cache, copy, switch, rtos, states, stop = (
            (0x2BB87C, 0x3D7F78), 0xC0CC, 0x340F44, 0xD6C0,
            0xE3C18, 0xE6D18, 0xE8F9C)
    elif role == 'slave':
        app, bounds, library, rng, control = 0x1474A8, 0xD7C0, 0x32F40, 0x1452F0, 0x51D74
        defaults, cache, copy, switch, rtos, states, stop = (
            (0x51F3C, 0x51F68), 0xC118, 0x1475B8, 0xD700,
            0x156C8, 0x186EC, 0x1A970)
    else:
        raise ValueError('Unsupported firmware role')
    # Standard ARM-to-Thumb interworking veneer at the application entry:
    # ADD r12, pc, #1 followed by BX r12. Single-instruction encodings,
    # pinned by semantics rather than redistributed as a byte sequence.
    require(u32(image, app) == 0xE28FC001 and u32(image, app + 4) == 0xE12FFF1C,
            'Expected original ARM-to-Thumb bootstrap veneer')
    table = literal(image, 0x278, 0)
    require(table == literal(image, 0x28C, 0), 'Copied and installed table addresses differ')
    config = literal(image, rtos + 0x50, 0)
    fields = [0] * 12
    for instruction, index in ((0x2F4, 0), (0x304, 1), (0x2FC, 3),
                               (0x314, 4), (0x31C, 5), (0x354, 10), (0x35C, 11)):
        fields[index] = literal(image, instruction, 1)
    fields[6:10] = [PRIVATE_BASE + 0x2000, PRIVATE_BASE + 0x1000, 29, 256]
    return dict(app_entry=app, bounds_entry=bounds, library_entry=library,
        bounds=[literal(image, bounds, 0), literal(image, bounds+4, 2)],
        rng_entry=rng, rng_base=thumb_literal(image, rng, 1)-0x7C,
        rng_increment=u32(image, rng+0x34), rng_multiplier=u32(image, rng+0x38),
        control=thumb_literal(image, control, 0),
        defaults=[(BASE + entry + 0x22 + thumb_literal(image, entry+0x1C, 0)) & 0xFFFFFFFF
                  for entry in defaults],
        cache_entry=cache, copy_entry=copy, switch_entry=switch, copied_table=table,
        rtos_entry=rtos, config=config, config_words=fields,
        ready=literal(image, rtos+0x28, 4),
        cache_count_words=[literal(image, rtos+0xA8, 1), literal(image, rtos+0xB4, 1)],
        states_entry=states, state=literal(image, states, 0),
        state_ref=literal(image, states+0x28, 1), state_array=literal(image, states+0x14, 0),
        stop=stop)


def seeded_words(profile):
    value = 1
    result = {}
    for index in range(54, -1, -1):
        result[profile['rng_base'] + index*4] = (value + (value >> 16)) & 0xFFFFFFFF
        value = (value * profile['rng_multiplier'] + profile['rng_increment']) & 0xFFFFFFFF
    return result
