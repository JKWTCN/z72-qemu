# SPDX-License-Identifier: GPL-2.0-or-later
"""C1.70 configuration stores between platform return and early copies."""

CONTINUATION_WORDS = (0x04281020, 0x20016000,
    *range(0x20016020, 0x20016040, 4), 0x20016D40,
    *range(0x20016D50, 0x20016D60, 4),
    0x20070000, 0x20070004, 0x20070010, 0x20070014, 0x20070018,
    0x20070020, 0x20070024, 0x20070028, 0x20070030)
PRESERVED_WORDS = (0x20070014, 0x20070020, 0x20070024)


def continuation_profile(role):
    if role == 'master':
        return dict(entry=0xBDC4, clock_entry=0xC300, clock_return=0xBE54,
                    optional_pointer=0x12399F80, stack_restore=0xBE64,
                    transfer_entry=0xC234, transfer_return=0xBE74,
                    transfer_destination=0xB18AEDC0, transfer_size=0x12AF750,
                    wait_entry=0xC2A0, wait_call=0xBF88)
    if role == 'slave':
        return dict(entry=0xBE10, clock_entry=0xC340, clock_return=0xBEA0,
                    optional_pointer=0x1085C4C0, stack_restore=0xBEB0,
                    transfer_entry=0xC280, transfer_return=0xBEC0,
                    transfer_destination=0xC1017D80, transfer_size=0x8B71D4,
                    wait_entry=0xC2EC, wait_call=0xBFD4)
    raise ValueError('Unsupported firmware role')


def continuation_writes(role, seeds=None):
    profile = continuation_profile(role)
    seeds = seeds or {}
    values = ((0x60000000, 0x50000000, 0x50000000, 0xB0000000,
               0x50000000, 0, 0x30000, 0x40000000) if role == 'master' else
              (0x40000000, 0x80000000, 0x40000000, 0xC0000000,
               0x80000000, 0, 0x30000, 0x80000000))
    return tuple(zip(range(0x20016020, 0x20016040, 4), values)) + tuple(
        zip(range(0x20016D50, 0x20016D60, 4), values[:4])) + (
        (0x20016000, 1), (0x20016D40, 1), (0x04281020, 0x90000),
        (0x20070000, 0), (0x20070014, seeds.get(0x20070014, 0) | 1),
        (0x20070020, (seeds.get(0x20070020, 0) & 0xFFFF0000) | 0x4000),
        (0x20070024, (seeds.get(0x20070024, 0) & 0xFFFF0000) | 0x4000),
        (0x20070028, (profile['transfer_size'] + 0x3FFF) >> 14),
        (0x20070018, 0), (0x20070004, 0),
        (0x20070030, profile['transfer_destination']), (0x20070010, 1))
