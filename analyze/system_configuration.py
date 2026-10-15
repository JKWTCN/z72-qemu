# SPDX-License-Identifier: GPL-2.0-or-later
"""Observed first system-configuration write sequence for stock C1.70."""

# Master and the slave bit-2-set path use this sequence. The bit-2-clear
# slave path changes two values, while preserving the address/store order.
SYSTEM_WRITES = (
    (0x20023000, 0x00000001),
    (0x20022000, 0x00000001),
    (0x20030010, 0x00000005),
    (0x20030014, 0x00000008),
    (0x20030018, 0x00000009),
    (0x2003001C, 0x00000007),
    (0x20030020, 0x00000003),
    (0x20030824, 0x00000001),
    (0x20030828, 0x00000043),
    (0x2003082C, 0x0000001A),
    (0x20030024, 0x19061200),
    (0x20030040, 0x00000030),
    (0x20030048, 0x00330026),
    (0x20030030, 0x00066606),
    (0x20030044, 0x00004664),
    (0x20030034, 0x00003713),
    (0x20030050, 0x00000026),
    (0x20030840, 0x0000004B),
    (0x20030054, 0x0009D084),
    (0x20030058, 0x000A0086),
    (0x2003005C, 0x0009E086),
    (0x20030060, 0x0009F085),
    (0x20030074, 0x00016030),
    (0x20030078, 0x00014030),
    (0x2003007C, 0x00014030),
    (0x20030080, 0x00016030),
    (0x20030094, 0x00000800),
    (0x20030098, 0x00000800),
    (0x2003009C, 0x00000800),
    (0x200300A0, 0x00000800),
    (0x200300B8, 0x00000003),
    (0x20030910, 0x00000000),
    (0x20030820, 0x00000000),
    (0x20030850, 0x00010050),
    (0x200300E4, 0x00089019),
    (0x200300E8, 0x00089019),
    (0x200300EC, 0x0008C01C),
    (0x200300F0, 0x00088018),
    (0x20030128, 0x00010016),
    (0x2003012C, 0x00010014),
    (0x20030130, 0x00010014),
    (0x20030134, 0x00010016),
    (0x20030148, 0x00010020),
    (0x2003014C, 0x00010020),
    (0x20030150, 0x00010020),
    (0x20030154, 0x00010020),
    (0x20020000, 0x00000000),
    (0x20020100, 0x00000000),
    (0x2002010C, 0x00000303),
    (0x20021004, 0x00000001),
    (0x20021008, 0x00000001),
    (0x2002100C, 0x00000001),
    (0x20021010, 0x00000001),
    (0x20021014, 0x00000000),
    (0x20022000, 0x00000000),
    (0x20022408, 0x00001F8D),
    (0x20022414, 0x0000553B),
    (0x20022100, 0x00000001),
)

SLAVE_BRANCH_WORDS = (0x0428242C, 0x0428202C)
POLL_ARGUMENTS = (0x20022300, 1, 0x02625A00)


def system_path(role, shared=False):
    if role == 'master':
        return 0x4C6C, 0x4E40, 0x8D4
    if role == 'slave':
        return (0x4CB8, 0x4E8C, 0x920) if shared else (0x361C, 0x37F0, 0x920)
    raise ValueError('Unsupported firmware role')


def expected_system_writes(role, shared=False):
    system_path(role, shared)
    if role == 'slave' and not shared:
        changes = {0x200300B8: 1, 0x2002010C: 0x101}
        return tuple((a, changes.get(a, v)) for a, v in SYSTEM_WRITES)
    return SYSTEM_WRITES


# Following stores include bit-0 acknowledgements and five command phases.
COMPLETION_WRITES = (
    (0x20022300, 0x00000001),
    (0x20023000, 0x00000000),
    (0x20023404, 0x00000043),
    (0x20023408, 0x0000001A),
    (0x2002340C, 0x00000002),
    (0x20023500, 0x02030101),
    (0x20023504, 0x02030101),
    (0x20023508, 0x30000000),
    (0x2002350C, 0x30000000),
    (0x20023510, 0x00000000),
    (0x20023514, 0x30000000),
    (0x20023600, 0x00000F9F),
    (0x20023604, 0x00013881),
    (0x2002360C, 0x0000018F),
    (0x20023610, 0x00040404),
    (0x20023614, 0x13031007),
    (0x20023618, 0x00000807),
    (0x2002361C, 0x020B0B07),
    (0x20023620, 0x030A0409),
    (0x20023624, 0x00000053),
    (0x20023628, 0x008F0023),
    (0x2002362C, 0x03000202),
    (0x20023630, 0x00050059),
    (0x20023634, 0x000A0A01),
    (0x20023700, 0x0000000D),
    (0x20023708, 0x00090003),
    (0x2002370C, 0x00000001),
    (0x20023800, 0x00000618),
    (0x20023804, 0x00000001),
    (0x20023808, 0x00000000),
    (0x20023900, 0x09896800),
    (0x20023904, 0x00000000),
    (0x20023A00, 0x030D4000),
    (0x20023A04, 0x00000000),
    (0x20023B00, 0x00000007),
    (0x20023B04, 0x00000000),
    (0x20023100, 0x00010001),
    (0x20023300, 0x00000001),
    (0x20023118, 0x00000001),
    (0x20023318, 0x00000001),
    (0x20023118, 0x00010001),
    (0x20023318, 0x00000001),
    (0x20023118, 0x00020001),
    (0x20023318, 0x00000001),
    (0x20023118, 0x00030001),
    (0x20023318, 0x00000001),
    (0x20023118, 0x00040001),
    (0x20023318, 0x00000001),
)

COMPLETION_STATUS = (0x20022300, 0x20023300, 0x20023318)
COMMAND_RESULT = 0x2003016C
CONFIGURATION_WORDS = tuple(sorted(set(dict(SYSTEM_WRITES)) |
    set(dict(COMPLETION_WRITES)) | set(COMPLETION_STATUS) | {COMMAND_RESULT}))


def expected_completion_writes(role, shared=False):
    changes = {0x20023504: 0x02030100, 0x20023508: 0x40000000,
               0x2002350C: 0x40000000, 0x20023514: 0x40000000}
    tail = COMPLETION_WRITES
    if role == 'slave' and not shared:
        tail = tuple((a, changes.get(a, v)) for a, v in tail)
    return expected_system_writes(role, shared) + tail


def completion_path(role, shared=False):
    system_path(role, shared)
    if role == 'master':
        return 0x3A8, 0x5BD0, 0x5354
    return (0x3C8, 0x5C1C, 0x53A0) if shared else (0x3EC, 0x4588, 0x3D10)
