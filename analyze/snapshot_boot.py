# SPDX-License-Identifier: GPL-2.0-or-later
"""Decode the original configuration snapshot that follows the controller chain."""
from analyze.decode_z72 import BASE, digest, require
from analyze.firmware_structure import u32

SNAPSHOT_GATE = 0x20010044
SNAPSHOT_SOURCE = 0x20014800
SNAPSHOT_WORDS = 512
SNAPSHOT_TAIL = {'master': 0x1E70C0, 'slave': 0x338B0}

# Register words the original sequence reads through the recovered pointer list.
DEREF_ADDRESSES = (0x20010038, 0x2001003C, 0x20010100, 0x20010104,
                   0x20010108, 0x2001010C, 0x20010110, 0x20010114,
                   0x20010118, 0x2001011C, 0x20015004, 0x20015020,
                   0x20015024, 0x20015028, 0x2001502C, 0x20015030,
                   0x20015034, 0x20015038, 0x2001503C)

# Verified stock code windows are pinned by file offset, length and SHA-256.
# The original instruction bytes are not redistributed with this project.
_MASTER = dict(
    entry=0x1E7310, call_site=0x1E003E, call_return=0x1E0042, load=0x1E733A,
    table_source=0xB18A9660, destination=0xB2B40C10,
    tail=dict(entry=0x1E70C0, pointer=0xB18A96AC, source=0xB18A97F0,
              dest=0x20013000, store=0x1E70DE, fault=0x20013000),
    pool=dict(base=0x1E735C, table=0x1E7350, dest=0x1E7360, source=0x1E7380),
    windows=(
        (0x1E7310, 0x40, 'b86891c9c617b3e9e58a008eb0a0a4cb1f3e86971dc34a2ce0732ab133ba6d92'),
        (0x1E003E, 4, '18b2548f325fe67d62d278d09240c3427e5fd475384acb3b32d711f238fc62c1')))

_SLAVE = dict(
    entry=0x33B18, call_site=0x32F7E, call_return=0x32F82, load=0x33B42,
    table_source=0xC1013C40, destination=0xC18B164C,
    tail=dict(entry=0x338B0, pointer=0xC1013C8C, source=0xC1013E18,
              dest=0x20013000, store=0x338D2, fault=0x20013000),
    pool=dict(base=0x33B64, table=0x33B58, dest=0x33B68, source=0x33B88),
    windows=(
        (0x33B18, 0x40, 'd4c53dd602c9be644985d4cd7d8077c3c6145b74f08e1198bad154cf11bec387'),
        (0x32F7E, 4, 'df3f3ee10dd1bbf6cc9a3addf8db5b7f2fa40258f8733f3fddebc36c45df658a')))


def snapshot_table(image, structure, role):
    """Recover the nineteen pointers from their early-copy destination."""
    profile = _MASTER if role == 'master' else _SLAVE
    for record in structure['startup']['early_copies']:
        destination, size = record['destination'], record['size']
        if size and destination <= profile['table_source'] and \
                profile['table_source'] + 0x4C <= destination + size:
            source = record['source'] - BASE + (profile['table_source'] - destination)
            return dict(source=source, pointers=tuple(u32(image, source + index * 4)
                for index in range(len(DEREF_ADDRESSES))))
    raise ValueError('Snapshot pointer table not covered by an original early copy')


def snapshot_profile(image, structure, role):
    require(role in ('master', 'slave'), 'Unsupported firmware role')
    profile = _MASTER if role == 'master' else _SLAVE
    for offset, length, window_sha in profile['windows']:
        require(digest(image[offset:offset + length]) == window_sha,
                'Unsupported configuration snapshot code window')
    pool = profile['pool']
    require(u32(image, pool['base']) == 0x20010000 and
            u32(image, pool['table']) - 0x4C == profile['table_source'] and
            u32(image, pool['dest']) == profile['destination'] and
            u32(image, pool['source']) == SNAPSHOT_SOURCE,
            'Unsupported configuration snapshot literals')
    table = snapshot_table(image, structure, role)
    require(table['pointers'] == DEREF_ADDRESSES,
            'Recovered snapshot pointers mismatch the original list')
    return dict(gate=SNAPSHOT_GATE, entry=profile['entry'],
                gate_store=profile['entry']+8,
                table_source=profile['table_source'],
                destination=profile['destination'],
                call_site=profile['call_site'], call_return=profile['call_return'],
                deref=DEREF_ADDRESSES, pointers=table['pointers'],
                source=SNAPSHOT_SOURCE, words=SNAPSHOT_WORDS,
                tail=profile['tail'], load=profile['load'],
                tail_source_pointer=profile['tail']['pointer'],
                next_fault_address=profile['tail']['fault'],
                next_fault_store=profile['tail']['store'])
