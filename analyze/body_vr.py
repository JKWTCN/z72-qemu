# SPDX-License-Identifier: GPL-2.0-or-later
"""Structure analysis for the distributed body VR update member.

Firmware analysis identified the member the menu update names "BobyVR": a
paged flash image for the body vibration-reduction unit's own controller,
whose ROM window sits at 0xFFF00000 like the FR-family co-processors the
bodies have historically carried. The member is not engine firmware and
never enters the engine boot window.

Layout, recovered from the stock member:

| Region | Content |
| --- | --- |
| record 0 (0x106 bytes) | header record: tag, fields, the `NikonBVR` label |
| records 1..N | `[04 01][u32le target address][256-byte page]` |
| last 2 bytes | container member CRC (checked by the package loader) |

Pages cover consecutive 0x100-aligned addresses; the stock member walks
0xFFF00000 to 0xFFFC7F00 (an 800 KiB window with ~120 KiB of content plus a
small sector at the top of the window).
"""
import struct

from analyze.decode_z72 import crc, require

RECORD_LENGTH = 0x106
PAGE_SIZE = 0x100
RECORD_TAG = b'\x04\x01'
LABEL = b'NikonBVR'


def describe_member(member):
    """Validate one body VR member and describe its page map.

    Returns the header record fields, the covered address window and the
    pages that carry content (anything beyond erased flash fill).
    """
    require(len(member) >= RECORD_LENGTH and len(member) % RECORD_LENGTH == 2,
            'Body VR member length does not match whole records plus CRC')
    require(crc(member) == 0, 'Body VR member CRC residue is not zero')
    records = [member[i:i + RECORD_LENGTH] for i in range(0, len(member) - 2, RECORD_LENGTH)]
    header = records[0]
    require(header[:2] == RECORD_TAG and LABEL in header,
            'Body VR header record lacks its tag or label')
    pages = {}
    address = None
    for record in records[1:]:
        require(record[:2] == RECORD_TAG, 'Body VR page record lacks its tag')
        page_address = struct.unpack_from('<I', record, 2)[0]
        if address is not None:
            require(page_address == address + PAGE_SIZE,
                    'Body VR page addresses are not consecutive')
        address = page_address
        require(page_address % PAGE_SIZE == 0, 'Body VR page address is unaligned')
        pages[page_address] = record[6:]
    require(pages, 'Body VR member carries no pages')
    filled = [base for base, data in pages.items() if data.strip(b'\xff')]
    return dict(records=len(records), base=min(pages), limit=max(pages) + PAGE_SIZE,
                pages=len(pages), filled_pages=len(filled),
                header_words=struct.unpack_from('<4H', header, 2))
