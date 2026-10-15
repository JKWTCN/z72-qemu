# SPDX-License-Identifier: GPL-2.0-or-later
"""Identity checks for locally supplied Nikon Z7 II C 1.70 firmware images."""
import binascii
import hashlib
import struct

# Update-package decoding, extraction and repacking tools are intentionally
# not part of this repository; only local-image identity checks live here.
BASE = 0x10020000
MASTER_SHA = '478caf02dba41fa9144c0c4b6e1a051dc556d40e51a79a308bdd1169efb9dbbe'
MASTER_SIZE = 38239098
SCATTER = (0x12399F94, 0xB1800000, 0xAEDB8, 0x1002006C)
SNAPSHOT = 0xB202BE70
FIELD = 0x19E
MASK_OFFSET = 0x2399844
TABLE = 0x1094AA24
# Hook only at aligned instruction boundaries; retain gate's original LDR.
# Stock windows are pinned by offset, length and SHA-256; the original
# instruction bytes are not redistributed with this project.
HOOKS = (
    (0x600348, 12, '8a89bdd00a79dc54cd1597646b1be3a70025a129eb58c2ccd0d202f20f0c956c', True, 0x600354, 0x60037A),
    # The digest covers the full ten-byte gate window (five Thumb halfwords).
    (0x539EE0, 10, 'a5d1202bc808047f5b08eaa158be1419fa7e5c661a13177f6868d602c79be6c8', False, 0x539EEA, 0x539EF2),
)

def digest(data):
    return hashlib.sha256(data).hexdigest()

def require(condition, message):
    if not condition:
        raise ValueError(message)

def crc(data):
    return binascii.crc_hqx(data, 0)

def validate_master(master):
    require(len(master) == MASTER_SIZE and digest(master) == MASTER_SHA and crc(master) == 0,
            'Requires stock Z7 II C 1.70 master EG')
    require(struct.unpack_from('<4I', master, 0x14000) == SCATTER, 'Scatter mapping mismatch')
    require(struct.unpack_from('<I', master, 0x600390)[0] == SNAPSHOT, 'Gate state binding mismatch')
    require(struct.unpack_from('<I', master, 0x53A1F8)[0] == SNAPSHOT, 'Widget state binding mismatch')
    require(struct.unpack_from('<I', master, 0x53A200)[0] == TABLE, 'Widget table binding mismatch')
    require(struct.unpack_from('<I', master, 0x92AAA4)[0] == 0xB181F8AC, 'Histogram descriptor mismatch')
    require(master[MASK_OFFSET:MASK_OFFSET + 36] == struct.pack('<9I', *([0x444] * 9)), 'Visibility masks mismatch')
    for site, length, window_sha, *_ in HOOKS:
        require(digest(master[site:site + length]) == window_sha, 'Hook window mismatch')
