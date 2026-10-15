# SPDX-License-Identifier: GPL-2.0-or-later
"""Decode the original mixed-width console setup and its next library boundary."""
import struct

from analyze.decode_z72 import require
from analyze.firmware_structure import literal, u32


def console_profile(image, role):
    require(role in ('master', 'slave'), 'Unsupported console firmware role')
    require(literal(image, 0x294, 0) == 0x2C090000 and
            u32(image, 0x1FC) == 0xE5D12003 and u32(image, 0x200) == 0xE3120002,
            'Unsupported original console base or TX-ready poll')
    stores = []
    for offset, register, size, value, instruction in (
        (0x19C, 1, 1, 0, 0xE5C34001), (0x1A4, 1, 1, 0x80, 0xE5C3C001),
        (0x1AC, 0, 1, 1, 0xE7C05201), (0x1B0, 2, 1, 0, 0xE5C34002),
        (0x1B4, 3, 1, 0x80, 0xE5C3C003), (0x1B8, 12, 2, 0, 0xE1C340BC),
        (0x1C0, 6, 2, 0x363, 0xE1C300B6), (0x1C8, 12, 2, 12, 0xE1C300BC),
        (0x1D4, 12, 2, 0x405, 0x11C300BC), (0x1E0, 1, 1, 0x81, 0xE5C30001)):
        require(u32(image, offset) == instruction, 'Unsupported console configuration store')
        stores.append(dict(offset=offset, register=register, size=size, value=value))
    fault, value = (0x1E0EF0, 0x410) if role == 'master' else (0x33BD4, 0xCB7)
    # Single Thumb store instruction (STR r1, [r2, #0x30]) pinning the
    # first pin-bank store of the next stage; no byte sequence is copied.
    require(struct.unpack_from('<H', image, fault)[0] == 0x6311,
            'Unexpected next library store')
    return dict(base=0x2C090000, initializer=0x180, initializer_return=0x1E8,
        caller_return=0x2A8, transmitter=0x1EC, tx_poll=0x1FC, tx_ready_mask=2,
        stores=stores, final_bytes=[1, 0x81, 0, 0x82], divisor=0x363, format=0x405,
        next_fault_offset=fault, next_fault_address=0x04280030, next_fault_value=value)
