# SPDX-License-Identifier: GPL-2.0-or-later
"""Decode the secondary reset path and original peer-ready publication."""
from analyze.decode_z72 import require
from analyze.firmware_structure import branch_target, literal, u32
from analyze.runtime_bootstrap import runtime_profile
from analyze.runtime_counter import counter_profile
from analyze.runtime_services import branch


def bne_target(image, offset):
    instruction = u32(image, offset)
    require(instruction >> 24 == 0x1A, 'Expected original ARM BNE')
    displacement = instruction & 0xFFFFFF
    if displacement & 0x800000:
        displacement -= 0x1000000
    return offset + 8 + displacement * 4


def smp_profile(image, structure):
    kernel = counter_profile(image, structure['role'])
    runtime = runtime_profile(image, structure['role'])
    secondary = bne_target(image, structure['startup']['entry_offset'] + 0x110)
    require(u32(image, secondary+8) == 0xE320F002 and
            bne_target(image, secondary+24) == secondary+8 and
            branch_target(image, secondary+40) == 0xAC,
            'Unsupported original secondary reset loop')
    release_word, release_value = literal(image, secondary, 0), literal(image, secondary+4, 2)
    require(release_word == 0x04008FFC and release_value == 0xBABEBABE,
            'Unexpected secondary release contract')
    ready = kernel['barrier_entry'] + 0x54
    atomic = branch(image, ready+0x14)
    require(literal(image, ready+0x10, 0) == kernel['peer_count_word'] and
            u32(image, ready+8) == 0xE320F002 and
            [u32(image, atomic+n) for n in (8, 12, 16)] ==
            [0xE1901F9F, 0xE2811001, 0xE1802F91],
            'Unsupported original atomic peer-ready publication')
    # The next original startup-task boundary is a byte store in the shared
    # low-level device initializer. Do not map its page merely to avoid a fault.
    peripheral = literal(image, 0x294, 0)
    require(peripheral == 0x2C090000 and u32(image, 0x19C) == 0xE5C34001,
            'Unexpected startup device boundary')
    return dict(**kernel, secondary_entry=secondary, secondary_wait=secondary+8,
        release_word=release_word, release_value=release_value,
        secondary_ready_entry=ready, ready_store=atomic+16,
        secondary_stack=structure['startup']['core_zero_stack_tops'][-1]-0x4000,
        copied_table=runtime['copied_table'],
        peripheral_base=peripheral, peripheral_fault_offset=0x19C,
        peripheral_fault_address=peripheral+1)
