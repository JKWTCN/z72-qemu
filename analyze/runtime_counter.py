# SPDX-License-Identifier: GPL-2.0-or-later
"""Decode the counter callbacks and common kernel initialization calls."""
from analyze.decode_z72 import BASE, require
from analyze.firmware_structure import branch_target, literal, u32
from analyze.runtime_bootstrap import runtime_profile
from analyze.runtime_services import branch


def counter_profile(image, role):
    runtime = runtime_profile(image, role)
    frequency = literal(image, 0xD4, 2)
    require(frequency == literal(image, 0x14C, 1) == 48000000,
            'Unsupported original timer frequency')
    common = branch_target(image, runtime['rtos_entry']+0x4C)
    calls = [common+offset for offset in (0x18, 0x48, 0x74, 0xA0, 0xCC,
        0xF8, 0x124, 0x150, 0x17C, 0x1A8, 0x1D4, 0x200, 0x22C,
        0x258, 0x284, 0x2B0, 0x2D4, 0x3DC)]
    barrier = branch(image, common+0x450)
    descriptor = literal(image, runtime['rtos_entry']+0x48, 0)
    descriptor_words = [u32(image, descriptor-BASE+n) for n in range(0, 48, 4)]
    require(descriptor_words[1] == 0x41 and descriptor_words[3:5] == [1, 0x2000],
            'Unexpected original startup task attributes')
    return dict(frequency=frequency, common_entry=common, calls=calls,
        entries=[branch(image, call) for call in calls],
        task_descriptor=descriptor, task_entry=descriptor_words[2],
        task_priority=descriptor_words[3], task_stack_bytes=descriptor_words[4],
        task_create_call=common+0x408, task_start_call=common+0x418,
        core_setup_call=common+0x430, barrier_entry=barrier, barrier_wait=barrier+0x28,
        peer_count_word=literal(image, barrier+0x20, 1))
