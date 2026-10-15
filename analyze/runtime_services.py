# SPDX-License-Identifier: GPL-2.0-or-later
"""Decode the first core-zero services and their original heap metadata."""
from analyze.decode_z72 import require
from analyze.firmware_structure import literal, u32
from analyze.runtime_bootstrap import runtime_profile


def branch(image, offset):
    instruction = u32(image, offset)
    require(instruction >> 24 == 0xEB, 'Expected original ARM service call')
    displacement = instruction & 0xFFFFFF
    if displacement & 0x800000:
        displacement -= 0x1000000
    return offset + 8 + displacement * 4


def service_profile(image, role):
    runtime = runtime_profile(image, role)
    entry = runtime['stop']
    calls = [entry + offset for offset in (0x50, 0x64, 0x78, 0x8C, 0xA0)]
    stages = [branch(image, call) for call in calls]
    pool, heap = stages[-2:]
    list_init = branch(image, heap + 0x30)
    start, end = runtime['config_words'][10:12]
    require(start < end and start % 8 == 0, 'Unsupported runtime heap bounds')
    pool_end = (start + ((end - start - 8) // 0x808) * 8 + 0x807) & ~0x7FF
    count = (end - pool_end) >> 11
    require(count > 2, 'Unsupported runtime pool size')
    sections = range(start >> 20, (end+0xFFFFF) >> 20)
    require(all(u32(image, 0x10000+section*4) & 0xFFF00003 ==
                (section << 20) | 2 for section in sections),
            'Runtime heap lacks original identity section descriptors')
    return dict(entry=entry, calls=calls, stages=stages,
        return_offset=runtime['rtos_entry']+0x44,
        pool_config=literal(image, pool+0x14, 4),
        pool_state=literal(image, pool+0x48, 2),
        heap_control=literal(image, heap+0x20, 1),
        lists=literal(image, list_init+4, 2),
        heap_start=start, heap_end=end, pool_end=pool_end, pool_count=count,
        native_heap_sections=len(sections),
        target_word=literal(image, stages[0]-0x15C, 1),
        counter_init=0x12C)
