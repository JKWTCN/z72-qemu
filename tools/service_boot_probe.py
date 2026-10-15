# SPDX-License-Identifier: GPL-2.0-or-later
"""Follow stock reset through GIC and runtime heap initialization."""
import argparse
import json
from pathlib import Path
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import BASE, require
from analyze.firmware_structure import analyze_eg
from analyze.runtime_bootstrap import runtime_profile
from analyze.runtime_services import service_profile
from tools.boot_probe import reset_machine
from tools.early_boot_probe import word
from tools.runtime_boot_probe import trace_runtime


def reach(remote, offset, vectors):
    addresses = [BASE + offset, *[vectors + n for n in (4, 12, 16)]]
    for address in addresses:
        remote.breakpoint(address)
    try:
        require(remote.command('c').startswith('T05'), 'Service execution did not stop')
        regs = remote.regs()
        require(remote.get(regs, 'pc') == BASE + offset and
                remote.get(regs, 'cpsr') & 0x3F == 0x13,
                f'Service did not reach {offset:#x} in ARM SVC mode')
        return regs
    finally:
        for address in addresses:
            remote.breakpoint(address, False)


def trace_services(remote, image, structure, scenario, stop_before_counter=True):
    role = structure['role']
    profile = service_profile(image, role)
    runtime = runtime_profile(image, role)
    vectors = structure['startup']['vector_address']
    prefix = trace_runtime(remote, structure, image,
                           'shared-path' if scenario == 'shared-path' else 'stock')
    stack = remote.get(remote.regs(), 'sp')
    returns = []
    negative = scenario == 'invalid-heap-section'
    descriptor = runtime['copied_table'] + (profile['heap_start'] >> 20) * 4
    for index, (call, stage) in enumerate(zip(profile['calls'], profile['stages'])):
        regs = reach(remote, stage, vectors)
        require(remote.get(regs, 'lr') == BASE + call + 4, 'Unexpected service caller')
        if index == 3:
            require(word(remote, profile['pool_config']) == profile['heap_start'] and
                    word(remote, profile['pool_config']+4) == profile['heap_end'],
                    'Original allocator bounds mismatch')
            if negative:
                saved = remote.read(descriptor, 4)
                remote.write(descriptor, bytes(4))
                remote.breakpoint(vectors + 16)
                try:
                    require(remote.command('c').startswith('T05'), 'Missing heap fault stop')
                    regs = remote.regs()
                    require(remote.get(regs, 'pc') == vectors + 16 and
                            remote.get(regs, 'cpsr') & 0x1F == 0x17 and
                            remote.get(regs, 'r0') == profile['heap_start'] and
                            remote.get(regs, 'lr') == BASE + stage + 0x9C,
                            'Invalid heap section did not abort at the original header store')
                finally:
                    remote.breakpoint(vectors + 16, False)
                    remote.write(descriptor, saved)
                return dict(prefix=prefix, service_returns=returns,
                    invalid_heap_section_data_abort=True, descriptor_restored=True,
                    fault_offset=stage+0x94, heap_start=profile['heap_start'],
                    first_service_group_completed=False)
            # Only the original allocator's header slots are poisoned. Nearby
            # guards stay outside its observed writes, including the tail slot.
            remote.write(profile['heap_start'], b'\xA5' * 24 + b'Z72!')
            tail = profile['heap_start'] + profile['pool_count'] * 8
            remote.write(tail, b'\x5A' * 8 + b'Z72!')
        regs = reach(remote, call+4, vectors)
        require(remote.get(regs, 'r0') == 0 and remote.get(regs, 'sp') == stack-8,
                'Original service return or stack mismatch')
        returns.append(dict(entry=stage, return_offset=call+4, r0=0))
        if index == 0:
            distributor, cpu = runtime['config_words'][7], runtime['config_words'][6]
            require(word(remote, distributor) == 1 and word(remote, cpu) == 1 and
                    word(remote, cpu+4) == 0xFF, 'Original GIC control/priority mask mismatch')
            priorities = bytearray(b'\xFF' * 256)
            priorities[1] = 0  # Stock inter-core callback configuration uses SGI 1.
            # A single-CPU QEMU GIC reads SPI target registers as zero. This
            # does not establish the target readback on the physical board.
            require(remote.read(distributor+0x400, 256) == priorities and
                    remote.read(distributor+0x820, 224) == bytes(224) and
                    remote.read(distributor+0xC08, 56) == bytes(56),
                    'Original GIC priorities, SPI targets or trigger configuration mismatch')
            require(word(remote, distributor+0x100) == 0xFFFF and
                    remote.read(distributor+0x104, 28) == bytes(28),
                    'Original SGI/PPI/SPI enable state mismatch')
    count, start, end = profile['pool_count'], profile['heap_start'], profile['heap_end']
    require(remote.read(profile['pool_state'], 16) ==
            struct.pack('<4I', count, count, start, profile['pool_end']) and
            word(remote, profile['pool_config']) == end, 'Original pool geometry mismatch')
    require(remote.read(start, 24) == struct.pack('<6I', 4, 4, 1, 0, (count << 2) | 1, 0) and
            remote.read(start+count*8, 8) == struct.pack('<2I', (count << 2) | 1, 0) and
            remote.read(start+24, 4) == b'Z72!' and
            remote.read(start+count*8+8, 4) == b'Z72!', 'Original pool headers or guards mismatch')
    require(word(remote, profile['heap_control']) == 0 and
            word(remote, profile['heap_control']+4) == 0x800, 'Heap control initialization mismatch')
    list_heads = []
    for flags in (0, 0x10, 0x300, 0x310):
        group = (profile['lists'] + (56 if flags & 0x300 == 0x300 else 0) +
                 (28 if not flags & 0x10 else 0)) & ~7
        require(remote.read(group+8, 20) ==
                struct.pack('<5I', group+8, group+8, group+16, group+16, flags),
                'Original empty heap list or attributes mismatch')
        list_heads.append(dict(flags=flags, address=group+8))
    regs = reach(remote, profile['return_offset'], vectors)
    require(remote.get(regs, 'r0') == 0 and remote.get(regs, 'sp') == stack,
            'First service group did not restore caller stack')
    require(remote.read(runtime['copied_table'], 0x4000) == image[0x10000:0x14000],
            'Services modified installed original page table')
    result = dict(prefix=prefix, service_returns=returns, first_service_group_completed=True,
        gic_original_configuration_verified=True, original_irq_handler_verified=False,
        heap_start=start, heap_end=end, pool_count=count, pool_end=profile['pool_end'],
        native_heap_sections=profile['native_heap_sections'],
        firmware_target_word=profile['target_word'], single_cpu_spi_target_readback=0,
        pool_headers_and_guards_verified=True, empty_heap_lists=list_heads,
        return_offset=profile['return_offset'], counter_device_supported=True)
    if not stop_before_counter:
        return result
    # Preserve the first service group's boundary before counter initialization.
    regs = reach(remote, profile['counter_init'], vectors)
    remote.command('s')
    remote.command('s')
    require(remote.get(remote.regs(), 'r0') == 0x04266000, 'Unexpected counter device base')
    result['next_mmio_offset'] = profile['counter_init'] + 8
    result['next_mmio_address'] = 0x04266000
    if scenario == 'counter-access-fault':
        remote.command('s')
        regs = remote.regs()
        require(remote.get(regs, 'pc') == vectors+16 and
                remote.get(regs, 'cpsr') & 0x1F == 0x17 and
                remote.get(regs, 'lr') == BASE+profile['counter_init']+16,
                'Unsupported counter access did not cause the original data abort')
        result['unsupported_counter_data_abort_verified'] = True
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--slave', type=Path, required=True)
    parser.add_argument('--qemu', required=True)
    parser.add_argument('--destination', type=Path, required=True)
    args = parser.parse_args()
    try:
        images = dict(master=args.master.read_bytes(), slave=args.slave.read_bytes())
        structures = {role: analyze_eg(image, role) for role, image in images.items()}
        args.destination.mkdir(parents=True, exist_ok=False)
        report = dict(format=1, contexts=[], full_boot_verified=False, menu_verified=False,
            qemu_version=subprocess.check_output([args.qemu, '--version'], text=True).splitlines()[0],
            assumptions=['Original reset and instructions, stock images preloaded.',
                'Experimental Cortex-A7/GIC layout and platform completion remain unchanged.',
                'Heap RAM covers the decoded bounds; physical hardware capacity is unconfirmed.',
                'Header poison/guards affect instance RAM; negative control changes one copied descriptor.',
                'Startup stops before the first counter read; the fault scenario disables its MMIO interface.'])
        for role, image in images.items():
            context = dict(role=role, sha256=structures[role]['sha256'], scenarios={})
            for scenario in ['stock', 'invalid-heap-section', 'counter-access-fault'] + (
                    ['shared-path'] if role == 'slave' else []):
                with reset_machine(args.qemu, args.destination/f'{role}-{scenario}', image, role,
                                   counter_enabled=scenario != 'counter-access-fault') as remote:
                    context['scenarios'][scenario] = trace_services(remote, image, structures[role], scenario)
                print('PASS', role, scenario, flush=True)
            context['passed'] = True
            report['contexts'].append(context)
        report['passed'] = True
        (args.destination/'report.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
        print('Report:', args.destination/'report.json')
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f'Error: {error}\n')


if __name__ == '__main__':
    main()
