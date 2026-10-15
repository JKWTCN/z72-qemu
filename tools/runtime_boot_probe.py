# SPDX-License-Identifier: GPL-2.0-or-later
"""Follow stock reset through ARM/Thumb bootstrap, table handoff and RTOS setup."""
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
from analyze.runtime_bootstrap import runtime_profile, seeded_words
from tools.boot_probe import reset_machine
from tools.continuation_boot_probe import trace_continuation, continue_to
from tools.early_boot_probe import word
from tools.structure_probe import poison


def trace_runtime(remote, structure, image, scenario):
    role = structure['role']
    profile = runtime_profile(image, role)
    invalid = scenario == 'invalid-copied-table'
    prefix = trace_continuation(remote, structure, image,
                               'shared-path' if scenario == 'shared-path' else 'stock')
    continue_to(remote, profile['app_entry'])
    require(word(remote, 0x20070008) == 0, 'Original memory wait did not acknowledge completion')
    stack = structure['startup']['core_zero_stack_tops'][-1]
    trace, caches, copied, cache_counts = [], [], False, []
    library_seen = switch_seen = config_seen = states_seen = False
    for _ in range(2200):
        regs = remote.regs()
        offset = remote.get(regs, 'pc') - BASE
        thumb = bool(remote.get(regs, 'cpsr') & 32)
        trace.append(dict(offset=offset, thumb=thumb, sp=remote.get(regs, 'sp')))
        require(remote.get(regs, 'cpsr') & 0x1F == 0x13, 'Runtime left SVC mode')
        if offset == profile['stop']:
            break
        if offset == profile['app_entry'] + 8:
            require(thumb and remote.get(regs, 'sp') == stack, 'Bootstrap interworking failed')
        if offset == profile['library_entry']:
            library_seen = True
            require(thumb and [remote.get(regs, f'r{i}') for i in (0, 1, 2)] ==
                    [*profile['bounds'], profile['bounds'][1]], 'Bootstrap bounds arguments mismatch')
        if offset == profile['app_entry'] + 0x12:
            require(all(word(remote, a) == v for a, v in seeded_words(profile).items()),
                    'Original random-state initialization mismatch')
            require(word(remote, profile['rng_base']+0xDC) == profile['rng_base']+0x7C and
                    word(remote, profile['rng_base']+0xE0) == profile['rng_base'],
                    'Original random-state cursor pointers mismatch')
            require(word(remote, profile['control'] + 4) == profile['defaults'][0] + 1 and
                    word(remote, profile['control'] + 12) == profile['defaults'][1],
                    'Default library data pointers mismatch')
        if offset == profile['cache_entry']:
            require(not thumb, 'Cache maintenance entered in Thumb')
            saved = [remote.get(regs, f'r{i}') for i in range(13)]
            resume = remote.get(regs, 'lr')
            continue_to(remote, resume - BASE)
            after = remote.regs()
            require([remote.get(after, f'r{i}') for i in range(13)] == saved and
                    remote.get(after, 'sp') == remote.get(regs, 'sp'), 'Cache maintenance changed caller state')
            caches.append(dict(entry=offset, return_offset=resume-BASE, preserved_registers=True))
            continue
        if offset == profile['copy_entry']:
            require(not thumb and remote.get(regs, 'r0') == profile['copied_table'] and
                    remote.get(regs, 'r1') == BASE+0x10000 and remote.get(regs, 'r2') == 0x4000,
                    'Original table-copy arguments mismatch')
            poison(remote, profile['copied_table'], 0x4000)
            for address in (profile['copied_table']-4, profile['copied_table']+0x4000):
                remote.write(address, b'Z72!')
            continue_to(remote, remote.get(regs, 'lr') - BASE)
            require(remote.read(profile['copied_table'], 0x4000) == image[0x10000:0x14000] and
                    remote.read(profile['copied_table']-4, 4) == b'Z72!' and
                    remote.read(profile['copied_table']+0x4000, 4) == b'Z72!',
                    'Copied original page table or guards mismatch')
            copied = True
            continue
        if offset == profile['switch_entry']:
            require(copied and not thumb and remote.get(regs, 'r0') == profile['copied_table'],
                    'Original table-switch argument mismatch')
            switch_seen = True
            if invalid:
                remote.write(profile['copied_table'] + 0x400, bytes(4))
        if offset == profile['rtos_entry']:
            require(switch_seen and not thumb and word(remote, 0x04008FFC) == 0xBABEBABE,
                    'Runtime entry or secondary-release marker mismatch')
            poison(remote, profile['config'], 48)
            remote.write(profile['config']+48, b'Z72!')
            config_seen = True
        if offset == profile['rtos_entry'] + 0xA8 or offset == profile['rtos_entry'] + 0xB4:
            cache_counts.append(remote.get(regs, 'r0'))
        if offset == profile['states_entry']:
            poison(remote, profile['state'], 16)
            poison(remote, profile['state_array'], 0x400)
            remote.write(profile['state']+16, b'Z72!')
            remote.write(profile['state_array']-4, b'Z72!')
            states_seen = True
        remote.command('s')
        after = remote.regs()
        if invalid and remote.get(after, 'pc') == structure['startup']['vector_address'] + 12:
            require(switch_seen and profile['switch_entry'] <= offset <= profile['switch_entry']+0x28,
                    'Copied-table abort occurred outside the native switch')
            require(remote.get(after, 'cpsr') & 0x1F == 0x17, 'Expected prefetch abort mode')
            remote.write(profile['copied_table'] + 0x400, image[0x10400:0x10404])
            require(remote.read(BASE+0x10000, 0x4000) == image[0x10000:0x14000],
                    'Negative control modified source page table')
            return dict(prefix=prefix, copied_table=profile['copied_table'], trace=trace,
                        fault_offset=offset, copied_table_prefetch_abort=True,
                        invalid_descriptor_restored=True,
                        source_table_preserved=True, rtos_entry_reached=False)
        require(remote.get(after, 'pc') not in [structure['startup']['vector_address'] + x for x in (4, 12, 16)],
                f'Runtime exception after {offset:#x}')
    else:
        raise ValueError('Runtime bootstrap exceeded instruction bound')
    require(library_seen and copied and switch_seen and config_seen and states_seen and len(caches) == 2,
            'Incomplete runtime bootstrap')
    require(remote.read(profile['config'], 48) == struct.pack('<12I', *profile['config_words']) and
            remote.read(profile['config']+48, 4) == b'Z72!', 'RTOS configuration object mismatch')
    require(remote.read(profile['state'], 16) == struct.pack('<4I', profile['state_ref'], 0, 0, 0) and
            remote.read(profile['state_array'], 0x400) == bytes(0x400) and
            remote.read(profile['state']+16, 4) == b'Z72!' and
            remote.read(profile['state_array']-4, 4) == b'Z72!', 'RTOS state clearing or guards mismatch')
    require(remote.read(profile['ready'], 20) == struct.pack('<5I', 1, *profile['config_words'][6:10]),
            'RTOS ready record mismatch')
    require(len(cache_counts) == 2 and [word(remote, a) for a in profile['cache_count_words']] == cache_counts,
            'RTOS cache geometry stores mismatch')
    require(remote.get(regs, 'sp') == stack-8 and not thumb,
            'RTOS setup stack/instruction state mismatch')
    require(remote.read(BASE+0x10000, 0x4000) == image[0x10000:0x14000] and
            remote.read(profile['copied_table'], 0x4000) == image[0x10000:0x14000],
            'Runtime changed source or installed table')
    return dict(prefix=prefix, trace=trace, caches=caches, copied_table=profile['copied_table'],
                copied_table_bytes=0x4000, source_table_preserved=True, installed_table_preserved=True,
                random_words_verified=55, default_data_pointers=profile['defaults'],
                config_address=profile['config'], config_words=profile['config_words'],
                state_address=profile['state'], state_array=profile['state_array'],
                zeroed_state_bytes=0x410, state_guards_preserved=True, cache_counts=cache_counts,
                secondary_release_marker=0xBABEBABE, stop_offset=profile['stop'],
                rtos_bootstrap_ready=True, next_service_executed=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--slave', type=Path, required=True)
    parser.add_argument('--qemu', required=True)
    parser.add_argument('--destination', type=Path, required=True)
    args = parser.parse_args()
    try:
        images = dict(master=args.master.read_bytes(), slave=args.slave.read_bytes())
        structures = {r: analyze_eg(i, r) for r, i in images.items()}
        args.destination.mkdir(parents=True, exist_ok=False)
        report = dict(format=1, contexts=[], full_boot_verified=False, menu_verified=False,
            qemu_version=subprocess.check_output([args.qemu, '--version'], text=True).splitlines()[0],
            assumptions=['Original reset, instructions and page-table copy/switch; stock EG preloaded.',
                'Laboratory Cortex-A7 with CBAR 0x04000000 and standard GICv2; hardware layout unconfirmed.',
                'Poison and guards affect instance RAM; invalid copied-table scenario changes only its code descriptor.',
                'Platform completion and rounded synchronous memory clearing remain experimental.'])
        for role, image in images.items():
            context = dict(role=role, sha256=structures[role]['sha256'], scenarios={})
            for scenario in ['stock', 'invalid-copied-table'] + (['shared-path'] if role == 'slave' else []):
                with reset_machine(args.qemu, args.destination/f'{role}-{scenario}', image, role) as remote:
                    context['scenarios'][scenario] = trace_runtime(remote, structures[role], image, scenario)
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
