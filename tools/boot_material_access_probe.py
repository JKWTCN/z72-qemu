# SPDX-License-Identifier: GPL-2.0-or-later
"""Check boot-window permissions and original NOR query command stores.

Uses a compiled QEMU laboratory, original reset instructions and page tables.
Controls redirect one original STR to synthetic boot-window data in separate
instances. After original startup installs RAM code and the copied page table,
an injected invalid request exercises the original query/permission wrapper.
The earlier camera loader is not executed. No firmware bytes or recovered
key material are exported in the report.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import BASE, require
from analyze.firmware_structure import analyze_eg
from tools.boot_probe import reset_machine, trace_prefix
from tools.continuation_boot_probe import continue_to
from tools.smp_boot_probe import stop_registers

WINDOW, WINDOW_SIZE, MATERIAL = 0x10000000, 0x20000, 0x10000088


def registers(remote):
    names = ('SCTLR_EL1_S', 'SCTLR_EL1', 'TTBR0_S', 'TTBR0',
             'TTBCR_S', 'TTBCR', 'DACR_S', 'DACR', 'DFAR_S', 'DFSR_S')
    return {name: remote.read_register(name) for name in names}


def section_aliases(table):
    result = []
    for index, descriptor in enumerate(struct.unpack('<4096I', table)):
        # This list covers ordinary first-level sections only, not coarse
        # second-level tables or supersections.
        if descriptor & 2 and not descriptor & (1 << 18) and descriptor & 0xFFF00000 == WINDOW:
            result.append(dict(virtual_base=hex(index << 20), descriptor=hex(descriptor),
                               ap=((descriptor >> 13) & 4) | ((descriptor >> 10) & 3),
                               domain=(descriptor >> 5) & 15))
    return result


def control(qemu, directory, image, structure, mmu):
    role = structure['role']
    with reset_machine(qemu, directory, image, role) as remote:
        if mmu:
            trace_prefix(remote, structure)
        site = structure['boot_prefix']['stop_offset']
        # Reuse the original first peripheral STR, changing only registers in
        # this control instance. The original image and table stay unchanged.
        require(struct.unpack_from('<I', image, site)[0] == 0xE5801000,
                'Expected original STR r1,[r0]')
        before = bytes(remote.read(MATERIAL, 8))
        require(before == bytes(8), 'Unexpected initial laboratory boot material')
        remote.set(pc=BASE + site, r0=MATERIAL, r1=0x13579BDF)
        if not mmu:
            require(remote.command(f'Z2,{WINDOW:x},{WINDOW_SIZE:x}') == 'OK',
                    'Boot-prefix control watchpoint unsupported')
            watch_response = remote.command('c')
            require('watch:' in watch_response, 'Original store did not trigger watchpoint')
            require(remote.command(f'z2,{WINDOW:x},{WINDOW_SIZE:x}') == 'OK',
                    'Control watchpoint removal failed')
        response = remote.command('s')
        regs = remote.regs()
        after = bytes(remote.read(MATERIAL, 8))
        system = registers(remote)
        pc, cpsr = remote.get(regs, 'pc'), remote.get(regs, 'cpsr')
        if mmu:
            require(pc == structure['startup']['vector_address'] + 16 and
                    cpsr & 31 == 0x17 and after == before, 'Expected write data abort')
            dfsr = system['DFSR_S']
            require(system['DFAR_S'] == MATERIAL and dfsr & 15 == 13 and
                    dfsr & (1 << 11), 'Expected section write permission fault')
        else:
            require(pc == BASE + site + 4 and
                    after == struct.pack('<I', 0x13579BDF) + bytes(4),
                    'MMU-off store control failed')
        return dict(role=role, mmu_enabled=mmu, original_store_offset=hex(site),
                    stop_pc=hex(pc), stop_response=response, system_registers=system,
                    write_completed=not mmu, permission_abort=mmu,
                    write_watchpoint_positive_control=not mmu)


def query_driver(qemu, directory, image):
    with reset_machine(qemu, directory, image, 'master') as remote:
        # Let original startup install both RAM routines and a writable copy
        # of its page table before entering the driver wrapper.
        continue_to(remote, 0xD6EC)
        before = bytes(remote.read(MATERIAL, 8))
        system = registers(remote)
        table_base = system['TTBR0_S'] & 0xFFFFC000
        original_table = bytes(remote.read(table_base, 0x4000))
        require(original_table == image[0x10000:0x14000], 'Original table mismatch')
        require(remote.command(f'Z2,{WINDOW:x},{WINDOW_SIZE:x}') == 'OK',
                'Boot-prefix write watchpoint unsupported')
        return_address = BASE + 0xD6EC
        remote.breakpoint(return_address)
        current = remote.regs()
        # An invalid program request runs the original permission/query/restore
        # wrapper but is rejected before any program-data routine is called.
        remote.set(pc=0xB2BB04E0, lr=return_address, r0=0, r1=0, r2=0,
                   cpsr=remote.get(current, 'cpsr') | 32)
        writes = []
        try:
            while True:
                response = remote.command('c')
                _, regs = stop_registers(remote, response)
                pc = remote.get(regs, 'pc')
                if 'watch:' not in response:
                    require(pc == return_address, 'Query did not return')
                    break
                require(pc == 0xB2BB0686 and len(writes) < 16,
                        'Unexpected query writer: ' + hex(pc))
                writes.append(dict(pc=hex(pc), address=hex(remote.get(regs, 'r1')),
                    halfword=hex(remote.get(regs, 'r2') & 0xFFFF),
                    table_record=hex(remote.get(regs, 'r0')),
                    descriptor=hex(struct.unpack('<I', remote.read(table_base + 0x400, 4))[0])))
                require(remote.command(f'z2,{WINDOW:x},{WINDOW_SIZE:x}') == 'OK',
                        'Write watchpoint removal failed')
                remote.command('s')
                require(remote.command(f'Z2,{WINDOW:x},{WINDOW_SIZE:x}') == 'OK',
                        'Write watchpoint restoration failed')
        except TimeoutError:
            remote.interrupt()
            raise
        finally:
            remote.breakpoint(return_address, False)
        expected = [(0x10000AAA, 0xAA), (0x10000554, 0x55), (0x10000AAA, 0x90),
                    (0x10000AAA, 0xF0), (0x100000AA, 0x98), (0x10000AAA, 0xF0)]
        require([(int(w['address'], 16), int(w['halfword'], 16)) for w in writes] == expected,
                'Query command sequence mismatch')
        require(all(w['descriptor'] == '0x10000432' for w in writes), 'Query permission mismatch')
        require(remote.read(MATERIAL, 8) == before == bytes(8), 'Query changed boot material')
        restored = bytes(remote.read(table_base, 0x4000))
        require(restored == original_table, 'Query did not restore translation table')
        require(remote.get(remote.regs(), 'r0') == 2, 'Invalid request was not rejected')
        return dict(entry='0xb2bb04e0', entry_injected_after_original_table_switch=True,
                    arguments=[0, 0, 0], result=2, program_data_routine_reached=False,
                    observed_halfword_writes=writes, material_write_observed=False,
                    original_table_sha256=hashlib.sha256(original_table).hexdigest(),
                    ordinary_section_aliases=section_aliases(original_table),
                    table_restored=True, laboratory_zero_material_preserved=True,
                    real_nor_device_emulated=False, earlier_camera_loader_executed=False)


def run(args):
    images = dict(master=args.master.read_bytes(), slave=args.slave.read_bytes())
    structures = {role: analyze_eg(image, role) for role, image in images.items()}
    args.destination.mkdir(parents=True, exist_ok=False)
    controls = []
    for role, image in images.items():
        for mmu in (False, True):
            controls.append(control(args.qemu, args.destination / f'{role}-mmu-{int(mmu)}',
                                    image, structures[role], mmu))
    observation = query_driver(args.qemu, args.destination / 'query', images['master'])
    return dict(format=1, firmware_included=False,
                image_sha256={r: s['sha256'] for r, s in structures.items()},
                qemu_sha256=hashlib.sha256(Path(args.qemu).read_bytes()).hexdigest(),
                boot_prefix=[hex(WINDOW), hex(BASE)], material_address=hex(MATERIAL),
                controls=controls, native_query=observation,
                actual_boot_material_supplied=False, initializer_found=False,
                k8_recovered=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--slave', type=Path, required=True)
    parser.add_argument('--qemu', required=True)
    parser.add_argument('--destination', type=Path, required=True)
    args = parser.parse_args()
    report = run(args)
    (args.destination / 'report.json').write_text(json.dumps(report, indent=2) + '\n',
                                                  encoding='utf-8', newline='\n')
    print('PASS original store permissions, native NOR query commands and table restoration')
