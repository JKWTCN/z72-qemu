# SPDX-License-Identifier: GPL-2.0-or-later
"""Exercise original update-confirmation objects and event dispatch offline.

Original package collection, selection, version summary and menu callbacks run
on synthetic runtime/display state. No camera or programming operation is used.
"""
import argparse
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import BASE, MASTER_SHA, digest, require, validate_master
from analyze.firmware_structure import scatter_records
from analyze.ptp_checksum_context import CONTEXT, CONTEXT_SIZE
from tools.native_update_probe import NativeUpdateProbe
from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_WRITE


PAGE = 0x2D8
OBJECT = 0xB2BB720C + PAGE * 44


class ConfirmationProbe(NativeUpdateProbe):
    def __init__(self, master, package):
        super().__init__(master, package)
        for address, size in ((0xB2BB0000, 0x60000), (0xB2B42000, 0x1000),
                              (0xB200E000, 0x1000), (0xB201B000, 0x1000),
                              (0xB2077000, 0x2000)):
            self.u.mem_map(address, size)
        for record in scatter_records(master):
            if record['kind'] == 'copy' and record['destination'] < 0xB2C00000:
                offset = record['source'] - BASE
                self.u.mem_write(record['destination'], master[offset:offset + record['size']])
        self.put_word(self.UPDATE_STATE + 0x40, self.SCRATCH)
        self.sentinel = bytes((17 * i + 3) & 255 for i in range(CONTEXT_SIZE))
        self.u.mem_write(CONTEXT, self.sentinel)
        self.context_writes, self.entries = [], []

        def write(u, access, address, size, value, unused):
            self.context_writes.append(dict(pc=hex(u.reg_read(self.pc)),
                                            address=hex(address), bytes=size))

        self.u.hook_add(UC_HOOK_MEM_WRITE, write,
                        begin=CONTEXT, end=CONTEXT + CONTEXT_SIZE - 1)
        for address in (0x1070261E, 0x1070271C, 0x1063CB3A, 0x1063CC1C,
                        0x1044E636, 0x1070297C, 0x1063AEC2,
                        0x1063CB3E, 0x103F67A4, 0x103F6474, 0x103F6938,
                        0x1039C638, 0x103AFE82, 0x103AED1C):
            self.u.hook_add(UC_HOOK_CODE,
                            lambda u, a, size, unused: self.entries.append(hex(a)),
                            begin=address, end=address)

        def forbidden(u, address, size, unused):
            raise ValueError('Unexpected authentication or programming entry: ' + hex(address))

        # The Yes case stops at the authentication event post, before the worker.
        for address in (0x103F6938, 0x1039C638, 0x103AFE82, 0x103AED1C,
                        0x1039C8FE, 0x1039C9EA, 0x1039CA48):
            self.u.hook_add(UC_HOOK_CODE, forbidden, begin=address, end=address)
        self.fixed(0x10635CEE, 0)  # Display-tree lookup: no rendered widgets.
        self.fixed(0x1063C826, 0)  # Alternate display-layout setting.

    def fixed(self, address, value):
        self.install_hook(address - BASE, lambda *args: self.result(value))

    def retained(self):
        require(not self.context_writes and
                bytes(self.u.mem_read(CONTEXT, CONTEXT_SIZE)) == self.sentinel,
                'Covered menu path changed the context')
        return True

    def prepare(self):
        require(self.word(OBJECT) == PAGE << 16 | 2 and
                self.word(OBJECT + 0x10) == 0x1096A858,
                'Original confirmation object binding differs')
        properties = self.word(OBJECT + 0x28)
        rows, tables = self.word(properties + 12), self.word(properties + 16)
        for row, widget, table, callback in (
                (0, 0x20BE, 0x1180C208, 0x1070297D),
                (1, 0x20BF, 0x1180C3F8, 0x1063AEC3)):
            require(self.word(rows + row * 28 + 24) == widget and
                    self.word(tables + row * 4) == table and
                    self.word(table + 9 * 16) == 0x27D and
                    self.word(table + 9 * 16 + 4) == callback,
                    'Original confirmation option binding differs')
        collected = self.collect_packages({
            'A:\\firmware\\': [('Z7_2_0~1.BIN', 'Z7_2_0170.BIN')], 'A:\\': []})
        require(collected['matching_count'] == 1 and collected['record_package_flag'] == 1,
                'Expected one original whole-package candidate')
        self.call(0x37DAA4, 13)
        self.installed_version_fixture()
        self.parameters[0x3900] = b'01.70' + bytes(5)
        output = self.SCRATCH + 0x6000
        self.call(0x3D636A, output)
        require(self.word(output) == 1, 'Expected one whole-package version row')
        version = bytes(self.u.mem_read(output + 4, 21))
        require(version[0] == 13 and version[1:6] == b'01.70' and
                version[11:16] == b'01.70', 'Same-version fixture differs')
        self.call(0x6E261E, OBJECT)
        selected = sum(struct.unpack('<HH', self.u.mem_read(OBJECT + 0x16, 4)))
        require(selected == 1, 'Confirmation page did not default to the return option')
        return dict(matching_count=collected['matching_count'],
                    original_package_selected=True, installed_version_is_synthetic=True,
                    current_version='01.70', target_version='01.70',
                    default_selected_row=selected, context_preserved=self.retained(),
                    authentication_entered=False)

    def dispatch(self, row, stop_offset=None):
        self.u.mem_write(OBJECT + 0x16, struct.pack('<HH', row, 0))
        self.fixed(0x10630814, 0)  # UI dispatch guard.
        self.fixed(0x1063082A, 0)
        self.fixed(0x1073EAA8, 0)  # Special-event handling, absent in this fixture.
        self.fixed(0x1063C7D4, 0)  # Optional UI recording setting.
        return self.call(0x42E636, OBJECT, 0x27D, stop_offset=stop_offset)


def menu_no(master, package):
    probe = ConfirmationProbe(master, package)
    preparation = probe.prepare()
    returned = probe.dispatch(1)
    require(returned == 0x43B and '0x1063aec2' in probe.entries and
            '0x1070297c' not in probe.entries, 'Return-option dispatch differs')
    probe.call(0x5FDB80, OBJECT)  # Original page-exit callback dispatcher.
    require('0x1070271c' in probe.entries and probe.retained(),
            'Page-exit callback did not execute or changed the context')
    return dict(preparation=preparation, selected_row=1,
                callback='0x1063aec2', returned=hex(returned),
                context_preserved=probe.retained(), entries=probe.entries,
                native_context_writes=probe.context_writes,
                page_exit_callback='0x1070271c', page_exit_callback_executed=True,
                generic_page_return_completed=False)


def menu_yes(master, package):
    probe = ConfirmationProbe(master, package)
    preparation = probe.prepare()
    # The execute callback runs with synthetic UI state; real widget rendering,
    # capture-mode effects and task scheduling are outside this offline case.
    for address in (0x10635E7A, 0x106347EC, 0x1063C7E0, 0x1063B790,
                    0x1061CBE8, 0x106B91A0, 0x10636CF8, 0x10634F58,
                    0x1070288C, 0x10635BDE, 0x106538F2, 0x1061AA7E,
                    0x1063C852, 0x1063D9EC, 0x10636680, 0x1062E472,
                    0x1039AD26, 0x103DB2CA, 0x103610D2):
        probe.fixed(address, 0)
    probe.fixed(0x1063C2B2, OBJECT)
    probe.fixed(0x102F4B1A, 1)
    probe.fixed(0x103F60CA, probe.SCRATCH + 0x4000)

    def capture_state(output, *args):
        probe.u.mem_write(output, bytes(0x464))
        probe.result(0)

    def progress_ready(*args):
        probe.put_word(0xB1826704 + 0x48, 0)
        probe.result(0)

    probe.install_hook(0x106B8DCE - BASE, capture_state)
    probe.install_hook(0x10714C80 - BASE, progress_ready)
    snapshot = bytearray(0x50)
    struct.pack_into('<I', snapshot, 0, 1)
    snapshot[4] = 1
    probe.u.mem_write(0xB23BCCF0 + 0xAC, bytes(snapshot))
    returned = probe.dispatch(0, stop_offset=0x3410CC)
    require(returned is None and probe.u.reg_read(probe.pc) == 0x103610CC and
            probe.u.reg_read(probe.regs[0]) == 0xB1887D24 and
            probe.u.reg_read(probe.regs[1]) == 0x10,
            'Yes did not reach the original authentication event post')
    require(all(hex(a) in probe.entries for a in
                (0x1070297C, 0x1063CB3E, 0x103F67A4, 0x103F6474)),
            'Menu-to-authentication controller chain was not executed')
    return dict(preparation=preparation, selected_row=0,
                authentication_post_reached_after_selection=True,
                authentication_event='0x10', authentication_event_object='0xb1887d24',
                stopped_at='0x103610cc', context_preserved_before_worker=probe.retained(),
                entries=probe.entries, authentication_worker_executed=False,
                programming_executed=False)


def run(master, package):
    validate_master(master)
    return dict(format=1, firmware_included=False, master_sha256=MASTER_SHA,
                package_sha256=digest(package), page=hex(PAGE), object=hex(OBJECT),
                page_initializer='0x1070261e', callback_table='0x1096a858',
                choice_event='0x27d',
                option_bindings=[dict(row=0, widget='0x20be', event_table='0x1180c208',
                                      callback='0x1070297c', purpose='execute update'),
                                 dict(row=1, widget='0x20bf', event_table='0x1180c3f8',
                                      callback='0x1063aec2', purpose='return to preceding page')],
                no=menu_no(master, package), yes=menu_yes(master, package),
                actual_camera_access=False,
                limitations=[
                    'Directory, file I/O and installed versions are runtime fixtures.',
                    'Original menu objects, row metadata and callback tables are restored from initialization data.',
                    'The display tree is absent; the Yes callback uses supplied UI/task readiness.',
                    'The No callback returns its navigation result; subsequent generic page teardown is not covered.',
                    'The Yes case stops before posting the authentication event and never runs programming.',
                    'This does not establish retention across physical USB reconnect or full PTP lifecycle.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = run(args.master.read_bytes(), args.package.read_bytes())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('PASS original confirmation initialization and return/execute option dispatch')


if __name__ == '__main__':
    main()
