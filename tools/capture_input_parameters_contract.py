# SPDX-License-Identifier: GPL-2.0-or-later
"""Recover original capture parameter cloning and finite-tail conditions."""
import argparse
import json
from pathlib import Path
import struct
import sys

from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R3, UC_ARM_REG_PC, UC_ARM_REG_LR

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import MASTER_SHA, require
from tools.boot_region_probe import RegionProbe


class ParametersProbe(RegionProbe):
    def __init__(self, image):
        super().__init__(image)
        self.tail = False
        self.selected_masks, self.frame_submissions, self.notifications = [], [], []

    def boundary(self, u, address, size, unused):
        if self.tail and address in (0x1022de00, 0x103aeafe, 0x103aeb22,
                0x103bf224, 0x1023aed6, 0x102358f6, 0x10360f2e, 0x10360f12,
                0x1023c314, self.DATA + 0x28000):
            a, b = u.reg_read(UC_ARM_REG_R0), u.reg_read(UC_ARM_REG_R1)
            result = 0
            if address == 0x1022de00:
                self.selected_masks.append(a)
                result = self.DATA + 0x10000
            elif address in (0x103aeafe, 0x103aeb22):
                result = int(bool(a))
            elif address == 0x10360f2e:
                result = 1
            elif address == 0x1023c314:
                self.frame_submissions.append((a, b))
            elif address == self.DATA + 0x28000:
                self.notifications.append((a, *struct.unpack('<2I', u.mem_read(b, 8))))
            u.reg_write(UC_ARM_REG_R0, result)
            u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))
            return
        if address == 0x103be8e8:
            u.mem_write(u.reg_read(UC_ARM_REG_R1), struct.pack('<H', 17))
        elif address == 0x102259f2:
            pass  # Identity conversion of the synthetic property above.
        else:
            return super().boundary(u, address, size, unused)
        u.reg_write(UC_ARM_REG_R0, 17)
        u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))


def probe(image):
    native = ParametersProbe(image)
    selectors = []
    for override in (0, 1, 2):
        for mode in range(5):
            value = native.call(0x2fdd92, override, mode)
            require(value == int(bool(override) or mode == 2), 'Original mode predicate differs')
            selectors.append(dict(override=override, mode=mode, result=value))
    source, destination = native.DATA + 0x10000, native.DATA + 0x12000
    source_nested, destination_nested = native.DATA, native.DATA + 0x4000
    cases = []
    for mode in range(4):
        for tail_flag in (0, 1):
            native.u.mem_write(source, bytes(0x1584))
            native.u.mem_write(destination, bytes(0x1584))
            native.u.mem_write(source_nested, bytes(0x33e8))
            native.u.mem_write(destination_nested, bytes(0x33e8))
            native.u.mem_write(source + 0x4f4, struct.pack('<I', source_nested))
            native.u.mem_write(destination + 0x4f4, struct.pack('<I', destination_nested))
            native.u.mem_write(source_nested + 0x2844, struct.pack('<2I', tail_flag, 23))
            native.u.reg_write(UC_ARM_REG_R3, destination)
            native.call(0x30ac52, mode, 7, source)
            enabled = int(mode == 2)
            actual = [native.word(destination + 0x2b4),
                      native.word(destination_nested + 0x2844),
                      native.word(destination_nested + 0x2848)]
            require(actual == [enabled, tail_flag if enabled else 0, 23 if enabled else 0],
                    'Original clone changed its conditional tail fields')
            require(native.word(source_nested + 0x2844) == tail_flag and
                    native.word(source_nested + 0x2848) == 23, 'Clone modified source fields')
            require(native.word(destination + 0x4f4) == destination_nested,
                    'Clone lost its destination-owned nested storage')
            cases.append(dict(mode=mode, source_tail_flag=tail_flag,
                source_other_flag=23, parameter_2b4=actual[0],
                nested_2844=actual[1], nested_2848=actual[2]))
    native.tail = True
    tail_cases = []
    node, context = native.DATA + 0xa000, native.DATA + 0xb000
    for tail_flag, metadata, queued in ((0, 0, 0), (0, 0, 1), (0, 1, 0),
                                       (0, 1, 1), (1, 0, 0), (1, 0, 1)):
        native.u.mem_write(source + 0x2b4, struct.pack('<I', metadata))
        native.u.mem_write(source_nested + 0x2844, struct.pack('<I', tail_flag))
        native.u.mem_write(0xb1887e78, bytes(16))
        native.u.mem_write(0xb1887e80, struct.pack('<I', native.DATA + 0x28001))
        native.u.mem_write(0xb25eebc4, struct.pack('<5I',
            node if queued else 0, node if queued else 0, queued, 0, 0))
        native.u.mem_write(node, struct.pack('<3I', node, node, context))
        native.selected_masks.clear()
        native.frame_submissions.clear()
        native.notifications.clear()
        native.call(0x20ff20)
        expected_frame = [(context, source)] if tail_flag and queued else []
        expected_notification = ([(0x041a000f, 0, source)]
                                 if not tail_flag or queued else [])
        require(native.frame_submissions == expected_frame and
                native.notifications == expected_notification,
                'Original finite-tail routing differs')
        require(native.word(0xb25eebcc) == queued, 'Tail worker unexpectedly consumed the peeked queue')
        tail_cases.append(dict(nested_2844=tail_flag, parameter_2b4=metadata,
            queued=queued, parameter_masks=native.selected_masks.copy(),
            frame_submissions=[[hex(a), hex(b)] for a, b in native.frame_submissions],
            notifications=[[hex(a), hex(b), hex(c)] for a, b, c in native.notifications]))
    native.tail = False
    request, config, auxiliary, context, output = [native.DATA + offset for offset in
                                                 (0x8000, 0x9000, 0xa000, 0xb000, 0xc000)]
    configurations = []
    inputs = ((0, 0, 0, 0, 0, 0), (0, 0, 1, 0, 1, 0), (0, 0, 1, 0, 0, 1),
              (11, 0, 0, 0, 0, 1), (12, 0, 0, 0, 0, 1), (0, 0, 0, 0, 0, 1),
              (11, 0, 1, 0, 0, 1), (0, 1, 1, 0, 1, 0), (0, 2, 1, 0, 1, 0),
              (0, 0, 1, 1, 1, 0), (0, 0, 1, 0, 2, 0), (11, 0, 0, 0, 0, 2),
              (0, 0, 2, 0, 1, 0), (12, 0, 2, 0, 0, 1))
    for mode, first_request, second_request, special, primary_option, alternate_option in inputs:
        native.u.mem_write(request, bytes(0xc0))
        native.u.mem_write(config, bytes(0x160))
        native.u.mem_write(request + 8, bytes([mode]))
        native.u.mem_write(request + 0x18, struct.pack('<2I', first_request, second_request))
        native.u.mem_write(request + 0xb0, bytes([special]))
        for offset, value in ((0x44, primary_option), (0x48, alternate_option),
                              (0x148, 0x12), (0x14c, 0x34), (0x150, 0x56)):
            native.u.mem_write(config + offset, bytes([value]))
        native.u.mem_write(config + 0x154, struct.pack('<IH', 0x12345678, 0x3456))
        native.u.mem_write(auxiliary + 4, bytes([0x78]))
        native.u.mem_write(context + 0xd, bytes([0x9a]))
        native.u.mem_write(output - 4, bytes([0xa5]) * 0x58)
        native.u.mem_write(native.DATA + 0x18000, struct.pack('<I', output))
        native.u.reg_write(UC_ARM_REG_R3, context)
        returned = native.call(0x340468, request, config, auxiliary)
        derived = int(not special and not first_request and
            (bool(second_request) and primary_option == 1 or
             not second_request and mode in (11, 12) and alternate_option == 1))
        actual = list(struct.unpack('<2I', native.u.mem_read(output + 0x48, 8)))
        require(returned == 1 and actual == [1 if derived else first_request, derived],
                'Original tail configuration predicates differ')
        expected = bytearray([0xa5] * 0x58)
        expected[4:7] = bytes.fromhex('123456')
        struct.pack_into('<IH', expected, 8, 0x12345678, 0x3456)
        expected[14:17] = bytes([0x9a, 0x78, special])
        struct.pack_into('<2I', expected, 0x4c, *actual)
        require(bytes(native.u.mem_read(output - 4, 0x58)) == bytes(expected),
                'Original configuration copy changed padding or guards')
        configurations.append(dict(mode=mode, request_18=first_request, request_1c=second_request,
            request_b0=special, config_44=primary_option, config_48=alternate_option,
            nested_2844=actual[0], nested_2848=actual[1]))
    request_variants = []
    for states, option, sequence in (((0, 0, 0), 0, 7), ((2, 1, 0), 0, 7),
            ((3, 3, 3), 0, 7), ((3, 3, 3), 1, 7), ((2, 3, 3), 0, 7),
            ((2, 2, 3), 0, 7), ((3, 0, 0), 2, 7), ((3, 0, 0), 0, 0xffffffff)):
        for address, state in zip((0xb23f6c30, 0xb23f6ca0, 0xb23f6ce8), states):
            native.u.mem_write(address, bytes(0x48))
            native.u.mem_write(address + 5, bytes([state]))
            native.u.mem_write(address + 8, struct.pack('<I', sequence))
        native.u.mem_write(0xb23f6c64, struct.pack('<2I', 0x12340000, 0x56780000))
        native.u.mem_write(0xb23f6c72, bytes([option]))
        native.u.mem_write(0xb23f6d0c, struct.pack('<I', 0x23450000))
        native.u.mem_write(output - 4, bytes(0x18))
        native.u.mem_write(output - 4, struct.pack('<I', 0x11223344))
        native.u.mem_write(output + 16, struct.pack('<I', 0x55667788))
        native.call(0x3cb2e4, output)
        if states[0] == 3:
            expected = [3 if option == 1 else 1, 0x12340000, 0x56780000, (sequence + 1) & 0xffffffff]
        elif states[1] == 3:
            expected = [2, 0, 0, 0]
        elif states[2] == 3:
            expected = [4, 0x23450000, 1, (sequence + 1) & 0xffffffff]
        else:
            expected = [0, 0, 0, 0]
        actual = list(struct.unpack('<4I', native.u.mem_read(output, 16)))
        require(actual == expected and native.word(output - 4) == 0x11223344 and
                native.word(output + 16) == 0x55667788, 'Original output selection differs')
        request_variants.append(dict(states=list(states), first_option=option,
            sequence=hex(sequence), selected=[hex(value) for value in actual]))
    return dict(format=1, firmware_included=False, master_sha256=MASTER_SHA,
        predicate='0x1031dd92', clone='0x1032ac52', nested_copy='0x10307bf0',
        selectors=selectors, cases=cases, tail_entry='0x1022ff20', tail_cases=tail_cases,
        configuration_entry='0x10360468', predicate_entry='0x1035aaf2', configurations=configurations,
        request_variant_entry='0x103eb2e4', request_variants=request_variants,
        host_boundaries=['synthetic property 17 and identity conversion for mode 2',
            'tail parameter selection, pointer validation, uncontended lock/unlock',
            'record tail frame submission and callback; bookkeeping endpoints return zero'],
        limitations=['Synthetic parameter storage; original initialization, copies and mode decisions execute.',
                     'Does not establish runtime mode selection or supply parameters to the running firmware.',
                     'Tail queues are synthetic; the original peek and routing execute.',
                     'The positive tail case disables metadata generation; no pixels or photo work execute.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    report = probe(args.master.read_bytes())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(selectors=len(report['selectors']), clones=len(report['cases']),
                          tail_cases=len(report['tail_cases']), configurations=len(report['configurations']),
                          request_variants=len(report['request_variants']))))


if __name__ == '__main__':
    main()
