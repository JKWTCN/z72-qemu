# SPDX-License-Identifier: GPL-2.0-or-later
"""Compare original GetDeviceInfo operation construction with a local capture.

Requires the dependencies of ptp_dispatch_probe. Executes original list
initialization, merging, configuration reads, serialization and packet routing.
Host boundaries supply a synthetic mutex, locks, bulk copy and captured PTP
responses. No USB connection is opened. Only the operations field is serialized,
not a complete live GetDeviceInfo transaction.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import BASE, MASTER_SHA, require
from tools.ptp_dispatch_probe import Probe
from unicorn import UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_R0


class DeviceInfoProbe(Probe):
    CACHE = 0xB188B911
    OUTPUT = Probe.INPUT + 0x4000

    def __init__(self, image):
        super().__init__(image)
        self.config_base = self.config - 0x4D6
        self.configuration_reads, self.command_callbacks = [], []
        self.hooks.update({0x340EBC: self.mutex, 0x340F18: lambda *a: 0,
                           0x340F12: lambda *a: 0})
        self.u.hook_add(UC_HOOK_CODE, self.configuration_read,
                        begin=BASE + 0x3A09E8, end=BASE + 0x3A09E8)
        for offset in (0x74F0E8, 0x74F110):
            self.u.hook_add(UC_HOOK_CODE, self.command_callback,
                            begin=BASE + offset, end=BASE + offset)
        self.call(0x444354)

    def mutex(self, address, *args):
        self.put_word(address, 1)
        return 0

    def configuration_read(self, u, address, size, unused):
        self.configuration_reads.append(u.reg_read(UC_ARM_REG_R0))

    def command_callback(self, u, address, size, unused):
        self.command_callbacks.append(hex(address))

    def build(self, mode, flag, feature=0, diagnostic=0, extra=0, invalidate=True):
        self.u.mem_write(self.config_base + 5, bytes([0x6A if feature else 0]))
        self.u.mem_write(self.config_base + 0x21C, bytes([extra]))
        self.u.mem_write(self.config, bytes([diagnostic]))
        if invalidate:
            self.u.mem_write(self.CACHE, b'\xff')
        self.configuration_reads.clear()
        pointer = self.call(0x444228, mode, flag)
        count = self.word(pointer)
        require(count <= 128, 'Unexpected operations count')
        operations = list(struct.unpack('<' + str(count) + 'H',
                                       self.u.mem_read(pointer + 4, count * 2)))
        return pointer, operations, dict(mode=mode, state_flag=flag,
            marker_feature=feature, config_21c=extra, config_4d6=diagnostic,
            profile=self.u.mem_read(self.CACHE, 1)[0], count=count,
            configuration_reads=[hex(v) for v in self.configuration_reads],
            advertises_92f0=0x92F0 in operations, advertises_9535=0x9535 in operations)

    def run_info(self, capture_bytes):
        capture = json.loads(capture_bytes.decode('utf-8'))
        require(capture['model'] == 'Z 7_2' and capture['device_version'] == 'V1.70',
                'Requires a Z7 II V1.70 capture')
        observed = [int(value, 16) for value in capture['operations']]
        require(len(observed) == len(set(observed)), 'Duplicate captured operations')
        pointer, baseline, _ = self.build(0, 0)
        require(len(baseline) == 95 and baseline == observed,
                'Original default operations differ from capture')
        vendor = list(struct.unpack('<76H', self.u.mem_read(0xB188B97C, 152)))
        standard = list(struct.unpack('<19H', self.u.mem_read(0xB188B934, 38)))
        require(baseline == standard + vendor, 'Operation source arrays differ')
        serialized = self.call(0x462844, self.OUTPUT, 0x1000, pointer)
        expected_wire = struct.pack('<I95H', 95, *baseline)
        require(serialized == 194 and bytes(self.u.mem_read(self.OUTPUT, serialized)) == expected_wire,
                'Original operation serializer mismatch')
        cases = []
        for mode in range(5):
            for flag in range(2):
                _, operations, result = self.build(mode, flag)
                require(0x92F0 not in operations and '0x4d6' not in result['configuration_reads'],
                        'Unexpected diagnostic advertisement dependency')
                cases.append(result)
        for flag in (0, 1):
            _, _, result = self.build(1, flag, extra=1)
            cases.append(result)
            _, _, result = self.build(0, flag, feature=1)
            cases.append(result)
        gates = []
        for diagnostic in (0, 1):
            _, operations, info = self.build(0, 0, diagnostic=diagnostic)
            require(operations == baseline, 'Diagnostic flag changed announcement')
            self.responses.clear()
            self.configuration_reads.clear()
            result = self.call(0x42415E, 0, self.INPUT)
            require(result == diagnostic and self.configuration_reads == [0x4D6] and
                    self.responses == ([] if diagnostic else [0x2005]), 'Diagnostic gate mismatch')
            gates.append(dict(config_4d6=diagnostic, operations_unchanged=True,
                              advertised=False, prepare_result=result,
                              responses=[hex(v) for v in self.responses],
                              builder_configuration_reads=info['configuration_reads']))
        # Profile identity is the cache key; configuration changes alone do not
        # rebuild a cached list. Invalidate explicitly when comparing inputs.
        self.build(0, 0)
        _, cached, _ = self.build(0, 0, feature=1, invalidate=False)
        require(cached == baseline and self.configuration_reads == [], 'Cache behavior mismatch')
        _, refreshed, _ = self.build(0, 0, feature=1)
        require(len(refreshed) == 97 and set(refreshed) - set(baseline) == {0x942B, 0x944B},
                'Feature merge mismatch')
        table1 = self.call(0x458EBC, 1)
        table5 = self.call(0x458EBC, 5)
        record = self.call(0x458EF6, table1, 0x9535)
        require(record == 0x119E1D24 and self.call(0x458EF6, table5, 0x9535) == 0,
                '9535 catalog mismatch')
        require(self.call(0x443D70, 0x9535) == 0, '9535 lookup unexpectedly succeeded')
        self.responses.clear()
        self.command_callbacks.clear()
        self.u.mem_write(self.INPUT, struct.pack('<IHHII', 16, 1, 0x9535, 0, 0))
        packet_result = self.call(0x443E8E, self.INPUT)
        require(packet_result == 0 and self.responses == [0x2005] and not self.command_callbacks,
                '9535 packet rejection mismatch')
        return dict(format=1, firmware_included=False, master_sha256=MASTER_SHA,
            capture_sha256=hashlib.sha256(capture_bytes).hexdigest(),
            identity=dict(model=capture['model'], device_version=capture['device_version']),
            addresses=dict(get_device_info='0x104643f6', initialize='0x10464354',
                           operations_builder='0x10464228', merge='0x1046417c',
                           conditional_extras='0x104641f0', serializer='0x10482844',
                           standard_table='0xb188b934', vendor_table='0xb188b97c',
                           built_dataset='0xb2a4e71c', cached_profile=hex(self.CACHE)),
            baseline=dict(standard_count=19, vendor_count=76, count=95,
                          ordered_capture_match=True, operations=[f'0x{v:04X}' for v in baseline],
                          serialized_bytes=serialized,
                          serialized_sha256=hashlib.sha256(expected_wire).hexdigest()),
            profile_cases=cases, diagnostic_cases=gates,
            cache_case=dict(before=95, after_marker_change=95, after_invalidation=97,
                            added_after_invalidation=['0x942B', '0x944B']),
            opcode_9535=dict(advertised=True, record=hex(record), catalog_selector=1,
                             classifier_selector=5, lookup_result=0, packet_result=packet_result,
                             packet_response='0x2005', handler_callbacks_reached=False,
                             physical_request_response_available=False),
            host_boundaries=['synthetic mutex creation', 'locks', 'bulk copy', 'PTP response capture'],
            physical_usb_commands_sent=False, full_device_info_transaction_emulated=False,
            alternate_route_verified=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--capture', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = DeviceInfoProbe(args.master.read_bytes()).run_info(args.capture.read_bytes())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
    print('PASS 95 captured operations, native construction/serialization, independent diagnostic gate and 9535 rejection')
