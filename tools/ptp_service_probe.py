# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute nested PTP service routing and read-range checks on synthetic data.

Original table lookup, service gate, parameter checks and read callbacks run
locally. Host boundaries capture data submission and responses. No camera is
opened, no programming callback is called and no boot bytes are exported.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import BASE, MASTER_SHA, digest, require
from analyze.firmware_structure import thumb_literal
from analyze.upgrade_signature import appended_key
from tools.ptp_dispatch_probe import Probe as DispatchProbe


class Probe(DispatchProbe):
    def __init__(self, image):
        super().__init__(image)
        self.image = image
        self.service = thumb_literal(image, 0x4598D8, 0)
        self.vendor_responses, self.submissions = [], []
        self.hooks[0x61C46E] = self.submit
        self.hooks[0x49014A] = self.submit
        self.call(0x4598DE)  # Register the original service-state predicate.

    def reply(self, packet, response, count, parameters):
        self.responses.append(response)
        require(count <= 5, 'Unexpected response parameter count')
        values = list(struct.unpack('<' + str(count) + 'I',
                                    self.u.mem_read(parameters, count * 4))) if count else []
        self.vendor_responses.append(dict(outer=response, parameters=values))
        return 0

    def submit(self, packet, source, count, timeout):
        require(count <= 256, 'Unexpected synthetic read length')
        data = bytes(self.u.mem_read(source, count))
        self.submissions.append(dict(source=source, bytes=count, timeout=timeout,
                                     sha256=digest(data)))
        return 1

    def packet(self, command, first=0, second=0, opcode=0x94FF, length=32):
        self.u.mem_write(self.INPUT, struct.pack('<IHHI5I',
            length, 1, opcode, 1, command, first, second, 0, 0))
        self.responses.clear()
        self.vendor_responses.clear()
        self.submissions.clear()

    def prepare(self):
        # Original outer-operation preparation wrapper, not a direct handler call.
        return self.call(0x75230C, 0, self.INPUT)

    def execute(self):
        return self.call(0x752312, 0, self.INPUT)

    def checksum_context(self):
        """Check whether the original checksum leaves readable RAM state."""
        context = 0xB2B422C8
        body_address, model, comparison, ctype = (self.INPUT + offset for offset in
                                                (0x6000, 0x7000, 0x7100, 0xA000))
        self.u.mem_map(0x10000000, 0x20000)
        self.put_word(ctype, ctype + 0x100)
        self.u.mem_write(ctype + 0x100, bytes(0x20 if 48 <= c <= 57 else 0 for c in range(256)))
        self.hooks[0x3D7144] = lambda *args: ctype
        self.hooks[0x39099C] = lambda *args: 0
        material = bytes(range(8))
        body = b'synthetic update body'
        expected_key = appended_key(material, self.image)
        expected_digest = hashlib.sha1(body + expected_key).digest()
        self.u.mem_write(0x10000088, material)
        self.u.mem_write(model, b'Z_7_2\0')
        cases = []
        for corrupt in (False, True):
            self.u.mem_write(body_address, body + bytes(8))
            wanted = bytes([expected_digest[0] ^ 1]) + expected_digest[1:] if corrupt else expected_digest
            self.u.mem_write(comparison, wanted)
            self.call(0x38ED1C)
            self.call(0x38ED24, BASE + 0x37C635)
            self.call(0x38ED2A, body_address, len(body))
            self.call(0x38ED32, comparison)
            self.call(0x38ED3E, 0x10000088, 0x44B, model)
            require(bytes(self.u.mem_read(context + 12, 8)) == material,
                    'Original setup did not retain synthetic raw material')
            result = self.call(0x38FE82)
            require(result == int(not corrupt) and
                    bytes(self.u.mem_read(context + 12, 8)) == expected_key and
                    bytes(self.u.mem_read(body_address + len(body), 8)) == expected_key,
                    'Original checker did not retain the transformed synthetic material')
            self.packet(0xF032, context, 0x34)
            require(self.prepare() == 1 and self.execute() == 1 and
                    self.submissions[0]['sha256'] == digest(bytes(self.u.mem_read(context, 0x34))),
                    'Nested read did not reach the retained checksum context')
            cases.append(dict(digest_matches=not corrupt, checker_returned=result,
                              context_bytes_transformed=True, body_suffix_matches_context=True,
                              submissions=list(self.submissions),
                              responses=list(self.vendor_responses)))
        self.call(0x38ED1C)
        require(bytes(self.u.mem_read(context, 0x34)) == bytes(0x34),
                'Original context reset did not clear the retained material')
        return dict(context_address=context, material_address=context + 12,
                    cases=cases, original_context_reset_clears_material=True,
                    host_boundaries=['synthetic boot material, body and expected digest',
                                     'ASCII digit classification table', 'assertion logging'],
                    menu_or_update_caller_executed=False, actual_material_recovered=False)

    def run_service(self):
        table = self.call(0x4A6A4C)
        require(table == 0x119E405C, 'Service table binding mismatch')
        records = []
        for index in range(1024):
            address = table + index * 28
            fields = struct.unpack('<7I', self.u.mem_read(address, 28))
            if not fields[0]:
                break
            require(self.call(0x4A6CC4, fields[0]) == address and
                    self.call(0x4A6CC4, fields[0]) == address, 'Service lookup/cache mismatch')
            records.append(dict(address=address, opcode=fields[0],
                                fields=list(fields[1:])))
        else:
            raise ValueError('Unterminated service table')
        require(self.call(0x4A6CC4, 0xFE31) == 0, 'Unexpected legacy operation')

        # Gate state is an explicit fixture input, not a hardware enable method.
        gates = []
        for enabled in (0, 1):
            self.put_word(self.service, enabled)
            self.packet(0xF032, self.SAMPLE, 16)
            result = self.prepare()
            require(result == enabled and self.responses == ([] if enabled else [0xA004]),
                    'Original service predicate mismatch')
            gates.append(dict(enabled=enabled, result=result,
                              responses=list(self.vendor_responses)))
        self.u.mem_write(self.SAMPLE, bytes((17 * i + 3) & 255 for i in range(256)))
        ranges = []
        for address, length, accepted in (
                (0x10000088, 8, False), (0x10000080, 16, False),
                (BASE, 16, False), (0x13FFFFF0, 16, False),
                (self.SAMPLE, 16, True), (self.SAMPLE, 0, False)):
            self.packet(0xF032, address, length)
            result = self.prepare()
            require(bool(result) == accepted, 'Original address admission mismatch')
            if accepted:
                require(self.execute() == 1 and self.submissions == [dict(
                    source=address, bytes=length, timeout=5000,
                    sha256=digest(bytes(self.u.mem_read(address, length))))],
                    'Read callback did not submit the supplied synthetic data')
                require(self.vendor_responses[0]['outer'] == 0x2001 and
                        self.vendor_responses[0]['parameters'][0] == 0x2001,
                        'Read success response mismatch')
            else:
                require(not self.submissions and self.responses == [0x2001] and
                        self.vendor_responses[0]['parameters'][0] == 0x201D,
                        'Read rejection must preserve the nested status')
            ranges.append(dict(address=address, bytes=length, accepted=accepted,
                               responses=list(self.vendor_responses),
                               submissions=list(self.submissions)))

        # F021 reads object 0x11's initialized buffer, not its physical base.
        # Service initialization is outside this isolated fixture.
        object_pointer = self.call(0x2286F6, 0x11)
        region_pointer = self.call(0x2286E4, self.word(object_pointer + 20))
        physical_base = self.word(region_pointer)
        require(physical_base == 0x132C0000, 'Object physical region mismatch')
        pointer = self.SAMPLE + 0x1000
        self.put_word(object_pointer + 8, pointer)
        self.packet(0xF021, 0, 16)
        require(self.prepare() == 1, 'Object read preparation failed')
        sample = bytes((i * 7 + 1) & 255 for i in range(16))
        self.u.mem_write(pointer, sample)
        require(self.execute() == 1 and self.submissions == [dict(
            source=pointer, bytes=16, timeout=5000, sha256=digest(sample))],
            'Object read did not use its original mapped address')
        object_read = dict(command=0xF021, object_id=0x11,
                           physical_region_base=physical_base,
                           cached_buffer_seeded_by_host=True,
                           submissions=list(self.submissions),
                           responses=list(self.vendor_responses), covers_boot_material=False)
        negatives = []
        for command, length in ((0xFE31, 32), (0xF032, 28)):
            self.packet(command, self.SAMPLE, 16, length=length)
            require(self.prepare() == 0 and not self.submissions, 'Invalid service request accepted')
            negatives.append(dict(command=command, container_bytes=length,
                                  responses=list(self.vendor_responses)))
        checksum = self.checksum_context()
        return dict(format=1, firmware_included=False, master_sha256=MASTER_SHA,
                    service_table_address=table, service_records=records,
                    service_gate_address=self.service, gate_cases=gates,
                    range_cases=ranges, object_read=object_read, negative_cases=negatives,
                    checksum_context=checksum,
                    host_boundaries=['transport response capture', 'data submission capture',
                                     'fragmented data submission capture',
                                     'existing bulk-copy boundary'],
                    service_enabled_by_host_fixture=True, actual_usb_transfer_verified=False,
                    actual_flash_read_verified=False, boot_material_recovered=False,
                    limitations=[
                        'Only selected read operations are executed; the table inventory does not establish every operation contract.',
                        'The original service-entry and exit operations are not executed.',
                        'The data boundary captures bytes in host memory, not on a USB endpoint.',
                        'Synthetic contents are not a camera flash image or actual boot material.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = Probe(args.master.read_bytes()).run_service()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('PASS nested service table, gate, read controls and object mapping')


if __name__ == '__main__':
    main()
