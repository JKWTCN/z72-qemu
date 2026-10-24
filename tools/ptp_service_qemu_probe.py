# SPDX-License-Identifier: GPL-2.0-or-later
"""Check original nested PTP read admission on the QEMU laboratory board.

Original startup installs RAM data and page tables before isolated service
calls are arranged by the debugger. The service flag and sample RAM are
explicit fixture inputs. Transport calls are captured at their boundaries;
this does not exercise physical USB, service entry or flash programming.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import BASE, MASTER_SHA, digest, require, validate_master
from analyze.firmware_structure import thumb_literal
from analyze.upgrade_signature import appended_key
from tools.boot_probe import reset_machine
from tools.continuation_boot_probe import continue_to


def run(args):
    image = args.master.read_bytes()
    validate_master(image)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    service = thumb_literal(image, 0x4598D8, 0)
    packet, sample = 0xB1802000, 0xB1803000
    returned = BASE + 0xD6EC
    replies, submissions = [], []
    with tempfile.TemporaryDirectory(prefix='ptp-service-', dir=args.output.parent) as folder:
        with reset_machine(str(args.qemu), Path(folder) / 'board', image, 'master') as remote:
            remote.sock.settimeout(30)
            continue_to(remote, 0xD6EC)
            entry_state = remote.get(remote.regs(), 'cpsr')
            boundaries = {BASE + 0x61C4FC: 'reply', BASE + 0x61C46E: 'data',
                          BASE + 0x49014A: 'fragmented_data',
                          BASE + 0x3D7144: 'ctype', BASE + 0x39099C: 'assertion'}
            for address in (returned, *boundaries):
                remote.breakpoint(address)

            def call(offset, r0=0, r1=0, r2=0, r3=0):
                remote.set(pc=BASE + offset, lr=returned, r0=r0, r1=r1,
                           r2=r2, r3=r3,
                           cpsr=entry_state | 32)
                visited = []
                for _ in range(512):
                    response = remote.command('c')
                    require(response.startswith('T05'), 'Unexpected QEMU service stop')
                    regs = remote.regs()
                    pc = remote.get(regs, 'pc')
                    if pc == returned:
                        return remote.get(regs, 'r0')
                    require(pc in boundaries, 'Unexpected service boundary: ' + hex(pc))
                    visited.append(hex(pc))
                    a, b, c, d = (remote.get(regs, name) for name in ('r0', 'r1', 'r2', 'r3'))
                    if boundaries[pc] == 'ctype':
                        result = 0xB1804000
                    elif boundaries[pc] == 'assertion':
                        result = 0
                    elif boundaries[pc] == 'reply':
                        require(c <= 5, 'Unexpected reply size')
                        values = list(struct.unpack('<' + str(c) + 'I', remote.read(d, c * 4))) if c else []
                        replies.append(dict(outer=b, parameters=values))
                        result = 0
                    else:
                        require(0 < c <= 0x34 and b in (sample, 0xB2B422C8),
                                'Unexpected data source or size')
                        submissions.append(dict(boundary=boundaries[pc], source=b,
                            bytes=c, timeout=d, sha256=digest(remote.read(b, c))))
                        result = 1
                    lr = remote.get(regs, 'lr')
                    cpsr = remote.get(regs, 'cpsr')
                    remote.set(pc=lr & ~1, r0=result,
                               cpsr=(cpsr | 32) if lr & 1 else (cpsr & ~32))
                raise ValueError('Service call exceeded its transport boundary limit: ' + repr(visited))

            require(call(0x4A6A4C) == 0x119E405C, 'QEMU service table mismatch')
            call(0x4598DE)
            content = bytes((17 * i + 3) & 255 for i in range(16))
            remote.write(sample, content)
            cases = []
            for enabled, address, length, accepted in (
                    (0, sample, 16, False), (1, 0x10000088, 8, False),
                    (1, BASE, 16, False), (1, sample, 0, False),
                    (1, sample, 16, True)):
                remote.write(service, struct.pack('<I', enabled))
                remote.write(packet, struct.pack('<IHHI5I', 32, 1, 0x94FF, 1,
                                                 0xF032, address, length, 0, 0))
                replies.clear()
                submissions.clear()
                result = call(0x75230C, 0, packet)
                require(bool(result) == accepted, 'QEMU service admission mismatch')
                if accepted:
                    require(call(0x752312, 0, packet) == 1 and len(submissions) == 1 and
                            submissions[0]['sha256'] == digest(content), 'QEMU data handoff mismatch')
                    require(replies == [dict(outer=0x2001, parameters=[0x2001, 0, 0, 0, 0])],
                            'QEMU service read response mismatch')
                else:
                    expected = dict(outer=0xA004, parameters=[0, 0, 0, 0, 0]) if not enabled else \
                        dict(outer=0x2001, parameters=[0x201D, 0, 0, 0, 0])
                    require(replies == [expected] and not submissions, 'QEMU rejection mismatch')
                cases.append(dict(service_enabled=enabled, address=address, bytes=length,
                                  accepted=accepted, responses=list(replies),
                                  submissions=list(submissions)))
            require(remote.read(sample, 16) == content, 'Synthetic source changed')
            context, body_address, model, comparison = 0xB2B422C8, 0xB1805000, 0xB1806000, 0xB1806100
            material, body = bytes(range(8)), b'synthetic update body'
            key = appended_key(material, image)
            wanted_digest = hashlib.sha1(body + key).digest()
            remote.write(0x10000088, material)
            remote.write(0xB1804000, struct.pack('<I', 0xB1804100))
            remote.write(0xB1804100, bytes(0x20 if 48 <= c <= 57 else 0 for c in range(256)))
            remote.write(model, b'Z_7_2\0')
            checksum_cases = []
            for corrupt in (False, True):
                remote.write(body_address, body + bytes(8))
                wanted = bytes([wanted_digest[0] ^ 1]) + wanted_digest[1:] if corrupt else wanted_digest
                remote.write(comparison, wanted)
                call(0x38ED1C)
                call(0x38ED24, BASE + 0x37C635)
                call(0x38ED2A, body_address, len(body))
                call(0x38ED32, comparison)
                call(0x38ED3E, 0x10000088, 0x44B, model)
                require(remote.read(context + 12, 8) == material, 'QEMU raw context mismatch')
                result = call(0x38FE82)
                require(result == int(not corrupt) and remote.read(context + 12, 8) == key and
                        remote.read(body_address + len(body), 8) == key, 'QEMU transformed context mismatch')
                remote.write(packet, struct.pack('<IHHI5I', 32, 1, 0x94FF, 1,
                                                 0xF032, context, 0x34, 0, 0))
                replies.clear()
                submissions.clear()
                require(call(0x75230C, 0, packet) == 1 and call(0x752312, 0, packet) == 1 and
                        len(submissions) == 1 and
                        submissions[0]['sha256'] == digest(remote.read(context, 0x34)),
                        'QEMU nested service did not submit the retained checksum material')
                checksum_cases.append(dict(digest_matches=not corrupt, checker_returned=result,
                    context_bytes_transformed=True, submissions=list(submissions), responses=list(replies)))
            call(0x38ED1C)
            require(remote.read(context, 0x34) == bytes(0x34), 'QEMU checksum reset mismatch')
    return dict(format=1, firmware_included=False, master_sha256=MASTER_SHA,
                qemu_sha256=digest(args.qemu.read_bytes()), original_startup_stop=returned,
                service_gate_address=service, cases=cases,
                checksum_context=dict(address=context, material_address=context + 12,
                    cases=checksum_cases, original_reset_clears_context=True,
                    synthetic_material=True, menu_caller_executed=False),
                host_boundaries=['debugger-arranged isolated calls', 'synthetic service flag and sample RAM',
                                 'synthetic checksum inputs and ASCII digit flags', 'assertion logging',
                                 'response and data submission capture'],
                real_usb_verified=False, flash_programming_executed=False,
                actual_boot_material_recovered=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--qemu', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = run(args)
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('PASS QEMU service gate, boot-window rejection and synthetic RAM read handoff')


if __name__ == '__main__':
    main()
