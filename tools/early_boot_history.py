# SPDX-License-Identifier: GPL-2.0-or-later
"""Exercise historical engine reset paths and optionally the dual-engine message ring."""
import argparse
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import BASE, digest, require, validate_master
from analyze.firmware_structure import PROFILES, boot_prefix, branch_target, scatter_records
from analyze.update_container import describe_container
from analyze.update_store import image_version
from analyze.upgrade_signature import decode
from tools.boot_probe import reset_machine
from tools.dual_boot_probe import MASTER_MAGIC, MASTER_MSG, dual_machine
from tools.early_boot_probe import trace_early
from tools.smp_boot_probe import reach


def controller_callbacks(image):
    # The first callback returns true; the adjacent one begins backend setup.
    # Locate their pointer pair inside the initialized data copied into RAM.
    records = scatter_records(image)
    tables = []
    for match in re.finditer(rb'\x01\x20\x70\x47.\x48\x20\x21\x10\xb5', image, re.DOTALL):
        address = BASE + match.start()
        pair = struct.pack('<2I', address | 1, (address + 4) | 1)
        for record in records:
            if record['kind'] != 'copy':
                continue
            start = record['source'] - BASE
            pos = image.find(pair, start, start + record['size'])
            if pos >= 0:
                require(image.find(pair, pos + 1, start + record['size']) < 0,
                        'Ambiguous controller callback pair')
                tables.append((record['destination'] + pos - start, pair))
    require(len(tables) == 1, 'Expected one controller callback table')
    return tables[0]


def trace_receiver(images, signature, qemu):
    slave = images['slave']
    require(slave.count(signature) == 1, 'Expected one matching receiver instruction sequence')
    offset = slave.index(signature) + 10
    with tempfile.TemporaryDirectory(prefix='z72-transport-') as folder:
        directory = Path(folder)
        process, remote = dual_machine(qemu, directory, images['master'], slave,
            directory / 'console.txt', icount='shift=4,sleep=off', trace=None,
            globals_=('nikon-z72-boot-config.transport-link=on',))
        try:
            remote.sock.settimeout(60)
            thread, _ = reach(remote, BASE + offset)
            require(thread in (3, 4), 'Receiver stop came from the wrong engine')
            remote.select_thread(thread)
            header = remote.read(0x47cf0000, 24)
            remote.select_thread(1)
            require(header == remote.read(MASTER_MSG, 24) and header[:8] == MASTER_MAGIC,
                    'Master and receiver ring headers differ')
            written, consumed = struct.unpack_from('<I4xI', header, 8)
            require(0 < written < 0xc0 and written == consumed, 'Receiver ring did not drain')
            # Observe the main task call its delay and return to the backward branch.
            call = 0x1e0192
            master = images['master']
            require(master[call - 6:call] == bytes.fromhex('40f2e8342046') and
                    master[call + 4:call + 6] == bytes.fromhex('fbe7'),
                    'Unexpected main task delay loop')
            main_thread, regs = reach(remote, BASE + call)
            delay = remote.get(regs, 'r0')
            require(main_thread in (1, 2) and delay == 1000, 'Unexpected main task delay')
            return_thread, _ = reach(remote, BASE + call + 4)
            require(return_thread in (1, 2), 'Delay returned on the wrong engine')
            remote.select_thread(return_thread)
            table, pair = controller_callbacks(master)
            slot = table - 0x28
            require(remote.read(slot, 4) == struct.pack('<I', table) and
                    remote.read(table, 8) == pair, 'Controller callbacks not installed')
            return dict(receiver_offset=offset, receiver_thread=thread,
                        written=written, consumed=consumed, alias_header_matches=True,
                        main_delay=dict(call_offset=call, argument=delay, returned=True),
                        controller_callbacks=dict(slot=slot, table=table,
                                                  functions=struct.unpack('<2I', pair)))
        finally:
            remote.sock.close()
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def trace_controller_request(images, controller, qemu):
    # The checker sums 256 bytes through r2 and branches on a sum of 0xff.
    loop = bytes.fromhex('4ff48071491e12f8014b2044c0b2f9d1ff280dd0')
    require(controller.count(loop) == 1, 'Expected one controller frame checksum loop')
    offset = controller.index(loop)
    require(controller[offset + 0x30:offset + 0x34] == bytes.fromhex('0120fbe7'),
            'Unexpected controller frame success branch')
    with tempfile.TemporaryDirectory(prefix='z72-controller-link-') as folder:
        directory = Path(folder)
        firmware = directory / 'controller.bin'
        firmware.write_bytes(controller)
        process, remote = dual_machine(qemu, directory, images['master'], images['slave'],
            directory / 'console.txt', icount='shift=4,sleep=off', trace=None,
            controller_firmware=firmware, controller_link=True,
            devices=('nikon-z72-controller-register-bank,bus=controller-i2c0,address=79',))
        try:
            remote.select_thread(5)
            regs = remote.regs()
            sp, reset = struct.unpack_from('<2I', controller)
            require(remote.get(regs, 'pc') == reset & ~1 and remote.get(regs, 'sp') == sp,
                    'Controller reset vectors differ from the packaged image')
            remote.sock.settimeout(60)
            thread, _ = reach(remote, 0x080002e2)
            require(thread == 5 and remote.read(0xe000ed08, 4) == struct.pack('<I', 0x20000000)
                    and remote.read(0x20000000, 0x1c4) == controller[:0x1c4],
                    'Controller reset did not relocate its vector table')
            thread, regs = reach(remote, 0x08000000 + offset)
            require(thread == 5, 'Frame checksum ran on the wrong processor')
            buffer = remote.get(regs, 'r2')
            frame = remote.read(buffer, 256)
            require(frame[:4] == bytes((1, 1, 28, 0)) and frame[252:254] == bytes((1, 1))
                    and sum(frame) & 255 == 255, 'Unexpected engine request frame')
            thread, regs = reach(remote, 0x08000000 + offset + 0x32)
            require(thread == 5 and remote.get(regs, 'r0') == 1, 'Controller rejected frame')
            master = images['master']
            checks = bytes.fromhex('57b348b30020a070206c0121')
            require(master.count(checks) == 1, 'Expected one master response acceptance path')
            accepted = master.index(checks) + 6
            thread, regs = reach(remote, BASE + accepted)
            require(thread in (1, 2) and remote.get(regs, 'r7') == 1,
                    'Master response checker did not accept the checksum')
            rx = remote.get(regs, 'r8')
            response = remote.read(rx, 256)
            require(response[:4] == bytes((1, 1, 28, 0)) and response[252:254] == bytes((1, 1))
                    and sum(response) & 255 == 255, 'Unexpected controller response frame')
            remote.select_thread(5)
            tx = int.from_bytes(remote.read(0x40026434, 4), 'little')
            require(remote.read(tx, 256) == response and remote.read(0x4002642c, 4) == bytes(4),
                    'Controller DMA and master response differ')
            ack_body = bytes.fromhex('0120a06104f15000bde810400821')
            require(controller.count(ack_body) == 1, 'Expected one acknowledgement callback')
            ack = controller.index(ack_body)
            thread, _ = reach(remote, 0x08000000 + ack)
            exception = int.from_bytes(remote.read(0xe000ed04, 4), 'little') & 0x1ff
            require(thread == 5 and exception == 39 and remote.read(0x40021810, 4)[0] & 0x40,
                    'Missing controller G6 receive confirmation')
            return dict(sha256=digest(controller), reset_pc=reset & ~1, vector_table=0x20000000,
                        checker_offset=offset, buffer=buffer, frame_sha256=digest(frame),
                        payload_bytes=28, frame_bytes=len(frame), accepted=True,
                        response=dict(frame_sha256=digest(response), master_buffer=rx,
                                      controller_dma_buffer=tx, acceptance_offset=accepted,
                                      acknowledgement_offset=ack, exception=exception))
        finally:
            remote.sock.close()
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def run_package(path, master, qemu, signature=None, controller_link=False):
    raw = path.read_bytes()
    body = raw[32:64] + decode(master, raw[64:], 32)
    members = describe_container(body)['members']
    engines = []
    images = {}
    for role, tag in (('master', 'mas'), ('slave', 'sla')):
        matches = [m for m in members if m['name'].startswith(f'eg1840_{tag}_')]
        require(len(matches) == 1, f'{path.name}: expected one {role} engine')
        member = matches[0]
        start = member['offset']
        image = body[start:start + member['length']]
        images[role] = image
        entry = branch_target(image, 0)
        profile = PROFILES[role]
        require(entry == profile.boot, f'{path.name}: unexpected {role} reset branch')
        prefix = boot_prefix(image, profile)
        structure = dict(role=role, boot_prefix=prefix, startup=dict(entry_offset=entry,
                         core_zero_stack_tops=[c['stack_top'] for c in prefix['stack_checkpoints']]))
        with tempfile.TemporaryDirectory(prefix='z72-reset-') as folder:
            with reset_machine(qemu, Path(folder) / role, image, role) as remote:
                observed = trace_early(remote, structure, image, 'stock')
        engines.append(dict(role=role, member=member['name'], sha256=member['sha256'],
                            version=image_version(image), entry_offset=entry,
                            **{k: v for k, v in observed.items() if k != 'trace'}))
        print(path.name, role, 'reached', hex(observed['stop_offset']), flush=True)
    result = dict(package=path.name, sha256=digest(raw), engines=engines)
    if signature:
        result['dual_transport'] = trace_receiver(images, signature, qemu)
        print(path.name, 'receiver drained ring', flush=True)
    if controller_link:
        controllers = [m for m in members if m['name'].startswith('ex1840_')]
        require(len(controllers) == 1, 'Expected one packaged body controller')
        member = controllers[0]
        start = member['offset']
        result['controller_request'] = trace_controller_request(
            images, body[start:start + member['length']], qemu)
        print(path.name, 'controller request, response and receive confirmation verified', flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--packages', required=True, type=Path)
    parser.add_argument('--master', required=True, type=Path, help='Original C 1.70 master EG')
    parser.add_argument('--transport-reference', type=Path,
                        help='Original C 1.70 slave EG for the dual-engine receiver check')
    parser.add_argument('--qemu', required=True)
    parser.add_argument('--controller-link', action='store_true',
                        help='Verify the first request and response between each packaged controller and its master')
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    paths = sorted(args.packages.glob('Z7_2_*.bin'))
    require(paths, 'No Z7 II update packages found')
    master = args.master.read_bytes()
    validate_master(master)
    signature = None
    if args.transport_reference:
        reference = args.transport_reference.read_bytes()
        require(digest(reference) == PROFILES['slave'].sha256, 'Expected original C 1.70 slave EG')
        signature = reference[0x40f7e - 10:0x40f7e + 12]
    report = dict(qemu_version=subprocess.check_output([args.qemu, '--version'],
                  text=True).splitlines()[0], member_and_container_crcs_checked=True,
                  package_signature_checked=False, full_boot_verified=False,
                  scope='Independent core-zero engine reset through the call to system initialization.',
                  dual_transport_requested=bool(signature),
                  packages=[run_package(path, master, args.qemu, signature, args.controller_link)
                            for path in paths])
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
