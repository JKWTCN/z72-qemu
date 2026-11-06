# SPDX-License-Identifier: GPL-2.0-or-later
"""Exercise historical engine reset paths and optionally the dual-engine message ring."""
import argparse
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import BASE, digest, require, validate_master
from analyze.firmware_structure import PROFILES, boot_prefix, branch_target
from analyze.update_container import describe_container
from analyze.update_store import image_version
from analyze.upgrade_signature import decode
from tools.boot_probe import reset_machine
from tools.dual_boot_probe import MASTER_MAGIC, MASTER_MSG, dual_machine
from tools.early_boot_probe import trace_early
from tools.smp_boot_probe import reach


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
            return dict(receiver_offset=offset, receiver_thread=thread,
                        written=written, consumed=consumed, alias_header_matches=True)
        finally:
            remote.sock.close()
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def run_package(path, master, qemu, signature=None):
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
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--packages', required=True, type=Path)
    parser.add_argument('--master', required=True, type=Path, help='Original C 1.70 master EG')
    parser.add_argument('--transport-reference', type=Path,
                        help='Original C 1.70 slave EG for the dual-engine receiver check')
    parser.add_argument('--qemu', required=True)
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
                  packages=[run_package(path, master, args.qemu, signature) for path in paths])
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
