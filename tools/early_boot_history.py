# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute each local update's two engine reset paths through early configuration."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import digest, require, validate_master
from analyze.firmware_structure import PROFILES, boot_prefix, branch_target
from analyze.update_container import describe_container
from analyze.update_store import image_version
from analyze.upgrade_signature import decode
from tools.boot_probe import reset_machine
from tools.early_boot_probe import trace_early


def run_package(path, master, qemu):
    raw = path.read_bytes()
    body = raw[32:64] + decode(master, raw[64:], 32)
    members = describe_container(body)['members']
    engines = []
    for role, tag in (('master', 'mas'), ('slave', 'sla')):
        matches = [m for m in members if m['name'].startswith(f'eg1840_{tag}_')]
        require(len(matches) == 1, f'{path.name}: expected one {role} engine')
        member = matches[0]
        start = member['offset']
        image = body[start:start + member['length']]
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
    return dict(package=path.name, sha256=digest(raw), engines=engines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--packages', required=True, type=Path)
    parser.add_argument('--master', required=True, type=Path, help='Original C 1.70 master EG')
    parser.add_argument('--qemu', required=True)
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    paths = sorted(args.packages.glob('Z7_2_*.bin'))
    require(paths, 'No Z7 II update packages found')
    master = args.master.read_bytes()
    validate_master(master)
    report = dict(qemu_version=subprocess.check_output([args.qemu, '--version'],
                  text=True).splitlines()[0], member_and_container_crcs_checked=True,
                  package_signature_checked=False, full_boot_verified=False,
                  scope='Independent core-zero engine reset through the call to system initialization.',
                  packages=[run_package(path, master, args.qemu) for path in paths])
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
