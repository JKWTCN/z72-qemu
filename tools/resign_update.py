# SPDX-License-Identifier: GPL-2.0-or-later
"""Rebuild a vendor update package from its decoded container.

Round-trip proof, not a camera operation: decode the original body, split it
into members, repack it with analyze.update_container.pack_container (fresh
directory, member CRCs and trailer), require the rebuilt body to be
byte-identical, re-encode the payload with the in-image tables and recompute
the whole-file SHA-1 with the locally supplied boot key.

The boot key never enters this repository: pass it as --material, either
eight raw bytes or a JSON file carrying a "b8_boot_key"/"boot_key" hex field
(or a "k8_appended"/"appended_key" hex field, converted with the derived
stream). Output reports equality booleans only; the rebuilt package lands
at --output for offline inspection or later custom builds.

Expected result against a stock file with the correct key: the rebuilt
package is byte-identical to the original, including the digest header.
"""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import digest, require, validate_master
from analyze.update_container import describe_container, pack_container
from analyze.upgrade_signature import (HEADER_LENGTH, encode, key_stream,
                                       update_digest, verify_update)


def load_boot_key(material, master):
    """Read eight key bytes from a private local file; never print them."""
    raw = material.read_bytes()
    if len(raw) == 8:
        return raw
    require(raw[:1] == b'{', 'Material file must be 8 raw bytes or JSON')
    fields = json.loads(raw)
    for name in ('b8_boot_key', 'boot_key'):
        if isinstance(fields.get(name), str):
            return bytes.fromhex(fields[name])
    for name in ('k8_appended', 'appended_key'):
        if isinstance(fields.get(name), str):
            appended = bytes.fromhex(fields[name])
            return bytes(a ^ b for a, b in zip(appended, key_stream(master)))
    raise ValueError('Material JSON lacks a boot_key/k8 hex field')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--original', type=Path, required=True)
    parser.add_argument('--material', type=Path, required=True,
                        help='private local file: 8 raw bytes or JSON hex field')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()

    master = args.master.read_bytes()
    validate_master(master)
    original = args.original.read_bytes()
    require(len(original) > HEADER_LENGTH * 2 + 0x30, 'Package is too short')
    require(original[HEADER_LENGTH:HEADER_LENGTH * 2] == b' ' * HEADER_LENGTH,
            'Package lacks the marked body prefix')

    from analyze.upgrade_signature import decode
    body = original[HEADER_LENGTH:HEADER_LENGTH * 2] + \
        decode(master, original[HEADER_LENGTH * 2:], HEADER_LENGTH)
    described = describe_container(body)

    entries = []
    for member in described['members']:
        start, size = member['offset'], member['length']
        entries.append((member['name'].encode('ascii'), body[start:start + size - 2]))
    rebuilt = pack_container(entries)
    require(rebuilt == body, 'Repacked body differs from the decoded original')

    payload = encode(master, rebuilt[HEADER_LENGTH:], HEADER_LENGTH)
    boot_key = load_boot_key(args.material, master)
    package_digest = update_digest(original[HEADER_LENGTH:HEADER_LENGTH * 2],
                                   payload, boot_key, master)
    result = package_digest + original[20:HEADER_LENGTH] + \
        rebuilt[:HEADER_LENGTH] + payload
    require(not args.output.exists(), 'Output file already exists')
    args.output.write_bytes(result)

    verify_update(result, boot_key, master)
    report = dict(
        output=str(args.output),
        packer_round_trip=True,
        rebuilt_body_identical=rebuilt == body,
        digest_matches_original_header=package_digest == original[:20],
        package_identical=digest(result) == digest(original),
        output_sha256=digest(result),
        original_sha256=digest(original),
        verify_update_passed=True,
        members=[dict(name=m['name'], bytes=m['length']) for m in described['members']])
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, RuntimeError, OSError) as error:
        print('Update rebuild failed: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
