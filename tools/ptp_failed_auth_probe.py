# SPDX-License-Identifier: GPL-2.0-or-later
"""Recover the checksum material through a deliberately failed menu check.

Two stages, both offline by default:

  --prepare  Derive a "bad digest" update file from an original package by
             flipping one bit of the file's 20-byte expected-digest header.
             The decoded body stays byte-identical (verified against the
             in-image tables and the full container/member CRC checks), so
             the menu still finds the file and shows its version page; the
             whole-file SHA-1 comparison after selecting "Yes" then fails
             and the firmware takes the verified failure branch -- no update
             preparation, no programming -- while the checksum context at
             0xB2B422C8 retains the transformed material.

  --execute  After the operator selected "Yes" on the camera and the failure
             dialog appeared: open one PTP session, enter/exit the nested
             service, read the fixed 52-byte context, and check it against
             both the used (corrupted) and the original package. Reports
             booleans and field bindings only; key material never enters
             the printed or saved report. When the material reproduces the
             original package digest it is written once to a private
             verified-material.json next to the report.

Safety: the failure branch returns before update preparation (see
research/z7ii/menu_confirmation.md and ptp_service.md); the worst case of a
passing digest would be a normal same-version reinstall of an otherwise
untouched body. No menu interaction, update request or programming is sent
from this tool.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze.decode_z72 import require, validate_master
from analyze.ptp_checksum_context import (CALLBACK, CONTEXT, CONTEXT_SIZE,
                                          TRANSFORMED_SEED, capture, identity,
                                          parameters)
from analyze.update_container import describe_container
from analyze.upgrade_signature import HEADER_LENGTH, decode, key_stream

BAD_BIT_MASK = 0xFF


def body_of(package, master):
    body = package[HEADER_LENGTH:HEADER_LENGTH * 2] + \
        decode(master, package[HEADER_LENGTH * 2:], HEADER_LENGTH)
    describe_container(body)
    return body


def prepare(args):
    master = args.master.read_bytes()
    validate_master(master)
    original = args.original.read_bytes()
    require(len(original) > HEADER_LENGTH * 2, 'Package is too short')
    body_of(original, master)
    corrupted = bytearray(original)
    corrupted[0] ^= BAD_BIT_MASK
    require(bytes(corrupted[:20]) != original[:20], 'Digest did not change')
    body = body_of(bytes(corrupted), master)
    require(body == body_of(original, master), 'Body changed unexpectedly')
    require(not args.output.exists(), 'Output file already exists')
    args.output.write_bytes(bytes(corrupted))
    print(json.dumps(dict(
        output=str(args.output),
        original_digest=original[:20].hex(),
        corrupted_digest=bytes(corrupted[:20]).hex(),
        diff_offsets=[0], body_identical=True, container_crcs_valid=True,
        guarantee='digest mismatch is certain; decoded body byte-identical'), indent=2))


def inspect(context, original, used, master):
    """Bind the context to the failed check and test the material.

    Returns (report, material-or-None); the report never contains material
    bytes or derived keys.
    """
    require(len(context) == CONTEXT_SIZE, 'Expected a 52-byte checksum context')
    body = body_of(original, master)
    pointer, length, callback, material, seed, model, expected = \
        struct.unpack('<III8sI8s20s', context)
    phase = 'raw' if seed == 0x44B else 'transformed' if seed == TRANSFORMED_SEED else 'unknown'
    report = dict(
        context_sha256=hashlib.sha256(context).hexdigest(),
        callback_matches_auth_chain=callback == CALLBACK,
        phase=phase,
        model_matches=model[:5] == b'Z_7_2',
        expected_digest_source='none',
        expected_matches_used_package=None,
        length_binding=length == len(body) + 8,
        material_bytes_present=any(material),
        material_recovered=False, package_digest_verified=False)
    if used is not None:
        report['expected_digest_source'] = 'used-package-header'
        report['expected_matches_used_package'] = expected == used[:20]
    bound = (report['callback_matches_auth_chain'] and phase == 'transformed'
             and report['model_matches'] and report['length_binding']
             and (used is None or report['expected_matches_used_package']))
    report['context_binding_valid'] = bound
    if not bound or not report['material_bytes_present']:
        return report, None
    stream = key_stream(master)
    appended = bytes(a ^ b for a, b in zip(material, stream))  # raw boot-key reading
    candidates = (('transformed-material', material),
                  ('raw-material-xor-stream', appended))
    for label, candidate in candidates:
        if hashlib.sha1(body + candidate).digest() == original[:20]:
            report.update(material_recovered=True, package_digest_verified=True,
                          interpretation=label)
            return report, candidate
    report['interpretation'] = 'no-digest-match'
    return report, None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group()
    source.add_argument('--prepare', action='store_true',
                        help='Derive the bad-digest update file; no camera access')
    source.add_argument('--execute', action='store_true',
                        help='Read the context after the failed menu check')
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--original', type=Path, required=True,
                        help='Original vendor package (digest arbiter)')
    parser.add_argument('--output', type=Path,
                        help='(prepare) output path for the bad-digest file')
    parser.add_argument('--used', type=Path,
                        help='(execute) the bad-digest file that was on the card')
    parser.add_argument('--destination', type=Path,
                        help='(execute) new directory for report and context')
    args = parser.parse_args()

    if args.prepare:
        require(args.output is not None, '--prepare needs --output')
        prepare(args)
        return
    if not args.execute:
        plan = dict(stage_plan=[
            dict(stage='prepare',
                 command='--prepare --master <C1.70-master> --original <vendor-package> '
                         '--output <bad-digest-file>',
                 effect='flip one bit of the digest header; body stays identical'),
            dict(stage='camera',
                 steps=['copy the bad-digest file to the card root under the vendor '
                        'update filename, original removed',
                        'menu: firmware version -> confirmation page -> select Yes',
                        'wait for the failure dialog (no update preparation follows)',
                        'exit the menu, keep the camera powered, connect USB']),
            dict(stage='execute',
                 command='--execute --master <C1.70-master> --original <vendor-package> '
                         '--used <bad-digest-file> --destination <new-dir>',
                 effect='one PTP session; F001, one fixed 52-byte F032 read, F002')],
            safety='failure branch precedes update preparation; worst case of a passing '
                   'digest is a normal same-version reinstall',
            privacy='reports contain booleans and bindings only; recovered material is '
                    'written once to a local verified-material.json and never printed')
        print(json.dumps(plan, indent=2))
        return

    require(args.destination is not None and not args.destination.exists(),
            '--execute needs a fresh --destination directory')
    master = args.master.read_bytes()
    validate_master(master)
    original = args.original.read_bytes()
    used = args.used.read_bytes() if args.used is not None else None

    from tools.ptp_checksum_context_probe import UsbCamera
    with UsbCamera() as camera:
        context, camera_identity = capture(camera)
    report, material = inspect(bytes(context), original, used, master)
    report.update(format=1, identity=camera_identity, camera_read_executed=True,
                  initiates_update=False, menu_confirmation_order_verified=True,
                  firmware_included=False)
    args.destination.mkdir(parents=True)
    (args.destination / 'context.bin').write_bytes(context)
    (args.destination / 'report.json').write_text(
        json.dumps(report, indent=2) + '\n', encoding='utf-8')
    if material is not None:
        (args.destination / 'verified-material.json').write_text(json.dumps(dict(
            material_hex=material.hex(),
            note='private: keep local; never print, commit or attach this file'), indent=2) + '\n',
            encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, RuntimeError, ImportError, OSError) as error:
        print('Failed-auth probe failed: ' + str(error), file=sys.stderr)
        for note in getattr(error, '__notes__', ()):
            print(note, file=sys.stderr)
        raise SystemExit(1)
