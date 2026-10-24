# SPDX-License-Identifier: GPL-2.0-or-later
"""Read a fixed checksum-context snapshot through the nested PTP service.

The transaction set contains identity, service entry/exit and one fixed RAM
read. No update or programming operation is sent.
"""
import hashlib
import struct

from analyze.decode_z72 import BASE, digest, require
from analyze.upgrade_signature import appended_key, decode, key_stream
from analyze.update_container import describe_container

CONTEXT = 0xB2B422C8
CONTEXT_SIZE = 0x34
CALLBACK = BASE + 0x37C635
TRANSFORMED_SEED = 0xB4FBFFFF


def parameters(command, *args):
    return [command, *args, *([0] * (4 - len(args)))]


def response_ok(response, allowed=(0x2001,)):
    outer, values = response
    require(outer == 0x2001 and bool(values) and values[0] in allowed,
            'Nested service response failed: ' + repr(response))


def identity(data):
    """Parse public DeviceInfo identity; do not return its serial number."""
    offset = 0

    def take(size):
        nonlocal offset
        require(size >= 0 and offset + size <= len(data), 'Truncated DeviceInfo')
        value = data[offset:offset + size]
        offset += size
        return value

    def number(fmt):
        return struct.unpack(fmt, take(struct.calcsize(fmt)))[0]

    def string():
        return take(number('<B') * 2).decode('utf-16-le').rstrip('\0')

    take(8)
    string()
    take(2)
    for _ in range(5):
        count = number('<I')
        require(count <= 16384, 'Excessive DeviceInfo array length')
        take(count * 2)
    manufacturer, model, version = string(), string(), string()
    string()
    require(offset == len(data), 'Trailing DeviceInfo data')
    require(manufacturer == 'Nikon Corporation' and model == 'Z 7_2' and version == 'V1.70',
            'Requires Z7 II C 1.70')
    return dict(manufacturer=manufacturer, model=model, version=version)


def capture(camera):
    data, reply = camera.read(0x1001, [])
    require(reply[0] == 0x2001, 'DeviceInfo failed')
    camera_identity = identity(data)
    # Always attempt exit after entry was sent, including ambiguous failures.
    error = None
    try:
        response_ok(camera.send(0x94FD, parameters(0xF001)), allowed=(0x2001, 0x201E))
        context, reply = camera.read(0x94FF, parameters(0xF032, CONTEXT, CONTEXT_SIZE))
        response_ok(reply)
        require(len(context) == CONTEXT_SIZE, 'Checksum context read was incomplete')
    except BaseException as exc:
        error = exc
        raise
    finally:
        try:
            response_ok(camera.send(0x94FE, parameters(0xF002)))
        except Exception as exc:
            if error is None:
                raise
            error.add_note('Service exit also failed: ' + str(exc))
    return bytes(context), camera_identity


def inspect_context(context, package, master):
    """Authenticate a retained candidate against the supplied original package.

    Return private material separately; it must not enter a public report.
    Matching a snapshot does not establish how its update was triggered.
    """
    require(len(context) == CONTEXT_SIZE, 'Expected a 52-byte checksum context')
    require(len(package) > 64, 'Package is too short')
    body = package[32:64] + decode(master, package[64:], 32)
    describe_container(body)
    pointer, length, callback, material, seed, model, expected = struct.unpack('<III8sI8s20s', context)
    phase = 'raw' if seed == 0x44B else 'transformed' if seed == TRANSFORMED_SEED else 'unknown'
    report = dict(context_sha256=digest(context), body_pointer=pointer,
                  body_length=length, callback=callback, seed=seed,
                  phase=phase, package_sha256=digest(package),
                  package_header_matches_context=expected == package[:20],
                  context_binding_valid=False, package_digest_verified=False,
                  material_recovered=False)
    bound = (pointer != 0 and callback == CALLBACK and model == b'Z_7_2\0\0\0' and
             phase != 'unknown' and expected == package[:20] and
             length == len(body) + (8 if phase == 'transformed' else 0))
    report['context_binding_valid'] = bound
    if not bound:
        return report, None
    final = appended_key(material, master) if phase == 'raw' else material
    matched = hashlib.sha1(body + final).digest() == package[:20]
    report['package_digest_verified'] = report['material_recovered'] = matched
    if not matched:
        return report, None
    raw = bytes(a ^ b for a, b in zip(final, key_stream(master)))
    report['material_sha256'] = digest(final)
    return report, dict(boot_key=raw.hex(), appended_key=final.hex())
