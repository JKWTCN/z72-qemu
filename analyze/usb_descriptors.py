# SPDX-License-Identifier: GPL-2.0-or-later
"""USB device descriptor personalities recovered from the boot data block.

Firmware analysis identified two complete USB descriptor personalities that
the startup copy of the master image places into RAM: a vendor-class bulk
personality (interface class 0xFF/0xF0, two bulk endpoints) and a
still-image personality (interface class 0x06/0x01/0x01, two bulk endpoints
plus one interrupt-in endpoint) with full-speed, high-speed and super-speed
variants. Both use vendor id 0x04B0, product id 0x044B and the product
string "NIKON DSC Z 7_2". The serial-number string slot exists but carries
no stock content, so a runtime value is expected there.

Descriptor bytes stay in the original firmware; only parsed fields are
reproduced here.
"""
import argparse
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze.decode_z72 import require
from analyze.firmware_structure import BASE, scatter_records

VENDOR_ID = 0x04B0
PRODUCT_ID = 0x044B

TYPE_DEVICE = 0x01
TYPE_CONFIGURATION = 0x02
TYPE_STRING = 0x03
TYPE_INTERFACE = 0x04
TYPE_ENDPOINT = 0x05
TYPE_QUALIFIER = 0x06
TYPE_OTHER_SPEED = 0x07
TYPE_CAPABILITY = 0x10
TYPE_COMPANION = 0x30

_ENDPOINT_TYPES = {0: 'control', 1: 'isochronous', 2: 'bulk', 3: 'interrupt'}


def parse_device(blob):
    require(len(blob) >= 18 and blob[0] == 18 and blob[1] == TYPE_DEVICE,
            'Malformed device descriptor')
    bcd, = struct.unpack_from('<H', blob, 2)
    vid, pid, release = struct.unpack_from('<3H', blob, 8)
    return dict(kind='device', usb_version=f'{bcd >> 8:02x}.{bcd & 0xFF:02x}',
                class_code=blob[4], subclass=blob[5], protocol=blob[6],
                max_packet_zero=blob[7], vendor_id=vid, product_id=pid,
                release=f'{release >> 8:04x}.{release & 0xFF:04x}',
                string_indices=(blob[14], blob[15], blob[16]),
                configuration_count=blob[17])


def parse_string(blob):
    require(len(blob) >= 4 and blob[0] == len(blob) and blob[1] == TYPE_STRING,
            'Malformed string descriptor')
    return dict(kind='string', raw=blob[:blob[0]],
                text=blob[2:blob[0]].decode('utf-16-le', 'replace'))


def parse_endpoint(blob):
    require(len(blob) >= 7 and blob[0] >= 7 and blob[1] == TYPE_ENDPOINT,
            'Malformed endpoint descriptor')
    max_packet, = struct.unpack_from('<H', blob, 4)
    return dict(address=blob[2], direction='in' if blob[2] & 0x80 else 'out',
                number=blob[2] & 0xF, transfer=_ENDPOINT_TYPES[blob[3] & 3],
                max_packet=max_packet, interval=blob[6], companion=None)


def parse_companion(blob, endpoint):
    """Attach a super-speed endpoint companion following its endpoint."""
    require(len(blob) >= 6 and blob[0] == 6 and blob[1] == TYPE_COMPANION,
            'Malformed companion descriptor')
    per_interval, = struct.unpack_from('<H', blob, 4)
    endpoint['companion'] = dict(max_burst=blob[2], attributes=blob[3],
                                 bytes_per_interval=per_interval)


def _parse_interface(blob):
    require(len(blob) >= 9 and blob[0] >= 9 and blob[1] == TYPE_INTERFACE,
            'Malformed interface descriptor')
    return dict(kind='interface', number=blob[2], alternate=blob[3],
                class_code=blob[5], subclass=blob[6], protocol=blob[7],
                string_index=blob[8])


def parse_descriptor_set(image, start):
    """Walk one bLength-chained descriptor sequence starting at `start`.

    The sequence ends before the first byte that is not a known descriptor
    header; padding between repeated sets is therefore skipped naturally.
    """
    require(0 <= start < len(image) - 18, 'Descriptor set outside firmware')
    device = parse_device(image[start:start + 18])
    require(device['vendor_id'] == VENDOR_ID and device['product_id'] == PRODUCT_ID,
            'Unexpected device identity')
    position = start + 18
    configurations, interfaces = [], []
    pending, endpoints = None, []
    while position + 2 <= len(image) - 2:

        def flush():
            if pending is not None:
                interfaces.append(dict(pending, endpoints=endpoints))
        length, kind = image[position], image[position + 1]
        if not length or kind not in (TYPE_CONFIGURATION, TYPE_STRING, TYPE_INTERFACE,
                                      TYPE_ENDPOINT, TYPE_QUALIFIER, TYPE_OTHER_SPEED,
                                      TYPE_CAPABILITY, TYPE_COMPANION):
            break
        require(position + length <= len(image) - 2, 'Truncated descriptor')
        blob = image[position:position + length]
        if kind == TYPE_CONFIGURATION:
            total, = struct.unpack_from('<H', blob, 2)
            configurations.append(dict(kind='configuration', total_length=total,
                                       interface_count=blob[4], attributes=blob[7],
                                       attributes_self_powered=bool(blob[7] & 0x40),
                                       attributes_remote_wakeup=bool(blob[7] & 0x20),
                                       max_power_units=blob[8]))
        elif kind == TYPE_ENDPOINT:
            endpoints.append(parse_endpoint(blob))
        elif kind == TYPE_COMPANION:
            require(endpoints, 'Companion descriptor without an endpoint')
            parse_companion(blob, endpoints[-1])
        elif kind == TYPE_INTERFACE:
            flush()
            pending, endpoints = _parse_interface(blob), []
        elif kind in (TYPE_QUALIFIER, TYPE_OTHER_SPEED, TYPE_CAPABILITY):
            if kind == TYPE_QUALIFIER:
                bcd, = struct.unpack_from('<H', blob, 2)
                entry = dict(kind='qualifier', usb_version=f'{bcd >> 8:02x}.{bcd & 0xFF:02x}',
                             max_packet_zero=blob[7])
            else:
                entry = dict(kind='other_speed' if kind == TYPE_OTHER_SPEED else 'capability',
                             raw=blob.hex())
            configurations.append(entry)
        elif kind == TYPE_STRING:
            configurations.append(parse_string(blob))
        position += length
    flush()
    # Each repetition combines one device descriptor with its configuration,
    # qualifier and other-speed variants in a single bLength chain.
    return dict(offset=start, device=device, configurations=configurations,
                interfaces=interfaces, descriptor_end=position)


def find_descriptor_clusters(image, gap=0x60):
    """Group device descriptor repetitions into clusters by proximity."""
    clusters, current = [], []
    for position in range(0, len(image) - 18):
        if image[position] != 18 or image[position + 1] != TYPE_DEVICE:
            continue
        if struct.unpack_from('<H', image, position + 8)[0] != VENDOR_ID:
            continue
        if current and position - current[-1] > gap:
            clusters.append(current)
            current = []
        current.append(position)
    if current:
        clusters.append(current)
    return clusters


def boot_ram_address(records, file_offset):
    """Map a member file offset to its startup-copied RAM address."""
    for record in records:
        if record['kind'] != 'copy':
            continue
        start = record['source'] - BASE
        if start <= file_offset < start + record['size']:
            return record['destination'] + file_offset - start
    return None


def _personality_summary(image, starts, ram_records):
    sets = [parse_descriptor_set(image, start) for start in starts]
    interfaces = [interface for item in sets for interface in item['interfaces']]
    classes = sorted({(i['class_code'], i['subclass'], i['protocol']) for i in interfaces})
    endpoints = [endpoint for i in interfaces for endpoint in i['endpoints']]
    transfers = sorted({endpoint['transfer'] for endpoint in endpoints})
    speeds = sorted({item['device']['usb_version'] for item in sets})
    strings = {}
    window_start, window_end = starts[0], starts[-1] + 0x400
    position = window_start
    while position + 4 <= min(window_end, len(image) - 2):
        if image[position + 1] == TYPE_STRING and 4 <= image[position] <= 0xFF and \
                (image[position] & 1) == 0:
            try:
                text = parse_string(image[position:position + image[position]])
            except ValueError:
                position += 2
                continue
            if text['text'].isprintable() and text['text'].isascii() and text['text']:
                strings.setdefault(text['text'], hex(position))
                position += image[position]
                continue
        position += 2
    first_ram = boot_ram_address(ram_records, starts[0]) if ram_records else None
    return dict(file_offset=hex(starts[0]), repetition_count=len(starts),
                ram_address=hex(first_ram) if first_ram else None,
                interface_classes=[f'{c:02x}/{s:02x}/{p:02x}' for c, s, p in classes],
                device_versions=speeds,
                endpoint_transfers=transfers,
                endpoint_addresses=sorted({f"0x{e['address']:02x}" for e in endpoints}),
                bulk_max_packets=sorted({e['max_packet'] for e in endpoints
                                         if e['transfer'] == 'bulk'}),
                interrupt_max_packets=sorted({e['max_packet'] for e in endpoints
                                              if e['transfer'] == 'interrupt'}),
                super_speed_companions=any(e['companion'] for e in endpoints),
                nearby_strings=strings, sets=sets)


def usb_personalities(image, ram_records=None):
    """Describe and validate the two stock USB descriptor personalities."""
    clusters = find_descriptor_clusters(image)
    require(len(clusters) == 2, 'Expected two USB descriptor clusters')
    vendor = _personality_summary(image, clusters[0], ram_records)
    still_image = _personality_summary(image, clusters[1], ram_records)
    require(vendor['interface_classes'] == ['ff/f0/00'],
            'Unexpected vendor personality class')
    require(all(len(i['endpoints']) == 2 for i in
                [f for s in vendor['sets'] for f in s['interfaces']]),
            'Vendor personality must expose two endpoints per interface')
    require(still_image['interface_classes'] == ['06/01/01'],
            'Unexpected still-image personality class')
    require(all(len(i['endpoints']) == 3 for i in
                [f for s in still_image['sets'] for f in s['interfaces']]),
            'Still-image personality must expose three endpoints per interface')
    require('NIKON DSC Z 7_2' in vendor['nearby_strings'], 'Product string missing')
    require('03.20' in still_image['device_versions'], 'Super-speed variant missing')
    return dict(vendor_bulk=vendor, still_image=still_image,
                vendor_id=f'0x{VENDOR_ID:04x}', product_id=f'0x{PRODUCT_ID:04x}',
                serial_string_stock_content=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True, help='New JSON file')
    args = parser.parse_args()
    image = args.master.read_bytes()
    try:
        report = dict(format=1, offset_space='decoded_member_file',
                      personalities=usb_personalities(image, scatter_records(image)))
    except ValueError as error:
        parser.exit(1, f'Error: {error}\n')
    args.report.parent.mkdir(parents=True, exist_ok=True)
    with args.report.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print('PASS two USB descriptor personalities:', args.report)


if __name__ == '__main__':
    main()
