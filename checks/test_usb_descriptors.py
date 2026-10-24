# SPDX-License-Identifier: GPL-2.0-or-later
"""Firmware-free checks for the USB descriptor personality parser."""
import struct
import unittest

from analyze.firmware_structure import BASE
from analyze.usb_descriptors import (VENDOR_ID, PRODUCT_ID, boot_ram_address,
                                     find_descriptor_clusters, parse_companion,
                                     parse_descriptor_set, parse_device,
                                     parse_endpoint, parse_string,
                                     usb_personalities)


def device(bcd=0x0210, cls=0, sub=0, prot=0, max0=0x40, vid=VENDOR_ID,
           pid=PRODUCT_ID, release=0x0100, strings=(1, 2, 3)):
    return (bytes([18, 1]) + struct.pack('<H', bcd) +
            bytes([cls, sub, prot, max0]) + struct.pack('<3H', vid, pid, release) +
            bytes([*strings, 1]))


def config(total, interfaces=1, attributes=0x80, power=0xFA):
    return bytes([9, 2]) + struct.pack('<H', total) + bytes(
        [interfaces, 1, 0, attributes, power])


def interface(cls, sub, prot, count):
    return bytes([9, 4, 0, 0, count, cls, sub, prot, 0])


def endpoint(address, transfer=2, max_packet=512, interval=0):
    return bytes([7, 5, address, transfer]) + struct.pack('<H', max_packet) + bytes([interval])


def qualifier(bcd=0x0210, max0=0x40):
    return bytes([10, 6]) + struct.pack('<H', bcd) + bytes([0, 0, 0, max0, 1])


def utf16(text):
    body = text.encode('utf-16-le')
    return bytes([2 + len(body), 3]) + body


def vendor_set(max_packet=512):
    body = (config(9 + 9 + 14) + interface(0xFF, 0xF0, 0, 2) +
            endpoint(0x81, 2, max_packet) + endpoint(0x02, 2, max_packet))
    return device() + body + b'\x00' * 12


def still_image_set(bcd, max_packet, interrupt, companion=False):
    endpoints = endpoint(0x81, 2, max_packet) + endpoint(0x02, 2, max_packet)
    if companion:
        endpoints += endpoint(0x83, 3, interrupt, 10) + bytes([6, 0x30, 15, 0, 0, 0])
    else:
        endpoints += endpoint(0x83, 3, interrupt, 9)
    body = config(9 + 9 + len(endpoints)) + interface(6, 1, 1, 3) + endpoints
    return device(bcd=bcd, max0=9 if bcd == 0x0320 else 0x40) + body + b'\x00' * 12


def synthetic_image():
    cluster_a = vendor_set() + vendor_set() + vendor_set()
    strings = utf16('NIKON') + utf16('NIKON DSC Z 7_2')
    cluster_b = (still_image_set(0x0210, 64, 8) + still_image_set(0x0210, 512, 8) +
                 still_image_set(0x0320, 1024, 24, companion=True))
    blob = (b'\x00' * 0x300 + cluster_a + strings + b'\x00' * 0x100 +
            cluster_b + b'\x00' * 0x100)
    image = bytearray(0x2000)
    image[0x400:0x400 + len(blob)] = blob
    return bytes(image)


class DeviceParsing(unittest.TestCase):
    def test_parses_identity_and_versions(self):
        parsed = parse_device(device(bcd=0x0320, vid=0x1234, pid=0x5678))
        self.assertEqual(parsed['usb_version'], '03.20')
        self.assertEqual(parsed['vendor_id'], 0x1234)
        self.assertEqual(parsed['product_id'], 0x5678)
        self.assertEqual(parsed['string_indices'], (1, 2, 3))

    def test_rejects_short_or_foreign_headers(self):
        with self.assertRaises(ValueError):
            parse_device(b'\x12\x01\x00')
        with self.assertRaises(ValueError):
            parse_device(device()[:17])
        with self.assertRaises(ValueError):
            parse_device(bytes([9, 2]) + b'\x00' * 16)


class EndpointParsing(unittest.TestCase):
    def test_bulk_endpoint_fields(self):
        parsed = parse_endpoint(endpoint(0x81, 2, 512))
        self.assertEqual((parsed['direction'], parsed['transfer']), ('in', 'bulk'))
        self.assertEqual((parsed['max_packet'], parsed['companion']), (512, None))

    def test_super_speed_companion_attaches(self):
        target = parse_endpoint(endpoint(0x81, 2, 1024))
        parse_companion(bytes([6, 0x30, 15, 0, 24, 0]), target)
        self.assertEqual(target['companion'], dict(max_burst=15, attributes=0,
                                                   bytes_per_interval=24))


class SetWalking(unittest.TestCase):
    def test_walks_chained_descriptors_and_stops_at_padding(self):
        image = synthetic_image()
        start = find_descriptor_clusters(image)[0][0]
        parsed = parse_descriptor_set(image, start)
        self.assertEqual(len(parsed['interfaces']), 1)
        endpoints = parsed['interfaces'][0]['endpoints']
        self.assertEqual([e['address'] for e in endpoints], [0x81, 0x02])
        self.assertEqual(parsed['configurations'][0]['interface_count'], 1)

    def test_rejects_unexpected_identity(self):
        image = bytearray(0x400)
        blob = device(vid=0xFFFF) + config(32) + interface(1, 1, 1, 0)
        image[0x100:0x100 + len(blob)] = blob
        with self.assertRaises(ValueError):
            parse_descriptor_set(bytes(image), 0x100)


class ClusterSearch(unittest.TestCase):
    def test_groups_two_personalities(self):
        clusters = find_descriptor_clusters(synthetic_image())
        self.assertEqual([len(c) for c in clusters], [3, 3])
        self.assertLess(clusters[0][0], clusters[1][0])

    def test_boot_ram_address_maps_through_copy_records(self):
        image = synthetic_image()
        first = find_descriptor_clusters(image)[0][0]
        records = [dict(kind='copy', source=BASE + 0x400, destination=0xB1800000,
                        size=0x1000, handler=0)]
        self.assertEqual(boot_ram_address(records, first), 0xB1800000 + first - 0x400)
        self.assertIsNone(boot_ram_address(records, 0x2000))


class Personalities(unittest.TestCase):
    def test_validates_both_stock_personalities(self):
        described = usb_personalities(synthetic_image())
        self.assertEqual(described['vendor_bulk']['interface_classes'], ['ff/f0/00'])
        self.assertEqual(described['still_image']['interface_classes'], ['06/01/01'])
        self.assertEqual(described['still_image']['device_versions'], ['02.10', '03.20'])
        self.assertEqual(described['still_image']['bulk_max_packets'], [64, 512, 1024])
        self.assertIn('NIKON DSC Z 7_2', described['vendor_bulk']['nearby_strings'])
        self.assertTrue(described['still_image']['super_speed_companions'])

    def test_rejects_wrong_endpoint_count(self):
        image = bytearray(synthetic_image())
        # Drop the second bulk endpoint from every vendor set.
        for start in find_descriptor_clusters(bytes(image))[0]:
            image[start + 18 + 9 + 9 + 7:start + 18 + 9 + 9 + 14] = b'\x00' * 7
        with self.assertRaises(ValueError):
            usb_personalities(bytes(image), None)

    def test_rejects_missing_super_speed_variant(self):
        image = bytearray(synthetic_image())
        cluster = find_descriptor_clusters(bytes(image))[1]
        start = cluster[2]
        image[start:start + 18] = b'\x00' * 18
        with self.assertRaises(ValueError):
            usb_personalities(bytes(image), None)

    def test_rejects_foreign_product_strings(self):
        image = bytearray(synthetic_image())
        marker = b'N\x00I\x00K\x00O\x00N\x00 \x00D\x00'
        position = bytes(image).find(marker)
        image[position] = ord('X')
        with self.assertRaises(ValueError):
            usb_personalities(bytes(image), None)


class StringDecoding(unittest.TestCase):
    def test_decodes_utf16_text(self):
        parsed = parse_string(utf16('NIKON DSC Z 7_2'))
        self.assertEqual(parsed['text'], 'NIKON DSC Z 7_2')

    def test_rejects_malformed_strings(self):
        with self.assertRaises(ValueError):
            parse_string(b'\x08\x03N\x00I')


if __name__ == '__main__':
    unittest.main()
