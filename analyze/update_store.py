# SPDX-License-Identifier: GPL-2.0-or-later
"""Accept, store and describe console-installed master firmware updates.

The stock menu firmware-update path scans the memory card through services
this laboratory does not model, so the console completes an update through
an explicit experimental storage directory instead. A candidate master
image is accepted only when it keeps the verified boot structure (version
record, reset branch, initialization table, communication window and boot
prefix); the stock-only digests of research probes deliberately do not
apply here because an update may legitimately change those bytes. The
installed manifest is the local trust anchor: later boots re-verify the
stored image against it before loading.
"""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re

from analyze.decode_z72 import BASE, crc, digest, require
from analyze.firmware_structure import (PROFILES, boot_prefix, branch_target,
                                        communication_header, scatter_records)

MANIFEST_FORMAT = 1
VERSION_PATTERN = re.compile(rb'Ver\.\d{2}\.\d{2}\.\d{2}')
# The master window ends at 0x14000000; the image starts at BASE.
MAXIMUM_LENGTH = 0x14000000 - BASE


def image_version(image):
    """Return the twelve-byte version record at file offset 0x20."""
    version = bytes(image[0x20:0x2C])
    require(VERSION_PATTERN.fullmatch(version) is not None,
            'Expected a Ver.xx.xx.xx record at offset 0x20')
    return version.decode('ascii')


def installable_master(image):
    """Describe a master image acceptable for installation.

    Checks the structure the machine actually executes during boot. The
    whole-image digest is returned so the manifest can pin it; stock-only
    bindings and display-window digests are intentionally not required.
    """
    profile = PROFILES['master']
    require(profile.size <= len(image) <= MAXIMUM_LENGTH,
            'Updated master length is outside the master memory window')
    require(crc(image) == 0, 'Updated master CRC residue is not zero')
    require(branch_target(image, 0) == profile.boot, 'Boot branch mismatch')
    records = scatter_records(image)
    require(len(records) == profile.scatter_count, 'Initialization record count mismatch')
    communication_header(image, 'master', records)
    boot_prefix(image, profile)
    return dict(role='master', length=len(image), sha256=digest(image),
                version=image_version(image))


class UpdateStore:
    """Persistent installed-update directory owned by the local console."""

    def __init__(self, directory):
        self.directory = Path(directory)
        self.image_path = self.directory / 'master.bin'
        self.manifest_path = self.directory / 'manifest.json'

    def _write(self, path, data):
        temporary = path.with_name(path.name + '.tmp')
        with temporary.open('wb') as stream:
            stream.write(data)
        os.replace(temporary, path)

    def installed(self):
        """Return the verified installed identity, or None when absent.

        The manifest is the commit record: an image without a manifest is
        a leftover partial write and reads as absent. A manifest whose
        image fails verification raises, so corruption stays visible.
        """
        return self.load()[0]

    def load(self):
        """Verify once and return (identity, image bytes) or (None, None)."""
        if not self.manifest_path.exists():
            return None, None
        manifest = json.loads(self.manifest_path.read_text(encoding='utf-8'))
        require(isinstance(manifest, dict) and manifest.get('format') == MANIFEST_FORMAT
                and manifest.get('role') == 'master', 'Invalid update manifest')
        image = self.image_path.read_bytes()
        require(len(image) == manifest.get('length'),
                'Installed image length does not match the manifest')
        candidate = installable_master(image)
        require(candidate['sha256'] == manifest.get('sha256'),
                'Installed image does not match the manifest')
        return dict(manifest, structure=candidate), image

    def install(self, image, note='', signature=None):
        """Validate and commit an update image plus its manifest."""
        candidate = installable_master(image)
        manifest = dict(candidate, format=MANIFEST_FORMAT,
                        installed_at=datetime.now(timezone.utc).isoformat(timespec='seconds'),
                        note=str(note), signature=dict(signature or {}))
        self.directory.mkdir(parents=True, exist_ok=True)
        # The image lands first; the manifest commit makes it visible.
        self._write(self.image_path, image)
        self._write(self.manifest_path,
                    (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode())
        return manifest

    def remove(self):
        """Roll back to the supplied stock image by deleting the commit record."""
        self.manifest_path.unlink(missing_ok=True)
        self.image_path.unlink(missing_ok=True)
        for leftover in self.directory.glob('*.tmp'):
            leftover.unlink(missing_ok=True)
