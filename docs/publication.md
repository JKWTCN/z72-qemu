# Source-only publication inventory

[Home](../README.md) · [Contributing](../CONTRIBUTING.md) · [Firmware input](firmware.md)

## What is published

The repository publishes only source and documentation: the Z72 machine
overlay, firmware-analysis and probe tools, synthetic firmware-free tests,
research notes, validation reports (text JSON), and license notices.
`publication-manifest.json` lists the SHA-256 of every published file,
excluding itself.

## What is never published

- Nikon firmware, extracted MAIN/EG/EX members, or any verbatim excerpt of
  stock machine code. Firmware structure is recorded as offsets, lengths,
  SHA-256 window digests, single-instruction semantics and call/flow notes.
- Original keys, decrypted update-package intermediates, or decoding and
  repacking tools.
- Camera ROM/RAM dumps, guest-memory captures or screenshots rendered from
  firmware assets.
- Generated experimental images, build artifacts, logs and run directories
  (`.local/`, `.build/`, both git-ignored).
- Local account names, absolute private paths and credentials.

Runtime outputs of the probes (reports under `.local/`) may contain hashes
of, or bytes derived from, your local firmware; they are local evidence and
are not committed. The committed `artifacts/` reports were reviewed to carry
digests, addresses and small marker strings only.

## Repeat the inventory check

```sh
python tools/verify_release.py
```

The checker walks the source tree while excluding `.git`, `.local`,
`.build`, `.venv`, `.vscode` and `__pycache__`. It rejects symlinks,
selected non-source suffixes, non-UTF-8 or binary (NUL-containing) content,
unexpected or missing files, and any manifest that does not declare
`firmware_included=false`.

It is an inventory checker, not a credential scanner or a legal review.
Before refreshing the manifest after an intentional change, review the
changed paths yourself:

```sh
git diff --name-only
python tools/verify_release.py --refresh
python tools/verify_release.py
```

A refreshed manifest records the current files; it does not itself approve
them for publication. Check staged paths as well as the working tree, and
never commit files from ignored directories.

## Attribution and licensing

The overlay, tools, tests and documentation are GPL-2.0-or-later unless a
file states otherwise; see [COPYING](../COPYING). QEMU retains its per-file
licenses and the upstream notice in
[LICENSES/QEMU-LICENSE.txt](../LICENSES/QEMU-LICENSE.txt).

Code adapted from [WonderLantern Z7 QEMU] and
[WonderLantern Z6 QEMU](https://github.com/WonderLantern/z6-qemu) is
attributed in [NOTICE.md](../NOTICE.md), with the exact upstream revisions
and file digests recorded in
[reference-sources.json](reference-sources.json).

No license in this repository grants any right in Nikon firmware: firmware
must be obtained legally and separately by each user, and Nikon is not
affiliated with this independent project.

[WonderLantern Z7 QEMU]: https://github.com/WonderLantern/z7-qemu
