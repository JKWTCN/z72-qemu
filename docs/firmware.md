# Local firmware input

[Home](../README.md) · [Testing](testing.md) · [Publication inventory](publication.md)

This repository contains no Nikon firmware, decrypted payload, camera dump,
key, calibration data or extracted asset. No tool here downloads firmware or
extracts an update package. Every experiment requires firmware images that
you supply from a local file.

## Accepted stock inputs

Probes validate each complete image before any guest starts. The accepted
stock identities are recorded from verified local research copies:

| Role | File | Length | SHA-256 |
| --- | --- | --- | --- |
| Master EG | extracted `eg1840_mas_01700` member | 38,239,098 bytes | `478caf02dba41fa9144c0c4b6e1a051dc556d40e51a79a308bdd1169efb9dbbe` |
| Slave EG | extracted `eg1840_sla_01700` member | 8,834,370 bytes | `e0d2589cf036bbf8ce6e4c32f5f2bab61fe35e863660bf6a0ee8082d8a64e1bb` |
| Controller EX | extracted `ex1840_013000` member | 524,290 bytes | `cb10af00b9485567453d448020892836ea48637bd638f4cf7cc1c9777a128a9a` |

Container/member relationships and further window digests are recorded in
[firmware identity](../research/firmware_identity.json). An update container
is not one of these payloads: the project ships no decoding, extraction or
repacking tools, so obtain the extracted members independently and legally,
and keep them outside the repository (`.local/` is ignored).

## What is checked, and when

`analyze/decode_z72.py` (`validate_master`) and
`analyze/firmware_structure.py` (`analyze_eg`) check, before a run directory
is created or QEMU starts:

1. Exact length and whole-image SHA-256 against the table above.
2. The trailing CRC-16/XMODEM residue (a stock EG reads zero).
3. Structural bindings: scatter record, gate/widget state pointers, widget
   table, histogram descriptor, visibility-mask words, and the SHA-256 of
   the recorded display-gate code windows.

Images are read into memory once, validated, and the validated bytes are
what QEMU loads. A file that is replaced on disk after the check cannot
alter a running experiment; each probe revalidates from scratch on every
launch.

| Error | Check |
| --- | --- |
| `Requires stock Z7 II C 1.70 ... EG` | Length, whole-image SHA-256 or CRC |
| `Scatter mapping mismatch` and similar | Structural words inside the image |
| `Hook window mismatch` | Display-gate code-window digests |
| `Unsupported ... code window` | Stage-profile code windows (`analyze/*_boot.py`) |

## Stock, extracted and modified images

- **Stock images** are the exact members listed above. All boot, kernel,
  controller and analysis probes accept stock images only; each stage
  additionally pins the code windows it executes by offset, length and
  SHA-256, so an unexpected layout fails loudly instead of executing.
- **Extracted members** are produced from your own update package by tools
  outside this repository. The container CRCs and member digests in the
  research record let you confirm an extraction before using it.
- **Modified images** are not produced by this repository. The laboratory
  infrastructure itself (`analyze/qemu_display.py` machine launcher and
  translation tables, the compiled boards) loads any image bytes you give
  it — the synthetic board and graphics tests run project-authored code,
  not stock firmware — but the stock-analysis probes compare the whole
  image against the identities above and reject anything else. That guard
  protects the recorded address research; it is a validation boundary, not
  a restriction of the emulator. Adapt or extend the probes if you research
  a different image.
- **Installed update images** are the one sanctioned exception, and only
  inside the console update store. A candidate supplied through
  `tools/web_console.py --update-image` is accepted when it preserves the
  executed boot structure (window-bounded length, zero CRC residue,
  version record, reset branch, initialization-table count, communication
  window and boot prefix); the stock digests above deliberately do not
  apply because an update may change those bytes. The manifest written at
  installation time is the local trust anchor: every boot re-verifies the
  stored image against it before loading, and a broken store falls back to
  the supplied stock master with a visible error. See
  [menu firmware update](../research/z7ii/firmware_update.md). The store
  contains only images you supplied; this repository still ships no
  decoding, extraction, repacking or image-building tools.

## Local outputs

Run directories, candidates, harness binaries, logs and reports are written
under `.local/` (ignored). Compiled output stays under `.build/`. The
[source-only inventory](publication.md) excludes both.
