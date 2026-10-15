# Attribution and licensing

Portions of this project are adapted from
[WonderLantern Z6 QEMU](https://github.com/WonderLantern/z6-qemu) and
[WonderLantern Z7 QEMU](https://github.com/WonderLantern/z7-qemu), including work
by R3tr0ooo and their contributors. We gratefully acknowledge their camera
emulation research, GPU implementation, build tools and regression tests.
Their attribution and GPL notices are retained. Upstream revisions and source
hashes are recorded in [reference-sources.json](docs/reference-sources.json).

The Z72 machine, firmware input guards and execution experiments target Nikon
Z7 II C 1.70. They implement a limited instruction laboratory, not a complete
EXPEED hardware specification.

Overlay, tools, tests and documentation are GPL-2.0-or-later unless stated
otherwise; see COPYING. QEMU retains its per-file licenses, with the upstream
notice retained in LICENSES/QEMU-LICENSE.txt. No project license grants any
right in Nikon firmware; firmware copyright remains with its rights holders,
and each user must obtain firmware legally and separately. Nikon is not
affiliated with this independent project.

Original firmware and generated candidate binaries are local inputs/outputs,
excluded from the source inventory. Update-package decoding, extraction and
repacking tooling, and verbatim stock byte excerpts are likewise not part of
this repository; firmware windows are recorded as offsets, lengths and hashes,
and single instructions as semantic encodings. This project does not operate
a physical camera.
