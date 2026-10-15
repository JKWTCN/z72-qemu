# Contributing

Contributions should include a reproducible problem statement, the relevant
firmware version and evidence for new addresses or peripheral behavior.
Distinguish execution results from experimental assumptions and unresolved
hardware contracts.

Use synthetic inputs for public tests. Do not include firmware binaries,
camera dumps, calibration data or extracted graphical assets in contributions.
Do not paste verbatim sequences of stock machine code: record firmware
windows as file offset, length and SHA-256, or pin single instructions with
their documented semantics. Generated inputs and runtime outputs belong in
the ignored `.local/` and `.build/` directories; see
[firmware input](docs/firmware.md) and [publication inventory](docs/publication.md).

Run `sh tests/run.sh`, the compiled board smoke test and the release inventory
check before submitting changes. Document the checks performed and any remaining
limitations. After reviewing source changes, refresh the inventory with
`python tools/verify_release.py --refresh`.

Preserve upstream attribution, SPDX identifiers and license notices.
