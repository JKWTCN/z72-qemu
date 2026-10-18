# Z72 QEMU

[中文](README.zh-CN.md) · [Architecture](docs/architecture.md) · [Development status](docs/porting.md) · [Firmware](docs/firmware.md) · [Testing](docs/testing.md) · [Publication](docs/publication.md) · [Research](research/README.md)

The [local browser console](docs/browser.md) provides live display frames,
held keys, keyboard shortcuts and restart controls. Run `tools/web_console.py`
with the three firmware paths and open `http://127.0.0.1:8666`.

Z72 QEMU is an experimental QEMU environment for Nikon Z7 II C 1.70 firmware
research. It provides a dedicated ARM machine, strict firmware input validation,
and reproducible experiments for memory initialization, MMU permissions and
display-state predicates. Both original engine images plus the original
controller image boot together to their schedulers with zero execution faults:
a synthetic battery peer completes the original serial authentication, the
five-second power policy clears, the shooting application renders and persists,
and a menu-key input runs the original menu start entry with a full structured
menu across the screen. Inside that menu the recovered input map moves the
highlight with the four direction inputs, switches tabs, and reaches the
confirmation bit; the playback input switches the foreground application.
Firmware analysis recovered the original menu firmware-update service, its
card-file naming rules and package-check library, so the browser console now
completes a menu-gated update: with a candidate master supplied from outside
the repository, the install requires the menu application in the foreground,
commits an atomically verified update store, and the restarted machine loads
the installed image (with rollback to the supplied stock master). The card,
file-system and flash-write stages stay host-side stand-ins. Menu reopening
after it closes, menu text semantics, LCD live view and the natural
production of a few notifications remain pending.
See the [menu key research](research/z7ii/controller_keys.md),
[menu firmware update](research/z7ii/firmware_update.md) and
[battery peer](research/z7ii/battery_serial.md) for the current boundaries.

## Startup structure

Stock master and slave startup structures can be inspected and their
initialization routines executed in isolated contexts. See
[startup structure](research/z7ii/startup_structure.md) for recovered addresses
and validation limits. Run with owned, unmodified C1.70 EG images:

```sh
python tools/structure_probe.py --master /path/to/eg1840_mas_01700.bin --slave /path/to/eg1840_sla_01700.bin --destination .local/structure-run
```

The default backend is `virt`. Use `--backend nikon-z72-lab --qemu ...` for the
compiled master and slave machines. Communication windows provide ordinary RAM;
inter-engine transport and natural boot remain unimplemented.

The native machines can also execute the stock reset prefix with the original
page table, checking all six mode stacks and stopping before the first MMIO
store. See [reset prefix](research/z7ii/reset_prefix.md) for the command and
negative control. This does not yet reach the RTOS or menus.

The [early-configuration stage](research/z7ii/early_configuration.md) adds four
configuration words and temporary stack RAM. Stock reset executes both original
delay loops and reaches system initialization offset `0x394`. Stock, register-bit
preservation and invalid-stack scenarios are checked; full boot and menus remain pending.

The [first system-configuration batch](research/z7ii/system_configuration.md)
continues through `0x394`, checking 58 stock configuration stores, both slave
selection paths and invalid-section data aborts. Execution stops before the
first readiness poll; the RTOS and menus are still pending.

The [completion stage](research/z7ii/system_completion.md) adds experimental
synchronous completion and acknowledgement behavior. The first configuration
call returns through seven original polls and five commands, reaching master
`0x5354` or the slave's next initialization entry. Disabled-completion controls
execute the original full timeout bound. Full boot and menus remain pending.

The [platform-initialization stage](research/z7ii/platform_initialization.md)
completes all four configuration calls across both channels: 360 stores, 48
original polls and six result reads. Stock reset reaches boot continuation
`0xBDC4` (master) or `0xBE10` (slave). A selectively blocked command executes
the original timeout. RTOS startup and menus remain pending.

The [boot-continuation stage](research/z7ii/boot_continuation.md) adds 24 exact
configuration words, restores the original SVC stack and executes all three
early copy loops continuously from reset. It reaches the memory-initialization
completion-wait entry.

The [boot memory stage](research/z7ii/boot_memory.md) supplies an experimental
bounded zero fill and completion/error status. Stock reset now reaches master
`0x416C60` or slave `0x1474A8` after the original completion wait. Whole-range
poison/guard checks and the stock fatal-error loop are verified. Those next
entry points are continued by the next stage; full RTOS startup and menus remain pending.

The [runtime bootstrap](research/z7ii/runtime_bootstrap.md) executes ARM/Thumb
interworking, library state initialization, original cache maintenance and the
16 KiB page-table copy/switch. It prepares the initial RTOS configuration and
reaches master `0xE8F9C` / slave `0x1A970`. The native boards now provide a
standard GICv2 and wired CPU timers at an experimental CBAR layout. Synthetic
checks verify actual interrupt delivery; stock interrupt handlers and scheduling
remain unverified.

The [initial services](research/z7ii/runtime_services.md) now complete original
GIC setup and runtime heap initialization. RAM covers both decoded heap bounds;
stock reset returns to master `0xE3C5C` / slave `0x1570C` and continues to the
first access of counter device `0x04266000`. Pool headers,
empty lists and heap-section data-abort controls are verified. Full startup
and menu rendering remain pending.

The [counter stage](research/z7ii/runtime_counter.md) supplies a running MMIO
counter and the original 48 MHz CPU frequency declaration. Stock reset completes
18 further kernel module calls and creates/starts the startup task, then waits
at master `0xFE660` / slave `0x30034` for another core in the default single-core context.

The [secondary-core stage](research/z7ii/smp_startup.md) adds optional `-smp 2`
within each isolated role. Both original reset paths run, the secondary publishes
readiness with the original exclusive store, and the scheduler enters the startup
task. Execution then faults on the unsupported byte register `0x2C090001`.
Directed SGIs and each core's physical timer are verified with synthetic code.
Full camera startup, stock IRQ handling and menus remain unverified.

The [console stage](research/z7ii/console_boot.md) now completes all ten original
mixed-width configuration stores at `0x2C090000` and restores the caller.
A bounded transmitter can send bytes to an optional QEMU character backend.
Native console text, receive and UART interrupts remain unverified.

The [pin-group stage](research/z7ii/library_boot.md) executes the next library
initializer: one configuration word at `0x04280030` and twelve five-word groups
copied from early-copy RAM into five banks at `0x04282000`, plus the original
read-modify-write pairs on the master. Stock reset returns to the initialization
chain and stops at the first `0x04281000` store; pin electrical behavior is
unmodeled.

The [controller-chain stage](research/z7ii/controller_boot.md) executes that
sequence: six constant words and setup stores at `0x04281000`, the original
counter delay, derived words at `0x04280000` and a polled gate at `0x04287000`
(master three phases, slave five). The [snapshot stage](research/z7ii/snapshot_boot.md)
then executes the next initializer: it gates `0x20010044`, dereferences nineteen
recovered pointers into `0x2001xxxx` register words and copies their values into
RAM from a zero-initialized 512-word source table at `0x20014800` (no writer
exists in startup; treated as read-only controller content). The
[parameter stage](research/z7ii/parameter_boot.md) then executes the tail
restore: twelve segments into `0x20013000`/`0x20016A00`, a polled register
ready bit, the original nineteen-word register restore, a mirror copy into the
eight-region window at `0x24074000`, the completion stores and the return to
the initializer chain. The master then copies its `0x21538`-byte payload into the new one-miB
staging window at `0xBAB00000` (verified byte-exact).

The [kernel-handoff stage](research/z7ii/kernel_handoff.md) explains those long
compute paths: the payload is the firmware's exception/service block (the
exception base has pointed at its `0x10100000` runtime address since the runtime
stage). The master then issues `svc #6` with descriptor `0x010B0211`, the slave
chain with `0x80430200`; both dispatch through the vector block (master
`0x10100008`, slave veneer `0x14108` into the `0x15010` dispatcher) and stay
inside the service implementation, never returning to the staging continuation
or the initializer chain within the bound. The descriptors match the firmware's
inter-engine command family; the completion source is judged to be the peer
engine's acknowledgement, which remains unmodeled. Access watchpoints recover the
wait itself: the slave polls a zeroed stack wait-block (`cmp`/`bhi` until
nonzero at file `0x19038`), the master re-enters a payload store veneer at file
`0x100430`; the wait words never change and both mailbox windows stay zero, so
the boundary is an RTOS event that no producer posts in isolation: a laboratory
interrupt injector sweeping every shared line found no interrupt that releases
the wait by itself. A single debugger write of the recovered wait word stands in
for the peer response (master heap word `0xB2C59A90`, slave stack block
`0xC19B4FC8`); the kernel then restarts (433 recorded exception events in one
run; the chain re-entry at `0x1E004A` is recorded from exploration), and both
roles converge on the same next boundary - the store to `0x04281058` faults
(DFSR `0x8`) and the original self-loop data-abort vector parks the arriving
core. Registering what stock execution actually touches on that path keeps the
run advancing - the controller bit-banks (`0x04281034/58/5C`), a companion
serial-adjacent page at `0x2C0A0000`, the counter-adjacent register file
`0x0426F000..14`, and the indexed `0x04280004`-relative register-file window at
`0x04280000` (single words plus `+0x30[idx]`/`+0x60[idx]` arrays) - until
structural boundaries appear: a firmware page-table gap at `0x2C020000`, the
stand-in value dereferenced as a pointer (`1+0x33`), and a response-derived
buffer pointer `0xB7F6A0EC`; one freed slave run records 590+ events, a master
run 20,130. Access watchpoints over the file recover the first descriptor
fields: the kernel polls the peer-ready word `0x0428002C` after posting its own
`+0x30=0x410` descriptor, so the machine now models the peer's readiness
(the file answers ready once the local descriptor is posted) and a freed master
run reaches ~25,000 events with only the single wait-word stand-in; the
remaining `NULL+0x33` dereference comes from a heap-object field of the peer
response structure - its field table is the next entry point.
The staging window becomes
a switchable device block whose negative control keeps the copy store faulting.

The [timer-tick stage](research/z7ii/kernel_handoff.md) then unblocks the idle
scheduler. Firmware analysis recovered the whole interrupt plumbing - the
payload IRQ entry at `0x101036A8`, the runtime handler tables and the timer
block at `0x2B000000` serviced through dispatch line 237 - so the machine
models the armed event mask as a periodic contract. With the tick enabled, the
freed master acknowledges ticks through the original dispatcher, picks up its
first real task (current-task table nonzero, thousands of interrupt entries,
zero data aborts) and keeps executing kernel work while the secondary core
idles. The isolated slave never arms this timer; menu-visible output still
awaits the inter-engine transport.

The [dual-engine machine](research/z7ii/kernel_handoff.md) then removes the
stand-ins: both original images run in one machine through private
address-space views over shared communication RAM, and the real slave answers
the master handoff naturally. Both engines boot from reset to their schedulers
with zero data aborts and no debugger writes anywhere, master tasks advance
into main-image modules, and the slave communication stack stays active. The
remaining boundary is the transport handshake retry loop (cross-engine
doorbell interrupts are unmodeled) and the display chain beyond it.

Later stages recovered the foreground wait chain up to live view: the
[waiting interface services](research/z7ii/message_wait.md), the experimental
[temperature parameters](research/z7ii/temperature_parameters.md), the
[input path and capture buffers](research/z7ii/input_path.md) and finally the
[capture-readiness boundary](research/z7ii/capture_readiness.md) - the
operation completion-callback table, the capture sub-state machine, the
unchanged readiness byte and local resource bitmap updates. Sub-state zero
returns before checking readiness; the pending device initialization still
needs its work producer. Menus remain unverified.

The [internal delay counter](research/z7ii/delay_counter.md) now delivers
the observed channel 9 interrupt and lets the original configuration task
return from its delay wait. Byte prescalers also support divided delays;
external capture events remain unmodeled, and
normal startup and menus are still unverified.

The [sampling synchronization configuration](research/z7ii/sampling_sync.md)
adds the recovered format and interface fields, including five indexed groups.
Configuration storage does not generate received samples or completion events.

The [input processing configuration](research/z7ii/input_configuration.md)
adds sparse format, geometry, analysis and buffer-address storage for each
engine. Synthetic checks cover access bounds, packed fields, reset and
isolation, without manufacturing pixel transfers or input events.
Original execution now reaches operation 14 completion and starts drawing the
shooting interface in mode 3. Further observation returns to mode 8 and clears
the surface; stable startup and menu interaction remain unverified.
The [subsequent observation](artifacts/shooting_interface_validation/report.json)
confirms the visible original shooting status bar and records the later
3 → 1 → 8 transition sequence.
The [startup timeout](research/z7ii/startup_idle_timer.md) is now traced to
the five-second application timer. The observed battery communication status
is 9 and the power-policy flag is 2; complete battery serial replies remain
pending.

The optional [controller supply interface](research/z7ii/controller_supply.md)
now completes its original handshake and uses bounded checksummed records
with receive/transmit DMA. Zero-filled experimental records still retain the
five-second power policy; stable startup and menu interaction remain pending.

The optional [experimental battery serial peer](research/z7ii/battery_serial.md)
now completes startup exchanges and parameter queries, clearing the five-second
power policy. It uses a documented controller-memory bridge and fixed laboratory
measurements. The original shooting application and rendering remain active across
the internal mode 3 → 1 transition for 11.50 sampled virtual seconds; see the
[persistence observation](artifacts/shooting_persistence_validation/report.json).
The visible `Err` indication and menu interaction remain unresolved.

The [menu key transport](research/z7ii/controller_keys.md) has been traced from
expander input 9 to bit 15 of the second decoded switch word and the original
system input callback and application action `0x1c`. Boot probes include
read-only capture health and resource-header observations. An experimental
group-32 header with the storage end marker now loads through the original
copy path and removes status `0x44`, without changing the runtime status list.

The [synchronization event path](research/z7ii/sampling_sync.md#同步事件与原厂等待)
now delivers external events through the native interrupt and callback. One
supplied pulse removes the observed `0x3e` timeout status. Combined with the
experimental header, this reaches mode 4 with an empty status list; continued
execution then adds `0x3f`, and a menu press in one such run stopped before
the application action consumer with no foreground rewrite after
initialization.

Holding the menu input from the first ready foreground takes a different,
working route: the original firmware runs the menu start entry `0x1044e3ae`
directly, the foreground switches to the menu application (index 1), it
stays foreground after the release, and the captured 720x480 frame shows a
full structured menu across the screen. The menu key probe reproduces this
(`--resource-header --sync-pulse --settle-seconds 0`, key held until the
switch). Action-chain analysis also recovered the general switch machinery:
a type-1 system event synthesizes action `0x50`, whose handler stores the
foreground-switch request; a late press instead yields the unhandled raw
action `0x1c`. Menu item interaction and text semantics remain unverified.

## Firmware input

Supply your own legally obtained, extracted, unmodified C1.70 master EG:
**38,239,098 bytes**, SHA256
`478caf02dba41fa9144c0c4b6e1a051dc556d40e51a79a308bdd1169efb9dbbe`.
An update container cannot substitute for the extracted master image, and
update-package decoding, extraction and repacking tools are not part of this
repository. No firmware binaries are included or downloaded by the project,
and firmware copyright remains with its rights holders. Every probe verifies
length, SHA-256, CRC and structure before the guest starts; see
[firmware input](docs/firmware.md).

## Quick start

Requires Python 3.10+, QEMU ARM, Clang and LLVM linker. From the project root:

```sh
python tools/structure_probe.py --master /path/to/eg1840_mas_01700.bin --slave /path/to/eg1840_sla_01700.bin --destination .local/structure-run
```

The default `virt` backend works with stock QEMU. All harnesses, logs and the
JSON report stay in the new run directory; the source is untouched. The
recorded run executed the original early copy loops, Thumb table copies, the
bounded communication-RAM zero record and the communication header store
block in both roles, with poisoned destinations and trailing guards.
See [startup structure](research/z7ii/startup_structure.md) and the
[structure validation](artifacts/structure_validation/summary.json).

## Build the Z72 machine

Build the `nikon-z72-lab` board on Linux/WSL with Python 3.12+, a C compiler,
Ninja, pkg-config, GLib/Pixman/zlib/libfdt development packages and python3-venv.
The boot probes additionally need Clang and LLVM linker:

```sh
python3 tools/build.py --jobs 4
python3 tests/test_board.py --qemu .build/build/qemu-system-arm
python3 tools/boot_probe.py --qemu .build/build/qemu-system-arm --master /path/to/eg1840_mas_01700.bin --slave /path/to/eg1840_sla_01700.bin --destination .local/native-run
```

Builds pin QEMU 10.2.4 and its source hash, accept an offline `--archive`, and
record build metadata in `.local/build-manifest.json`. The lab board supplies the studied master
RAM windows and one experimental CPU by default, with optional two-core execution.
The master graphics upload window is connected to the shared GPU command
executor. Stock initialization uploads and their completion callback are verified;
menu output and LCD scanout remain unverified.

## Testing

```sh
sh tests/run.sh
python tools/verify_release.py
```

CI runs the firmware-free checks and the pinned QEMU build; see
[testing](docs/testing.md) and the [publication inventory](docs/publication.md).

## Acknowledgements

We thank [WonderLantern Z6 QEMU](https://github.com/WonderLantern/z6-qemu) and
[WonderLantern Z7 QEMU](https://github.com/WonderLantern/z7-qemu), including
R3tr0ooo and the project contributors, for their open-source camera emulation
work, graphics and image-processing implementations, and research tools.

## License

The project is licensed under [GPL-2.0-or-later](COPYING), unless an individual
file states otherwise. Attribution and licensing information are in
[NOTICE](NOTICE.md). Upstream QEMU retains its per-file licenses. Nikon is not
affiliated with this project; no project license grants rights in Nikon firmware.
