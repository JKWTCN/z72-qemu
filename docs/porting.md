# Development status

The current runtime gate model completes original bank enable and disable
requests through interrupt 250 and the original event handler. Each engine's
GIC uses its own first CPU index; synthetic SGI and private-timer checks verify
that interrupts stay within the intended engine. The default experimental tick
interval is 10 ms to allow lower-priority completions to run during software
execution. Complete startup and menu display remain pending; see the
[runtime gate contracts](../research/z7ii/runtime_gate.md).

Z72 QEMU implements isolated master and slave instruction laboratories for Nikon Z7 II C 1.70.
The following interfaces are supported by firmware analysis and execution tests.

| Interface | Evidence and implementation |
| --- | --- |
| Master image | 38,239,098 bytes; strict length, SHA-256, CRC and instruction-window checks |
| Code mapping | `0x10020000 + file offset` for the studied master sections |
| Data initialization | Source `0x12399F94`, destination `0xB1800000`, length `0xAEDB8` |
| Startup structures | ARM boot, TTBR/vector/stack literals, 20 master and 15 slave initialization records |
| Reset prefix | Stock entry and page table execute through six banked stack initializations; stops before MMIO at `0x04264000` |
| Early configuration | Four configuration words and temporary SRAM stack; stock reset reaches system initialization at `0x394`, including both original delay loops |
| First system batch | 58 stock stores to 57 words; both slave selector paths, nested stacks and invalid-section aborts; stops before readiness polling |
| System completion | Experimental synchronous completion and acknowledgements; seven stock polls and five commands return to the caller; disabled completion tests the full timeout bound |
| Platform initialization | Four original configuration calls across both channels; 360 stores, 48 polls and six result reads; returns to master `0xBDC4` / slave `0xBE10` |
| Boot continuation | 24 further stores, original SVC stack restoration and all three early copy loops; reaches master `0xC2A0` / slave `0xC2EC` before memory completion waiting |
| Boot memory | Experimental bounded zero fill and original completion/error wait; successful reset reaches master `0x416C60` / slave `0x1474A8`; forced error reaches fatal loop `0x2B4` |
| Runtime bootstrap | Original ARM/Thumb entry, library state, cache maintenance and page-table installation; initial RTOS configuration reaches master `0xE8F9C` / slave `0x1A970` |
| Interrupt foundation | Experimental CBAR layout, standard GICv2 and CPU timers; synthetic SGI 1 and secure physical timer 29 delivery/acknowledgement verified |
| Initial runtime services | Native GIC setup and heap initialization return to master `0xE3C5C` / slave `0x1570C`; original pool headers, list heads and invalid-heap aborts verified |
| Counter and kernel setup | Original counter callbacks and 18 module returns; startup task creation/start reach master `0xFE660` / slave `0x30034` waiting for another core |
| Secondary-core startup | Optional two-core execution per role; original release/ready handshake and actual startup-task entry verified; next unsupported byte store is `0x2C090001` |
| Console initialization | Ten original byte/halfword stores and caller restoration verified; bounded TX backend; next library configuration store faults at `0x04280030` |
| Pin-group configuration | Configuration word `0x04280030`, 60 bank words at `0x04282000` and master modification pairs verified from stock reset; next controller store faults at `0x04281138` |
| Controller chain | 22 words at `0x04281000/0x04280000/0x04287000`, counter delay and gate finals `0x3000`/`0x4000` verified from stock reset; next store faults at `0x20010044` |
| Configuration snapshot | Gate word `0x20010044`, nineteen dereferenced register words and the zero-source bulk copy verified from stock reset; tail parameter store faults at `0x20013000` |
| Parameter restore | Twelve copy segments, ready polls, register restore, mirror window fill, completion stores, chain return and the staging payload copy into `0xBAB00000` verified from stock reset; both roles afterwards exceed the bounded wait |
| Kernel handoff | Both roles issue `svc #6` after the parameter tail (master descriptor `0x010B0211`, slave `0x80430200`), dispatch through the payload service block / slave dispatcher and wait on an unchanging RAM event object (slave poll loop `0x19038`, master store veneer `0x100430`); no interrupt releases the wait, one stand-in write of the recovered word restores kernel activity; registering the release-path content and modeling the peer-ready descriptor word advances runs toward the heap response structure and the page-table gap `0x2C020000` |
| Scheduler idle | With the peer stand-in write, both roles finish startup with zero data aborts and park both cores in the per-core dispatch loop of the service block (master `0x1010705C..0x101070B0`, measured `0x10107070/78`; slave `0x10038A4C`); ready queues empty |
| Timer tick | Recovered interrupt plumbing: payload IRQ entry `0x101036A8` acknowledges the controller, primary handler table `0xB2B41E48` (line 1 kernel IPI, line 29 per-cpu service) and secondary table `0xB2B5DF20`; the timer block `0x2B000000` (start word `+0`, period `+4`, event mask `+8` observed `0x300`, channel pages from `+0x1000`) maps to dispatch line 237 whose dispatcher `0x105165D4` reads `+8` and writes the serviced bits back; an experimental periodic device latches the armed mask and raises line 237, and the freed master dispatches real tasks (per-core current-task table `0xB2B41604` nonzero, 10k+ interrupt entries, zero faults); the isolated slave never arms this timer |
| Dual-engine machine | `nikon-z72-dual-lab`: four cores, one private address-space view per engine (code, RAM, GIC and peripherals per engine) and the two 1 MiB communication RAMs shared at native addresses in both views; both engines boot naturally from reset to their schedulers with zero data aborts, no stand-in writes anywhere, master tasks running and the slave communication stack active |
| Slave initialization | Three early ARM loops, four table copies and a bounded Thumb zero record |
| Display state | Byte at `0xB202BE70 + 0x19E` |
| Display predicates | Master file offsets `0x600348` and `0x539EE0` |
| MMU permissions | Preserved section attributes; append-section XN negative control |
| Menu object getter | Master file offset `0x5FDAAE`; complete calling contract remains unresolved |
| Processor roles | Separate master/slave EG images; inter-engine communication distinct from CPU SMP |
| Graphics components | Master graphics upload window wired to the shared GPU command executor; stock initialization uploads and their completion callback verified |

## Remaining implementation

Complete startup requires recovery of the master boot RAM and peripheral
interfaces, followed by the image-memory, power and application-ready routines
and their calling contracts. Menu support additionally requires menu-level GPU
command flows, LCD scanout and fuller input event routing.

The [reset-prefix probe](../research/z7ii/reset_prefix.md) now establishes the
uninterrupted core-zero path through MMU enable and stack initialization.
The [early-configuration probe](../research/z7ii/early_configuration.md) extends
that path through `0x2B8` and master `0xD700` / slave `0xD740` to `0x394`.
The [system-configuration probe](../research/z7ii/system_configuration.md)
executes the first 58 stores in master `0x4C6C`, slave `0x361C` and slave
`0x4CB8`. The [completion stage](../research/z7ii/system_completion.md) extends
these first calls through 106 stores, seven polls and five command stages using
an experimental synchronous device contract. The
[platform stage](../research/z7ii/platform_initialization.md) executes the next
configuration routine and repeats both calls for the second channel. It returns
to master `0xBDC4` / slave `0xBE10` before the boot continuation's result check
and following configuration stores. The
[continuation stage](../research/z7ii/boot_continuation.md) now executes those
stores and all three early copy loops, restoring the original SVC stack.
The [boot memory stage](../research/z7ii/boot_memory.md) implements a bounded
zero-fill interpretation of the rounded 16 KiB setup and executes the original
completion/error wait. Successful reset reaches master `0x416C60` / slave
`0x1474A8`. Whole-range RAM
effects and fatal error handling are verified in the model; actual hardware
operation, block rounding and timing remain unresolved.
The [runtime bootstrap](../research/z7ii/runtime_bootstrap.md) now executes those
entry points through the native RAM page-table handoff and initial RTOS setup.
The [first service group](../research/z7ii/runtime_services.md) now returns
normally after configuring GIC and initializing the runtime heap. Additional
RAM covers the decoded heap bounds without changing the original page table.
The [counter stage](../research/z7ii/runtime_counter.md) now implements the
bounded device at `0x04266000`, executes 18 subsequent kernel module calls and
creates/starts the original startup task. Execution waits for one additional
core at master `0xFE660` / slave `0x30034`; peer readiness stays zero in the
single-CPU context. The [secondary-core stage](../research/z7ii/smp_startup.md)
now executes both original reset paths, verifies the peer's exclusive ready
store and reaches the startup task on the primary. Synthetic directed SGIs and
both cores' timer delivery pass. The next boundary is the low-level device
initializer at offset `0x180`, whose first byte store faults at `0x2C090001`.
The [console stage](../research/z7ii/console_boot.md) now completes that device's
original initialization and verifies byte transmission using synthetic code.
The [pin-group stage](../research/z7ii/library_boot.md) now executes the following
library initializer: the `0x04280030` configuration word, twelve five-word groups
copied from early-copy RAM into `0x04282000` banks and the master's original
read-modify-write pairs. The [controller stage](../research/z7ii/controller_boot.md)
now executes the following `0x04281000` sequence with its original counter delay
and polled `0x04287000` gate. The [snapshot stage](../research/z7ii/snapshot_boot.md)
now executes the following initializer through its nineteen register reads and
the zero-source bulk copy from `0x20014800` (no startup writer exists; treated
as read-only controller content). The [parameter stage](../research/z7ii/parameter_boot.md)
now completes the whole tail restore through its register polls, snapshot
write-back, mirror window fill and completion stores, returning to the chain.
The staging copy into the new one-miB `0xBAB00000` window is verified
byte-exact. The [kernel-handoff stage](../research/z7ii/kernel_handoff.md)
resolves that boundary: the payload is the exception/service block, both roles
issue `svc #6` (master `0x010B0211`, slave `0x80430200`) and dispatch through
it (master vector `0x10100008`; slave veneer `0x14108` into the `0x15010`
dispatcher and class handler `0x10038FF8`), then remain inside the service
implementation; the staging continuation, the `0x348150` remap family and the
chain's module sweep never execute in isolation. The completion source is
judged to be the peer engine's acknowledgement. Access watchpoints localize the
wait: the slave polls a zeroed stack wait-block (`0x19038` loop) and the master
re-enters a payload store veneer (`0x100430`); the wait words never change and
both mailbox windows stay zero. A laboratory interrupt injector (private-block
word `0x04009000`) sweeping every shared line releases nothing, so the peer
writes the event word itself: one stand-in write (master `0xB2C59A90`, slave
`0xC19B4FC8`) restarts the kernel; registering the touched release-path
content (controller bit-banks `0x04281034/58/5C`, companion page `0x2C0A0000`,
counter-adjacent file `0x0426F000..14`, and the indexed `0x04280004`-relative
register-file window) advances runs to structural boundaries: the firmware
page-table gap at `0x2C020000`, the stand-in value dereferenced as a pointer
(`1+0x33`) and the response-derived buffer pointer `0xB7F6A0EC`. The file
watchpoints recover the first descriptor fields - the kernel polls the
peer-ready word `0x0428002C` after posting `+0x30=0x410` - so the machine
models the peer's readiness and a freed master run reaches ~25,000 events with
only the wait-word stand-in; the remaining NULL+0x33 dereference comes from a
heap field of the peer response structure.
The [timer-tick stage](../research/z7ii/kernel_handoff.md) unblocks the idle
scheduler: with the tick device enabled, the freed master acknowledges the
armed event mask (`0x300`) through the original dispatcher, the primary core
picks up its first real task from `0xB2C335F0`, and bounded runs record
thousands of interrupt entries with zero data aborts while the secondary core
idles. The [dual-engine machine](../research/z7ii/kernel_handoff.md) replaces the
stand-ins: with both images running in one machine through private views over
shared communication RAM, the real slave answers the master handoff naturally,
both schedulers come up fault-free and master tasks advance into main-image
modules. The remaining boundary is the transport handshake retry loop -
cross-engine doorbell interrupts are not yet modeled - and the display
initialization chain beyond it.
Menu-visible output still requires inter-engine transport and the
application initialization chain.
Stock IRQ handlers beyond the recovered lines, complete scheduling, inter-engine transport and
runtime/application initialization remain unresolved. Real platform completion timing and nonzero result retry
behavior also remain unresolved.

Image processing requires validated RAW input geometry, ISP submission,
completion signaling and stream restart handshakes. Firmware-specific addresses
and parameters must be verified against C 1.70 before these paths are exposed
as supported behavior.

## Dual-EXPEED coordination

The master communication address `0xB7CF0000`, slave address `0xC60F0000`,
192-slot queue with 264-byte records and initialization constants are established
research observations. Selected slave initialization routines execute in an
isolated machine. Inter-engine transport, complete slave boot, frame scheduling
and image-buffer ownership remain unresolved.

## Scope

The `nikon-z72-lab` machine supplies the memory and CPU execution context for
selected routines. Full camera startup, interactive menus, real-time display,
photo recording and installation are not verified by these experiments.
