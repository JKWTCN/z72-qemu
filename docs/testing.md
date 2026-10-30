# Validation

The 2026-10-23 source build produced QEMU 10.2.4 and passed the synthetic
boot-store reprogram/reset check. The stock combined machine also reached
the original card slot table registration in read-only observation mode.
The full card-consumer probe timed out during key injection; this does not
establish native menu update acceptance. Binary and source identities are in
the [build/runtime record](../artifacts/build_runtime_validation/report.json).

`tools/gate_boot_probe.py` follows stock reset through runtime bank-zero gate
enable and disable, interrupt 250 acknowledgement and original task resumption.
Its disabled-completion control requires both the handler and continuation to
remain absent, with bank status zero. The experimental tick interval is 10 ms.
These checks do not establish complete startup or menu output.

`tests/test_dual_interrupts.py` executes synthetic instructions in all four cores
of the dual machine. It checks both directions of engine-local SGI delivery,
source CPU information, per-core private timers, EOI and unchanged records in
the other engine. CI includes this check; no remote CI run is claimed.

`python -m unittest discover -s checks -v` checks wrong-size and
wrong-content master rejection before any patching. `python -m unittest discover -s tests -p test_platform.py -v`
checks both backend page translations, section rejection, XN isolation,
same-size wrong-master rejection and repeatable/version-guarded integration.
`python -m unittest discover -s tests -p test_structure.py -v` checks initialization
table bounds, copy/zero distinction, branch and literal decoding, slave page
isolation and consistency between board RAM and translation profiles. It also
checks Thumb literal PC alignment, communication header store guards, role-local
addresses and the matching zero record.
It also rejects unsupported stock section descriptors and checks reset-prefix
boundaries, role-specific stack checkpoints and native identity mappings.

`sh tests/run.sh` additionally compiles the GPU renderer test with ASan/UBSan.
The renderer uses a synthetic address-space adapter, not Nikon assets. `tests/test_board.py --qemu ...` checks mapped RAM and executes synthetic
ARM code on the compiled custom machine. CI runs these firmware-free checks
and a pinned QEMU10.2.4 build; configuration of CI does not imply a remote run.


`tools/structure_probe.py` also executes the communication header store block in
each role, after OS calls and before the return POP. Two fill patterns check the
four written words, two untouched words and surrounding guards. Both backends
passed; see [communication validation](../artifacts/communication_validation/report.json).
This does not verify the full initializer or inter-engine transport.

`tools/boot_probe.py` requires the compiled native laboratories and stock master
and slave images. It executes each EG entry without a synthetic harness or
replacement page table, verifies all six mode stacks and stops before first
MMIO. A separate instance with the code-section descriptor invalidated must
take a prefetch abort after MMU enable. The stock table must remain byte-identical.
See [reset-prefix evidence](../artifacts/boot_validation/report.json).
Full startup, RTOS entry and menu rendering remain unverified.

`tools/early_boot_probe.py` extends stock reset to offset `0x394` on both native
machines. Each role runs stock, seeded-configuration and invalid-stack scenarios.
It checks original register stores, preservation of unrelated bits, temporary
stack contents/restoration, both unmodified delay loops and the stock page table.
Invalid stack mapping must cause a data abort on the configuration routine's PUSH.
See [early-boot evidence](../artifacts/early_boot_validation/report.json).
Synthetic board checks additionally cover configuration reset clearing and aborts
on byte stores and neighboring unsupported words.

`tools/system_boot_probe.py` continues stock reset through the first system
configuration batch. Master and slave stock/poisoned/invalid-section scenarios
and an additional slave bit-2-set scenario verify all 58 stores in order,
readbacks, selector preservation, nested stack saves and the original page
table. Invalid system mapping must abort on the first store. Both slave paths
stop before `0x920`; master stops before `0x8D4`. The status poll is not executed.
Board smoke checks cover all 63 supported words, reset clearing and sparse holes.
See [system configuration](../research/z7ii/system_configuration.md) for commands
and the remaining readiness contract.
The 2026-10-10 seven-scenario native run and all three regression probes passed;
compact evidence is [system_boot_validation](../artifacts/system_boot_validation/report.json).

`tools/completion_boot_probe.py` follows the first system configuration call
through all 106 successful-path stores, seven original polls and five command
stages, checking three zero-result reads, acknowledgements, return state and the
next initialization entry. Both roles additionally run with device completion
disabled: each original poll executes 40,000,000 failed iterations, returns
`0xFFFFFFFF` and produces a system result of `0x4000`. The negative controls
change the device property only. Board checks cover 103 words, command-triggered
status, selective acknowledgement, read-only results and pending-status reset.
See [completion contracts](../research/z7ii/system_completion.md) for assumptions.
The 2026-10-10 five-scenario native run, both board checks, 22 Python checks and
renderer sanitizer checks passed. All three regression probes also passed;
evidence is [completion_boot_validation](../artifacts/completion_boot_validation/report.json).

`tools/platform_boot_probe.py` executes all four initial configuration calls
from the stock reset entry, using the original page table and instructions.
Three successful paths check 360 stores, 48 polls, six result reads, call
arguments, preserved registers and stack restoration. Each role also blocks
only control `0x20024100`: one original poll performs 40,000,000 failed
iterations, its call returns `0x4000`, and the caller continues to a final zero
return. This path has 359 stores because the failed status is not acknowledged.
All five scenarios stop before boot continuation, at `0xBDC4` or `0xBE10`.
Board checks now cover 348 words and all 40 command/status pairs, reset,
acknowledgement, results and unsupported-access aborts. Both boards, 22 Python
checks and 270 renderer sanitizer checks passed on 2026-10-10.
Completion and structure regressions passed on the rebuilt model.
See [platform contracts](../research/z7ii/platform_initialization.md) and
[platform_boot_validation](../artifacts/platform_boot_validation/report.json).

`tools/continuation_boot_probe.py` follows the platform stage through 24 further
configuration stores and all three early copies without changing PC or using
a replacement harness. It checks original call arguments, SVC stack restoration,
read-modify-write preservation and every copied byte with poisoned destinations
and trailing guards. The zero-length third loop must preserve four bytes.
Both roles run stock, seeded-register and invalid-system-section scenarios;
slave additionally runs its shared selection path. The invalid descriptor is
introduced after platform return; the first continuation store must abort and
leave its configuration word unchanged, then the descriptor is restored.
Successful runs stop before the memory completion-wait routine executes.
Board checks at that stage covered 372 words and rejected the then-unsupported
wait status, holes, byte stores and unaligned stores. Seven native scenarios, both boards,
22 Python checks and 270 renderer sanitizer checks passed on
2026-10-10. Platform and structure regressions passed.
See [continuation contracts](../research/z7ii/boot_continuation.md) and
[continuation_boot_validation](../artifacts/continuation_boot_validation/report.json).

`tools/memory_boot_probe.py` follows stock reset beyond the original memory wait.
Physical RAM preload poisons the complete rounded clear extent and adds guards
at both ends. A physical dump checks every byte: success clears the extent;
forced error preserves it. Both roles verify status, the original wait return,
acknowledgement, stack and original page table. Success reaches the next entry;
error must remain in the stock fatal self-loop. Slave also runs the shared path.
All five scenarios passed on 2026-10-10. Board checks cover 373 words, valid fill,
invalid destination/alignment/count/stride/source rejection, selective
acknowledgement and reset clearing. Both boards, 22 Python checks and 270 renderer sanitizer checks passed. Continuation and structure
regressions passed. See [memory contracts](../research/z7ii/boot_memory.md) and
[memory_boot_validation](../artifacts/memory_boot_validation/report.json).

`tools/runtime_boot_probe.py` continues stock reset through library bootstrap,
two original cache-maintenance calls, a guarded 16 KiB page-table copy and the
original MMU switch. It checks 55 seeded state words, cursor/default data pointers,
secondary-release marker, the 48-byte RTOS configuration, cache-geometry stores
and 0x410 bytes of original state initialization with guards. Master/slave
stock and invalid-copied-table scenarios plus slave shared path passed on
2026-10-10. The negative controls invalidate only the copied code descriptor;
the original MMU switch must cause prefetch abort, then the descriptor is restored.
`tests/test_interrupts.py` uses an original synthetic ARM harness, with no camera
firmware: both machines deliver SGI 1 and secure physical timer 29, acknowledge
them and restore SVC state. The final IAR read must report spurious ID 1023.
These checks do not prove stock ISR behavior. Both board checks, 22 Python
checks and renderer sanitizer checks passed; memory and structure
regressions passed. See [runtime contracts](../research/z7ii/runtime_bootstrap.md)
and [runtime_boot_validation](../artifacts/runtime_boot_validation/report.json).
CI now includes the interrupt check; no remote CI run is claimed.

`tools/service_boot_probe.py` extends the native reset path through the five
initial core-zero services. It checks original GIC configuration, all service
returns, pool geometry, poisoned header slots with guards and four empty heap
lists. Seven scenarios passed: both roles' stock paths, invalid copied heap
sections, unsupported counter access faults and slave shared path. Successful
paths stop before the first read of `0x04266000`; the counter fault scenario
now disables the implemented device's MMIO interface.
Both boards' new RAM boundaries, 22 Python checks and renderer sanitizer
checks passed. Native structure and Windows `virt` structure regressions
also passed. See [runtime services](../research/z7ii/runtime_services.md) and
[service_boot_validation](../artifacts/service_boot_validation/report.json).

`tests/test_counter.py` checks virtual-clock progression, stop/resume, 32-bit
carry, split programming, reset and CPU-issued access faults on both machines.
`tools/counter_boot_probe.py` follows original reset through the counter callbacks,
18 kernel module returns and startup task creation/start. Seven scenarios cover
stock/seeded counters, disabled-interface data aborts and slave shared path.
Successful paths check four original peer-wait iterations at master `0xFE660`
or slave `0x30034`, requiring one peer and observing zero. No peer-ready value
is injected. These checks do not prove task execution or scheduler completion.
Board checks, SGI/timer delivery, 22 Python checks, renderer sanitizers and
service and structure regressions passed on 2026-10-10. CI includes the
synthetic counter check; no remote CI run is claimed. See
[counter contracts](../research/z7ii/runtime_counter.md) and
[counter_boot_validation](../artifacts/counter_boot_validation/report.json).

Recorded `virt` verification used Windows QEMU 10.0.0, Clang and LLVM
linker. The custom board was then built from the verified QEMU10.2.4 archive
with Clang18 in Ubuntu24.04 WSL; synthetic RAM/CPU checks and the stock boot
probes passed on that backend. Neither backend verifies natural boot, menu
rendering, master/slave cooperation, photo saving or installation. CI is
configured but has not been dispatched.

`tools/structure_probe.py` validates stock master and slave identities before
creating output. It runs three early ARM copy loops, four Thumb table copies and
one bounded zero record per role. Every copy uses poisoned destination memory,
checks every byte and preserves a trailing guard; the zero sample checks both
guards. The zero-length early loop must preserve four poisoned bytes.
`tests/test_board.py` exercises both custom machines with synthetic instructions.
See [startup structure](../research/z7ii/startup_structure.md) for commands and
the distinction between this validation and natural startup.

The 2026-10-10 structure validation passed on Windows QEMU `virt` and the rebuilt
QEMU10.2.4 native machines. Both synthetic board checks, 18 Python checks,
270 renderer sanitizer checks passed. Evidence is retained in
[structure_validation](../artifacts/structure_validation/summary.json).

`tools/smp_boot_probe.py` uses the stock reset entry on one or two execution
cores in each isolated role. Six scenarios verify the single-core wait,
secondary reset WFE and stack, original exclusive ready store with a held peer,
concurrent startup-task execution, source/copied page-table integrity and the
next unsupported device data abort (`DFSR=0x808`, `DFAR=0x2C090001`). The probe
does not write firmware instructions, registers, page tables or handshake words.

`tests/test_smp.py` uses firmware-free ARM code to check directed SGI 1 in both
directions, source CPU information in IAR, independent timer IRQ 29 delivery,
EOI and banked stack restoration on both cores. GIC MMIO is accessed by guest
instructions, which supply the required current-CPU context. The existing
single-core board, IRQ and counter checks and source/sanitizer suite also pass.
CI includes the synthetic SMP check; a remote run is not claimed. Commands and
limits are in [secondary startup](../research/z7ii/smp_startup.md), with compact
[validation evidence](../artifacts/smp_boot_validation/report.json).

After console integration, the SMP regression explicitly disables the console
interface to retain the same address boundary (`DFSR=0x1808`); the earlier
unmapped-device evidence remains unchanged. `tools/console_boot_probe.py` runs
four stock-reset scenarios: both roles complete ten original mixed-width stores
and restore their caller, while disabled-console controls abort on the first
byte store. Enabled paths continue into Thumb library initialization and fault
at `0x04280030` with `DFSR=0x808`.
`tests/test_uart.py` verifies actual character-backend bytes, register widths,
device-owned TX-ready, reset and ten unsupported-access cases per role using
synthetic ARM instructions. Native console text, RX and UART IRQs remain
unverified. See [console contracts](../research/z7ii/console_boot.md) and
[console evidence](../artifacts/console_boot_validation/report.json).

After pin-group integration, the console regression explicitly disables those
words to retain its recorded boundary (`DFSR=0x808`).
`tools/library_boot_probe.py` runs four stock-reset scenarios: both roles
verify the RAM-delivered 240-byte source table against the file-derived copy,
all 60 bank words, the master's modification results, caller restoration and
the next `0x04281138` boundary, while disabled controls abort on the first
`0x04280030` store. See [pin-group evidence](../artifacts/library_boot_validation/report.json).

After controller-chain integration, the pin-group regression disables those
words to retain its recorded boundary. `tools/controller_boot_probe.py` runs
four stock-reset scenarios: both roles verify the original counter delay,
22 stored words, the master/slave gate finals (`0x3000`/`0x4000`), caller
restoration and the next `0x20010044` boundary, while disabled controls abort
on the first `0x04281138` store. See
[controller evidence](../artifacts/controller_boot_validation/report.json).

After snapshot integration, the controller regression disables those words to
retain its recorded boundary. `tools/snapshot_boot_probe.py` runs four
stock-reset scenarios: both roles verify the RAM-delivered pointer table against
the file-derived list, the nineteen register reads, the restored gate value, the
zero-source bulk copy and the tail `0x20013000` store fault, while disabled
controls abort on the first gate store. See
[snapshot evidence](../artifacts/snapshot_boot_validation/report.json).

After parameter integration, the snapshot regression disables those words to
retain its recorded boundary. `tools/parameter_boot_probe.py` runs four
stock-reset scenarios: both roles verify all segment, block and scattered
words against their sources, the mirror window fill, the trigger lifecycle,
the nineteen-word register restore and the return to the chain; the master's
bounded continue then records the `0xBAB00000` fault while the slave's long
logging loop is recorded as a bounded timeout. Disabled controls abort on the
first `0x20013000` store. See
[parameter evidence](../artifacts/parameter_boot_validation/report.json).

After the kernel-handoff integration, the parameter regression disables those
words to retain its recorded boundary. `tools/kernel_boot_probe.py` runs seven
scenarios: both roles' stock runs verify the payload copy, the original `svc #6`
handoff arguments, vector dispatch and the unchanging wait object; both
peer-release runs perform the single stand-in wait-word write and verify the
flushed log is fault-free with both cores parked in the recovered dispatch
loops; the master stage-disabled control keeps the staging copy faulting; the
master tick-release run enables the experimental timer contract and verifies
repeated interrupt delivery, a dispatched task on the primary core (current-task
table nonzero in repeated samples, timer event mask latched) and a fault-free
flushed log while both cores stay inside the payload service block. See
[kernel-handoff evidence](../artifacts/kernel_boot_validation/report.json).

`tools/dual_boot_probe.py` boots both engines in the dual machine without
debugger writes to guest state: after a free window it requires every core inside its
engine's service block, both communication headers initialized (recovered
magic), the master current-task table active and a flushed log free of data
aborts with sustained kernel activity. The scenario records the natural
transport milestone. The descriptor-ready word retains experimental timing;
console output and menus stay unverified. See
[dual-boot evidence](../artifacts/dual_boot_validation/report.json).

`tools/peer_gpio_boot_probe.py` checks the original readiness output, the
complementary input and the polling continuation. Its disconnected scenario
keeps the input low and the original initialization task waiting.

`tools/transport_boot_probe.py` checks the original command exchange, channel
reset, communication initialization return, slave message callback and matching
producer/consumer indices through the shared message alias. It also checks the
original main task's initialization return, the firmware-installed controller
callback table and all four cores' fault status. Its disconnected
scenario cannot complete the startup exchange. These probes only observe
execution and memory; they do not establish complete startup or menu rendering.

The pin initializer regression uses instruction-count virtual time with both
cores advancing together. Secondary-only execution is kept in the separate
SMP regression; it cannot advance the instruction-count clock with the primary
held. This avoids host-speed timer starvation while preserving the original
pin initializer, restored caller state and unsupported-register controls.

Current local contracts are recorded in the [gate report](../artifacts/gate_boot_validation/report.json),
[runtime wait report](../artifacts/runtime_wait_validation/report.json),
[memory transfer report](../artifacts/sequencer_boot_validation/report.json),
[readiness report](../artifacts/peer_gpio_validation/report.json) and
[transport report](../artifacts/transport_boot_validation/report.json).
These reports explicitly leave complete boot and menu verification false.

`tests/test_spi.py` checks the bounded serial FIFOs and both interrupt lines
with synthetic instructions on each engine. `tools/spi_boot_probe.py` observes
the original driver configuration and its queued, checksum-valid request at
the disconnected controller boundary. Capacity 64 and latency 100 us are
experimental choices; controller replies and panel behavior remain unmodeled.
See the [serial bus evidence](../research/z7ii/serial_bus.md) and
[stock serial report](../artifacts/spi_boot_validation/report.json).

```sh
python tests/test_spi.py --qemu .build/build/qemu-system-arm --destination .local/spi-check
python tools/spi_boot_probe.py --qemu .build/build/qemu-system-arm --master /path/to/eg1840_mas_01700.bin --slave /path/to/eg1840_sla_01700.bin --destination .local/spi-stock-check
```

`tools/controller_core_probe.py` starts the original controller image from its
reset vectors in an isolated machine. It verifies clock setup, vector relocation,
software interrupt dispatch, runtime timer configuration and return from pin setup.
It also observes return from the original calendar access setup, including its
native context and backup-access enable. Full calendar initialization is unverified.
The original disconnected bus configuration must return zero with its driver ready
and the peripheral enabled; this does not verify interrupt-driven transfers.
The subsequent original pin cleanup must return without faults and restore the
bus pins to input mode.
The trace must contain the original bus event and error exception dispatches;
synthetic checks cover both buses' mapped pending bits and acknowledgement.
The original DMA initializer must return ready with its recovered stream
configuration and no faults. Actual peripheral DMA requests remain disconnected.
The original compare timer must return ready with prescaler 49 and limit
0xffff, then dispatch its stock shared handler through exception 42 with
the compare flag and interrupt enabled, without faults.
Raising and lowering the external G7 input must enter the stock interrupt
dispatcher through exception 39 and return with its edge acknowledged and no
faults. This does not prove that the serial service has started.
Disabling clock completion must preserve the original wait without vector copying
or faults. The execution core and clocks remain experimental; controller wiring
and menu output remain unverified. See the
[controller evidence](../research/z7ii/controller_core.md).

```sh
python tools/controller_core_probe.py --qemu .build/build/qemu-system-arm --firmware /path/to/ex1840_013000.bin --destination .local/controller-core-check
python tests/test_controller_gpio.py --qemu .build/build/qemu-system-arm
python tests/test_controller_rtc.py --qemu .build/build/qemu-system-arm
python tests/test_controller_i2c.py --qemu .build/build/qemu-system-arm
python tests/test_controller_i2c_targets.py --qemu .build/build/qemu-system-arm
python tools/controller_i2c_probe.py --qemu .build/build/qemu-system-arm --firmware /path/to/ex1840_013000.bin --destination .local/controller-i2c-check
python tests/test_controller_routing.py --qemu .build/build/qemu-system-arm
python tests/test_controller_dma.py --qemu .build/build/qemu-system-arm
python tests/test_controller_timer.py --qemu .build/build/qemu-system-arm
python tests/test_controller_position.py --qemu .build/build/qemu-system-arm
python tests/test_controller_actuator.py --qemu .build/build/qemu-system-arm
python tests/test_controller_switch.py --qemu .build/build/qemu-system-arm
python tests/test_controller_flash.py --qemu .build/build/qemu-system-arm
python tools/controller_flash_probe.py --qemu .build/build/qemu-system-arm --firmware /path/to/ex1840_013000.bin --destination .local/controller-flash-check
python tools/controller_start_probe.py --qemu .build/build/qemu-system-arm --firmware /path/to/ex1840_013000.bin --destination .local/controller-start-check
python tests/test_controller_adc.py --qemu .build/build/qemu-system-arm
python tools/controller_power_probe.py --qemu .build/build/qemu-system-arm --firmware /path/to/ex1840_013000.bin --destination .local/controller-power-check
```

The synthetic clock check covers protection keys, configuration status, twenty
backup words, reset and unsupported-access faults, plus disabled completion.
Calendar advancement and alarm interrupts are absent from the current model.
The bus check covers disconnected address NACK, START, STOP, software reset,
unsupported-access faults and disabled START completion on both ports.
The attached-target check covers both buses, address acknowledgement sequencing,
wrapping register pointers, repeated START, one/two/three/four-byte receive tails,
buffer interrupt masks and reset. The stock transfer probe checks identity reads
with and without an explicit experimental register bank, and requires the stock
configuration routine to validate its own writes by reading them back. A separate
auxiliary fixture checks the stock four-byte status receive and classification. The fixture
is register storage, not a physical power device model; power readiness remains
unverified. See the [bus contract](../research/z7ii/controller_i2c.md).
The DMA check covers sixteen streams, equal byte/halfword/word widths, guarded
memory copies, completion and error interrupt acknowledgement, unsupported
parameters, peripheral request waits, cancellation and reset. It does not verify
firmware peripheral transfers or migration. See the
[DMA contract](../research/z7ii/controller_dma.md).

The timer check covers hardware compare/update events, software events, mask
gating, shared interrupt acknowledgement, one-pulse stop, reset, rejected
accesses and disabled hardware completion. See the
[timer contract](../research/z7ii/controller_timer.md).

The position check exercises C6/C7 routing to TIM3 only with alternate function 2
selected, independent channels, edge polarity, captured-value acknowledgement,
simultaneous EXTI delivery, unchanged-level suppression and reset. It supplies
external pin levels; it does not model a motor or prove photo completion.

The actuator check separately exercises the optional PWM-driven peer with one
nanosecond instruction counting. It checks default-disabled behavior, AF1 pin
selection, both directions, captured position edges, disabled counter/channel,
equal-drive braking, restart and whole-board reset. The peer uses a functional
speed rather than measured camera calibration; controller-local reset leaves its
physical position intact while the reset PWM and GPIO configuration stop drive.

The switch check exercises external levels, pull override, reset retention and
output isolation. The routing check covers all sixteen pins, all eight ports,
rising and falling edges, masks, grouped interrupts and physical switch input.
The stock probe checks both switch levels at pin G5 and native acknowledgement
of G7 edges; this does not prove a complete power transition.

The converter check covers three banks, independent channels, four resolutions,
alignment, status acknowledgement, shared EOC/overrun interrupts, reset,
cancellation, unsupported requests and disabled completion. Inputs are explicit
experimental codes. The stock power probe observes three original conversions
and their average, plus the disconnected and disabled-completion paths. It does
not verify power readiness or menu output. See the
[converter contract](../research/z7ii/controller_adc.md).

The resident flash check covers the exact data window, both flash addresses,
preserved surrounding program bytes, reset, unchanged input files and rejection
of invalid lengths or occupied windows. The supply input check covers D13 and E9 levels,
pull override and reset retention. The stock flash probe distinguishes invalid
configuration headers and both supply levels, then observes the original battery
preparation gate with explicit experimental data. Gate acceptance does not verify
the power-ready event or menu output. See the
[resident data contract](../research/z7ii/controller_flash.md).

The stock start probe uses the original image and default controller inputs, with
no resident data or analog sample fixture. An explicit register bank at address
0x4f must allow the stock power-ready event, the original initialization wait to
receive bit 0, and entry into transmit initialization without faults. Removing
the target must preserve the original failed configuration and shutdown path.
Serial transfers and menu output remain unverified. See the
[start evidence](../research/z7ii/controller_start.md).

`tests/test_controller_rng.py` checks random data readiness and consumption,
retained unread data when disabled, interrupt masking, reset, access bounds and
disabled completion. Stock combined execution crosses the original random data
read and delivers the configuration message without the previous bus fault.
See the [random source contract](../research/z7ii/controller_rng.md).

`tools/graphics_boot_probe.py --icount-shift 0` selects the instruction timing
used for the resident-data observation. The default remains 4. Reports record
the selected shift and the system controller mode, configuration flags and
cached power input alongside application and graphics observations. These fields
describe current firmware state; they do not establish normal startup or menus.

The graphics report's `idle_timer` records the application timeout policy,
its destination message and the last timer-start interval. The interval is
neither remaining time nor proof that the timer is active. Native observation
correlates slot 0's `0x03000003` message with the subsequent mode request;
see the [startup timeout evidence](../artifacts/startup_idle_timer_validation/report.json).

`tools/menu_navigation_probe.py` opens the original menu with a held menu
input and then presses each requested expander input once inside it. The
report records decoded switch deltas, the foreground index and per-row frame
differences; it never writes firmware state or substitutes callbacks. The
menu must stay foreground for a step to count, so inputs that leave the menu
end the useful sweep order. Reopening the menu after it closes remains
outside the probe; see the
[input map evidence](../artifacts/menu_navigation_validation/report.json).

`tools/menu_boundary_probe.py` measures where a menu key press stops after
the shooting application has fully stabilised. It reads the application
input-method key parameters from their descriptor-resolved storage, records
the input request ring indices across the key edges, and observes the
application action router through a single observation point. The passing
report shows the menu action `0x1c` repeatedly routed while no application
switch request appears and the foreground stays on the shooting application;
it documents the steady-state boundary without writing firmware state. Only
one software breakpoint is used per run because this QEMU reports just the
first inserted one. See the
[steady-state boundary evidence](../artifacts/menu_steady_boundary/report.json).

The frame synchronization source has a firmware-free qtest
(`tests/test_frame_sync.py --qemu ...`) covering period, pending and
acknowledgement behaviour, role isolation and reset. The browser console
holds a quick menu click until the foreground leaves the shooting
application; `checks.test_web_console` covers that hold, its expiry and
cancellation without firmware.

`tools/menu_interaction_probe.py` boots with the periodic frame
synchronization source and the controller key interrupt wired, the same
combination the interactive console uses. After the shooting application has
stabilised well beyond any startup window, it taps the menu input for a tenth
of a guest second and requires the original menu application to become
foreground, then taps the exit input and requires the shooting application
back. Both presses are short taps; nothing is held and no firmware state is
written. The run also records whether a later second menu tap reopens the
menu: a capture status raised while the menu application runs is not cleared
in this combination, so the reopen stays a documented boundary. See the
[steady-state interaction evidence](../artifacts/menu_steady_interaction/report.json).

`tools/console_interaction_check.py` repeats that acceptance through the
browser console's own local HTTP interface, the same path a person uses. Each
cycle restarts the console machine in place, waits for the shooting
foreground, settles far past the old startup window, then performs exactly one
short menu click and one short exit click; a cycle passes only when the
foreground switches to the menu application and back on those single clicks.
The real-time virtual clock stays unusable here (the machine never reaches the
foreground under it), and accelerating the guest clock with a larger
instruction-count shift breaks startup the same way, so the acceptance runs
on the default clock. See the
[single-click console evidence](../artifacts/console_single_click/report.json).

`tests/test_boot_store.py --qemu .build/build/qemu-system-arm` checks the
engine boot store with synthetic marker images only: the stored first image
runs, the store is reprogrammed through the monitor, and a whole-machine
reset restarts the core at the image entry so the second image runs. This is
the experimental console's image-property reset contract, without firmware.
The check also places a CRC-valid decoded container with an unauthenticated
header in RAM: default resets must keep the stored image. Explicitly enabling
`harvest-update` permits the laboratory fixture to boot; a damaged container
or disabling that option keeps the stored image as the reset source. See the
[decoded-window opt-in checks](../artifacts/decoded_window_opt_in/report.json).

`tools/update_window_probe.py` explicitly enables
`nikon-z72-boot-store.harvest-update=on` and checks a laboratory decoded-window
fixture: a preloaded package boots as its own master member after a machine
reset and survives a second reset, while a
one-byte-corrupted copy is rejected by the container CRCs and keeps the
stock master running. The fixed window address is supplied by the experiment;
native service execution allocates its own package buffer. This does not
execute native flash programming or establish update authentication. See the historical
[update window evidence](../artifacts/update_window_harvest/report.json).

`tools/menu_fwupdate_probe.py` sweeps the original menu pages with real key
presses, walking every tab to its lower items and pressing OK while an
observation point on the firmware-management eligibility entry reports
whether the key path alone reaches the update service. See the
[menu navigation evidence](../artifacts/menu_fwupdate_navigation/report.json).

`tools/card_slot_probe.py` boots the original machine and stops on the
runtime write that registers the card slot driver table (0xB18105BC),
recording the table, the per-slot driver objects and every function
pointer resolved to a master file offset. See the
[card slot table evidence](../artifacts/card_slot_table/report.json).
Use `--registration-only` for a read-only startup check that stops after
observing the table; it skips forced slot enable and the later key sequence.
`--sd-card-image` enables the optional hosts and attaches a raw card before
boot; `--sd-card-engine master|slave` selects its owner, defaulting to slave.
The card uses an overlay. The
[runtime startup observation](../artifacts/sd_runtime_startup/report.json)
records the shooting foreground with both slot enable bytes still zero.

`tests/test_sd_host.py --qemu .build/build/qemu-system-arm` exercises the
optional `sd-host` profile with a synthetic card image in snapshot mode. It checks
the link prerequisites, the active-low clock request, controller reset,
card address assignment and a complete 512-byte PIO sector read. It also
checks PCIe INTA status and GIC input 243 assertion, acknowledgement while
the source remains high, and deassertion after SDHCI status clear. The host
uses QEMU's SDHCI implementation at the firmware-derived first BAR.
This check does not execute firmware or establish its filesystem path.
The check covers a 1 MiB SDSC card and a 4 GiB SDHC card, verifies the OCR
capacity bit, uses byte and sector command addresses respectively, and reads
back aligned/mixed-width PIO and ADMA writes while preserving sector zero.
Native capture probes use a complete image larger than 2 GiB: their observed
command addresses are sector numbers. Reducing an image to 512 MiB changes
the device to SDSC byte addressing even if its partition still fits.
The [SD host validation record](../artifacts/sd_host_validation/report.json)
identifies the compiled binary and the checks that passed.

`tools/sd_native_probe.py --qemu .build/build/qemu-system-arm
--ram-dump .local/card-ram.bin --destination .local/sd-native` executes the
captured card workers with the recovered MMIO windows forwarded to QEMU.
It creates a temporary blank card by default; `--card-image` selects a raw
image, with all writes confined to an overlay. The SD completion wait uses
actual QEMU status and a 1 ms device-clock step. ADMA2 descriptors and
transferred buffers are synchronized between the two execution memories;
other RTOS service/caller combinations stop immediately. Firmware execution
remains bounded. The
[native SD host record](../artifacts/sd_native_host/report.json) proves an
original open return of zero and a DMA first-sector digest matching its
input image. A one-byte damaged boot signature still reads successfully
but the original open rejects it with -830; see the
[negative control](../artifacts/sd_native_bad_signature/report.json).
`--slot-query` reaches the filesystem task's unmodeled response wait,
recorded in the [filesystem boundary](../artifacts/sd_native_slot_query/report.json).
`--list-directory` continues after the slot query: the probe calls the
original directory functions on the synthetic FAT card. The current record
shows the volume recognized (mount state two, not mounted) and the original
directory open returning the original not-mounted status; the filesystem
worker's mount operation and its nested task forward remain the boundary.
A synthetic FAT16 card can also be built with `.local/build_fat16.py`
style scripts; the shipped runs use one containing the stock update
package under its 8.3 short name. See the
[mount boundary evidence](../artifacts/sd_native_mount_boundary/report.json).

Card-open checks alone do not establish a mounted filesystem or native menu update.

`--list-directory B:\` on `tools/sd_native_probe.py` now checks the original
directory open, enumeration, native end marker `0x80000030` and close.
The SD logical slot maps to B, while the other slot maps to A. No manual
per-volume mount option is required for this path. `--find-update` then
runs the original update filename finder with an explicit SD-root selector.
The [card directory case](../artifacts/native_update_card_directory/report.json)
selects the stock package's short name and length from actual FAT records;
the [no-candidate case](../artifacts/native_update_card_no_candidate/report.json)
reaches normal directory end and selects nothing. The latter intentionally
has `passed=false` because its requested candidate is absent.
`--read-file` records the remaining asynchronous SDK file-open boundary;
it does not supply file bytes from the host or report update acceptance.
The read-only message trace records the native send result and shared queue
indices. The [message boundary](../artifacts/native_file_message_boundary/report.json)
shows resource 9, operation 13 queued with no consumer in the bounded snapshot.
This distinguishes an unprocessed request from a package verification rejection;
the peer file service and its reply still require execution on the second engine.
With `--sd-card-image`, `tools/card_slot_probe.py` also records PC, CPSR and
instruction/data fault registers for all four engine cores. Its `passed` field
only covers table registration; inspect `engine_fault_free` before treating the
peer as running. The [startup boundary](../artifacts/pcie_sd_startup_boundary/report.json)
records configuration progress followed by an unsupported SD-host extension read.
That historical extension boundary is now covered by the conventional SD
profile's read-only UHS-II capability snapshot. The native file diagnostic is:

```sh
python tools/filesystem_peer_probe.py --qemu .build/build/qemu-system-arm \
  --master master.bin --slave slave.bin --controller controller.bin \
  --card-image card.raw --reference marker/PROBE.TXT --destination .local/peer-file
```

Use `--camera-path` for a different card filename. The reference supplies only
comparison bytes, capped at 64. Queue requests and the open-reply client are
explicit fixtures; native peer file handling, data-copy dispatch and its reply
must run. Success requires matching bytes, a successful copy acknowledgement
and fault-free engine states. This does not execute the SDK sender or menu caller.
The [native peer file record](../artifacts/native_peer_file_read/report.json)
checks both a 20-byte marker and a 64-byte prefix of the stock update package.
The negative observation before byte-copy support records success from the file
service alongside a failed copy acknowledgement and zero destination bytes.
The content comparison correctly rejects that observation.

To make a new synthetic FAT card from a directory, use `qemu-img convert
-f raw -O raw fat:/path/to/directory card.raw`, then `qemu-img resize
-f raw card.raw 512M`. The conversion creates a 504 MiB disk; extending it
to a power of two satisfies the SD device's size requirement. The original
directory remains outside the emulator's write path. The SVC return-stack
regression is `python -m unittest checks.test_card_worker -v`.

`tools/sdk_file_probe.py` checks complete file transport through the original
SDK on a native task stack, including open, repeated reads, EOF and close:

```sh
python tools/sdk_file_probe.py --qemu .build/build/qemu-system-arm \
  --master master.bin --slave slave.bin --controller controller.bin \
  --card-image card.raw --camera-path 'B:\Z7_2_0~1.BIN' \
  --reference Z7_2_0170.bin --destination .local/sdk-file
```

The supported SDK entry addresses are checked against both engine image
hashes. A temporary resource-8 caller invokes original SDK functions; original
senders, filesystem tasks and replies execute without host answers. Each guest
block is captured through the monitor and compared with the reference, which
does not supply bytes to the guest. Success requires matching whole-file length
and SHA-256, the SDK success value for open/read/close, native EOF, an invalidated
handle after close, restored task stack and fault-free engine states. Card writes
use a temporary overlay. The [SDK file record](../artifacts/native_sdk_file_read/report.json)
covers a marker, the entire stock update package and a missing-file negative case.
The missing file intentionally exits with failure and records open error
`0x043A0084`, without entering SDK read or close.

`--find-update` first invokes the original update filename finder with SD selected
and the existing other-root fallback flag retained. The current live observation
returns `0x80001003` while resolving unregistered local volume `B:`. It intentionally
fails verification before SDK open; this is neither a package authentication
result nor a menu update result. The selector and callbacks are restored on exit.
The earlier bounded directory experiment and this live native-task diagnostic
have different initialization and scheduling conditions; neither substitutes
for the normal menu service's media setup. Whole-file transport does not establish
native update authentication, programming or restart acceptance.

The live update collection path has a separate diagnostic:

```sh
python tools/native_update_collect_probe.py --qemu .build/build/qemu-system-arm \
  --master master.bin --slave slave.bin --controller controller.bin \
  --card-image card.raw --expected-path 'B:\Z7_2_0~1.BIN' \
  --destination .local/native-collection
```

This calls original collection entry `0x1039D984`, mode 0, through a temporary
resource-8 caller. It selects SD explicitly and restores the selector afterward.
Original SDK directory existence/enumeration, directory callbacks, candidate file
reads, classification, record construction and allocation cleanup run on native
tasks. The local `B:` lookup failure from `--find-update` does not prevent this
SDK directory path. Observation points record the first visit to each stage;
they do not replace replies or change guest registers to skip work.

`--expected-path` requires exactly one whole-camera candidate with that exact
path, category 4 and package flag 1. Omit it for a card without any matching
upgrade package: successful collection must return normally with zero matches
and an empty whole-camera record. Both cases also require native stage visits,
released directory vectors, restored callbacks/selector/task stack and zero
fault status on all four engine cores. See the
[native collection record](../artifacts/native_update_collection/report.json).
Candidate collection does not authenticate the package, activate menu dispatch
or exercise storage programming and restart.

Add `--execute-service` to the collection diagnostic to check the original
service's authentication rejection with the default laboratory boot material.
It calls the original card-log initializer, selects record 13, checks propriety
and requests execution only if that check succeeds. The original allocator,
worker task, whole-package read/decode/SHA-1, completion event, error logging
and return to the caller must execute. The option expects rejection with zero
raw boot-window material; a passing diagnostic does not mean installation was
accepted. It checks service results and reasons, buffer release, event mask
`0x20`, restored caller state and fault-free cores. See the
[native service record](../artifacts/native_update_service/report.json).

The complete encoded guest buffer is captured in 512 KiB pieces for SHA-256
before native decoding; capture files are temporary and never supply input to
the guest. A slow monitor reply is awaited on the same command and connection.
Native decode and SHA-1 may take several minutes: unchanged message indices do
not establish a stall, so service observations also sample all engine PCs and
fault registers. The ordinary collection-only case retains its shorter bound.

`tools/card_worker_probe.py` loads a captured machine RAM snapshot into a
bounded environment, forces the SD logical-slot enable byte and runs the original
card worker entries, recording the executed chain and every peripheral
access; the snapshot comes from `tools/card_slot_probe.py --ram-dump`.
See the [card worker evidence](../artifacts/card_worker_execution/report.json).

`tools/console_update_check.py` drives the menu-gated firmware update over
the same HTTP path with a signed update file and its eight boot-window key
bytes supplied from outside the repository. It requires an install attempt
outside the menu to be rejected, opens the menu with one click, verifies the
whole-file digest, installs, and verifies the machine resets and reboots —
inside the same emulator process — onto the installed image and reaches the
shooting foreground again, checking the guest-visible version record of the
booted image; `--verify-restart` reboots once more through a full process
restart to prove persistence and `--verify-rollback` returns to the supplied
stock master through the same machine-reset path. The firmware-free sides
are `checks.test_update_store` (synthetic structure images: candidate
acceptance/rejection and store lifecycle), `checks.test_upgrade_signature`
(synthetic tables: digest formula, signed round trip, wrong-key/tamper/
marker rejection) and the update cases of `checks.test_web_console` (staged
signature check, menu gate, identical-firmware refusal, stock fallback on a
broken store, status reporting). See the
[menu update evidence](../artifacts/menu_update_validation/report.json).

`tools/sensor_frame_probe.py` boots the combined machine with the console
inputs and samples the recovered capture chain after the shooting foreground
stabilises: the capture control block, the capture event byte, operation
14's completion slot, the second-level interrupt registrations, the sampled
result window and all three synchronization banks. Without arguments it is
the survey (the chain sits parked with the sampling mask armed and no
producer); `--sample-source` arms the laboratory sensor-sample source and
adds a menu open/exit/reopen sequence, and `--sample-lines` sweeps the held
result-word pattern. `tests/test_input_events.py` covers the third
synchronization bank contract (latching, mask routing, write-one
acknowledgement, level retention, reset and engine isolation) and the
result-window write rejection. See
[sensor sampling research](../research/z7ii/sensor_frames.md).

`tests/test_input_dma.py` also checks the optional `frame-process` path:
native port/sequence gating, validation of all three output descriptors before
any writes, four destination slots, independently specified luminance values,
neutral chroma, padding/guards, completion status acknowledgement and reset.
It exercises the full-scale RAW12 monochrome model with synthetic firmware-free
descriptors. This does not qualify native live view or photography; see
[processing contracts and runtime evidence](../research/z7ii/display_output.md).
