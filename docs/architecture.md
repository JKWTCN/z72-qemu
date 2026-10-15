# Z72 instruction laboratory

The custom board runs one Cortex-A7 execution CPU by default, supports `-smp 2`,
and supplies RAM at:

| Address | Capacity | Purpose |
| --- | --- | --- |
| `0x04008000` | 4 KiB | Temporary stock boot stack and secondary-release address |
| `0x10000000` | 64 MiB | Master mapped at `0x10020000`, including experimental tail |
| `0xB1800000` | 1 MiB | Native scatter destination |
| `0xB1900000` | 7 MiB | Boot memory-clear range between existing RAM windows |
| `0xB2000000` | 12 MiB | Display state and synthetic stack |
| `0xB2C00000` | 51 MiB | Original runtime heap beyond state RAM |
| `0xB5F00000` | 1 MiB | Fourth initialization-table copy |
| `0xB7C00000` | 1 MiB | Master communication RAM zero sample at `0xB7CF0000` |
| `0x40100000` | 1 MiB | Synthetic harness, vectors and adapted TTBR |

These capacities and the CPU type are explicit laboratory choices. They are
not a recovered DRAM map or processor identification. Both execution cores
belong to the selected role; they do not stand for the two EXPEED chips.
No inter-engine peripheral is executed.

The separate `nikon-z72-slave-lab` machine supplies the same code/harness windows,
10 MiB at `0xC1000000`, 54 MiB at `0xC1A00000`, 1 MiB at `0xC5000000`
and 1 MiB at `0xC6000000`. The added RAM completes the decoded slave runtime
heap `0xC1940000..0xC5000000`; its first 6 MiB already occupies state RAM.
It executes selected slave initialization routines in isolation. Both images use
the same code base, so loading them together into one address space is incorrect.
Communication windows are ordinary RAM with no transport or interrupt behavior.

The generic loader preloads the complete master and sets PC to a synthetic ARM
harness. The harness enables short-descriptor MMU translation. Relevant native
section attributes are preserved, while physical bases target the lab's RAM.
The `virt` backend translates to its own RAM; the `nikon-z72-lab` backend uses
the studied software address windows directly. Neither configuration executes
the camera loader or proves its load length.

The host selects the original ARM copy loop `0x1002BE74..0x1002BECC`, checks
all 716,216 copied bytes, then drives the two original Thumb display predicates
at file offsets `0x600348` and `0x539EE0`. Exhaustive DISP values check native
continuations, R0, R4, SP and LR. Missing-tail stepping is bounded; XN must cause
prefetch abort. Candidate identity must equal the deterministic known patch.

The custom board provides four early configuration words at `0x04264000`,
`0x04264020`, `0x04281028` and `0x0428102C`, with 32-bit storage, reset clearing
and device state serialization. Reset values are experimental; hardware clock,
power and pin effects are unresolved. Both roles have the temporary stack RAM.
The first system batch adds two slave selector words and 57 system configuration
words, for 63 in total. Two sparse containers expose only these word locations;
their holes remain unassigned. The completion stage extends this to 103 words,
with three bit-0 completion/acknowledgement words and a read-only zero result.
Selected control/command stores publish completion synchronously by default;
`-global nikon-z72-boot-config.auto-complete=off` disables completion for stock
timeout tests. These are experimental contracts, not recovered hardware timing.
The platform stage extends the sparse map to 348 words, including 40 explicit
control/status pairs and two read-only result words. Both channel blocks use
the same completion policy. The uint32 property
`-global nikon-z72-boot-config.blocked-control=0x20024100` selectively inhibits
one command while other pairs continue normally; its default is zero.
Status acknowledgement uses experimental write-one-to-clear semantics.
The final two group status bits remain pending because stock code writes the
preceding status word after these polls. Device state format is version 4 and
rejects earlier layouts. Hardware timing and actual training remain unresolved.
The continuation stage adds 24 exact words (372 total), covering the two boot
configuration blocks, `0x04281020` and nine memory-initialization setup words
at `0x20070000`. The boot memory stage adds status `0x20070008` (373 words total).
Command 1 at `0x20070010` interprets the observed zero-source/16 KiB setup as a
bounded synchronous zero fill. Destination and rounded size must fit the
role's RAM extent, master `0xB1800000..0xB2C00000` or slave
`0xC1000000..0xC1A00000`; invalid setups produce error bit `0x10` without writes.
Successful clearing publishes bit 0; status uses write-one-to-clear acknowledgement.
`-global nikon-z72-boot-config.memory-init-error=on` forces the error path without
clearing RAM. Zero-fill semantics, block rounding and timing are experimental.
The current device state format is version 6 and rejects earlier layouts.
See [boot memory](../research/z7ii/boot_memory.md).
The native boards now set CBAR to the experimental `0x04000000`, with a standard
QEMU GICv2 distributor at `+0x1000` and banked CPU interface at `+0x2000`.
The GIC has 256 interrupt slots, security extensions and one interface per CPU.
CPU generic-timer outputs connect
to PPIs 30 (nonsecure physical), 27 (virtual), 26 (hypervisor) and 29 (secure
physical) in each core's private input bank; IRQ and FIQ outputs connect to the
corresponding CPU. Affinities are 0 and 1. Firmware derives its GIC
addresses from CBAR and configures timer interrupt 29. Base, GIC revision and
wiring are laboratory choices; synthetic SGI/timer delivery is verified, while
stock interrupt handlers and actual hardware layout remain unverified.
The board has no LCD; complete machine migration is unverified.
Unmapped hardware accesses are not masked by a catch-all device.
Original core-zero service initialization now configures GIC and initializes
the runtime pools and four empty heap lists. A separate bounded counter device
at `0x04266000` now executes the original reset/frequency/enable callbacks.
Its 64-bit MMIO count uses the CPU's virtual-clock period, freezes when stopped
and resets with the machine. CPU CNTFRQ is declared as 48 MHz; upstream integer
nanosecond rounding yields a 20 ns tick. MMIO gating and reset do not alter the
CPU counter's origin or gating. Unsupported widths, holes and programming
requests abort. The counter state format is version 1; full migration remains
unverified. See [counter contracts](../research/z7ii/runtime_counter.md).
The `nikon-z72-dual-lab` machine runs both engines at once: four cores in two
pairs, each engine with a private address-space view (its code RAM, private RAM
windows, GIC, configuration banks, counter, console, notification source and
tick timer are per-engine instances) while the two 1 MiB message RAMs are one
shared storage each, mapped at the native address in both views through alias
regions - firmware literals reference the peer communication area directly.
Boot images load per view through the loader's CPU argument. In this machine
both engines boot naturally to their schedulers without any stand-in writes;
see [kernel handoff](../research/z7ii/kernel_handoff.md).
The `nikon-z72-timer` device maps the timer family at `0x2B000000..0x2B003000`
under the release-path gate. Firmware analysis recovered the block's role: the
kernel stores a channel mask into the event word (`+8`, observed `0x300`) and
services it through dispatch line 237, whose handler reads the word, calls one
callback per set bit pair and writes the serviced bits back. The device latches
the armed mask into the event and channel-status words (`+8`/`+0x10`) at a
selectable period (`timer-tick-us`, default 1 ms) and holds the line asserted
until the write-back; all other words are passive storage, and `timer-tick=off`
keeps the whole block at its previous passive/unmapped boundary. The period
unit and real channel timing remain unconfirmed; the isolated slave never arms
this timer. Its device state format is version 1; see
[kernel handoff](../research/z7ii/kernel_handoff.md).
Original kernel initialization and task creation/start reach the wait for one
additional core in the default single-core machine. With two cores, each loader
sets its original reset entry, the secondary consumes the original release
marker and publishes peer readiness, and the scheduler enters the startup task.
The next byte store at `0x2C090001` aborts because that device is unimplemented.
See [secondary startup](../research/z7ii/smp_startup.md). The SMP probe changes
debugger run control only, without register or instruction patches.
The bounded `nikon-z72-uart` device now maps one 16-byte console port at
`0x2C090000`. Byte registers 0..3 and halfword registers 4, 6 and 12 cover the
original initialization and transmitter. TX-ready bit 1 is device-owned;
halfword data writes latch their value and synchronously send the low byte to
an optional character backend. Unsupported widths and holes abort. Reset
clears configuration; its device state format is version 1. RX, UART interrupts,
baud timing and full machine migration remain unmodeled/unverified.
Stock initialization now returns past the pin-group stage: the library
initializer stores `0x04280030`, copies twelve five-word groups into
`0x04282000..0x04282428` and applies the original read-modify-write pairs
(master only). Those 61 words are passive storage in `nikon-z72-boot-config`
(state format version 7); `pin-config=off` leaves them unassigned for the
negative control. The controller-chain stage then completes the original `0x04281000`
sequence, counter delay, derived `0x04280000` words and the polled
`0x04287000` gate (state format version 8; bit 0 of `0x04287004` is
device-owned ready, `controller-config=off` leaves the block unassigned).
The snapshot stage then gates `0x20010044` and dereferences nineteen
recovered pointers into twenty passive storage words plus a zero-initialized
0x800-byte source window at `0x20014800` (state format version 10;
`snapshot-config=off` leaves the block unassigned). The parameter stage then executes the whole tail restore across 211 passive
storage words, the 0x800-byte mirror window at `0x24074000` and a
device-owned ready bit on `0x20010038` (state format version 12;
`parameter-config=off` leaves the block unassigned), returning to the chain.
The master board adds a one-miB staging RAM window at `0xBAB00000` for the
payload copy that follows; both roles then run into long compute paths beyond
the bounded probe wait.
See [console startup](../research/z7ii/console_boot.md),
[pin groups](../research/z7ii/library_boot.md),
[controller chain](../research/z7ii/controller_boot.md) and
[configuration snapshot](../research/z7ii/snapshot_boot.md).
The GPU renderer backs the master graphics upload window;
menu-level command submission and display contracts remain pending.

`tools/early_boot_probe.py` follows the original reset path through both first
stores, the no-op boot hook and the configuration routine's two stock delay loops.
It stops at system initialization offset `0x394`. See
[early configuration](../research/z7ii/early_configuration.md) for the register
contract and unresolved hardware effects.

`tools/structure_probe.py` executes three early ARM copy loops and all four Thumb
initialization-table copies per role, plus one bounded zero record. The third
early loop has zero length while the third table copy does not. These experiments
use the native routines with poisoned destination memory and guard checks; they
do not execute the complete startup or initialization dispatcher. Firmware
structures and address semantics are described in
[startup structure](../research/z7ii/startup_structure.md).
