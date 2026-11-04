# Optional master NVMe storage

The optional `nikon-z72-boot-config.nvme-drive` property selects an existing
raw block backend for the master engine. The browser and body probe expose
it as `--nvme-card`. The slave SD host remains available independently.
Without the property, the previous passive master PCI configuration model
remains selected. The optional host is explicitly unmigratable.

The host forwards PCI configuration and BAR transactions to QEMU's GPEX and
NVMe devices. QEMU owns queue processing, PRP DMA, completion generation,
namespace geometry and block I/O. Firmware owns discovery, partitions and
filesystems. There is no host filesystem service or command-success shortcut.
The console uses a temporary write overlay for this image; its existing SD
card export does not export NVMe writes.
For body-probe diagnostics, `--capture-nvme-copy .local/new-card.raw` creates
an exclusive persistent NVMe clone. `--capture-card-copy` still selects the
separate SD copy. The probe records the two destinations independently.

## C 1.70 contract

These observations use the master image SHA-256
`478caf02dba41fa9144c0c4b6e1a051dc556d40e51a79a308bdd1169efb9dbbe`.
Function addresses are specific to that image.

| Interface | Firmware observation | Model |
| --- | --- | --- |
| Presence | `105167fe`, route 3, samples `2b000010` raw bit 2 and filtered bit 10; `105162a2` tests the filtered result before host initialization | Static inserted level follows successful endpoint attachment, independently of training |
| Configuration | `10517b24` computes root DBI `2a900000` and external CFG0 `2a800000` from distinct selectors | Separate root configuration and external NVMe function |
| Outbound windows | `10517b40` programs index 0: type 4, `2a800000..2a80ffff`, target 0; index 1: type 0, `2a810000..2a8fffff`, target `2a810000` | Only these enabled windows forward transactions after training |
| BAR access | `10754846` accesses BAR base `2a810000` with byte, word or DWORD widths | Transactions forward to the native PCI memory address space |
| I/O availability | `10517720` reads PHY `210`; `1049d7c0` and `1049d800` require a nonzero result before dispatching block I/O | Read-only functional guard requires an active window/link and native CSTS.RDY without CSTS.CFS; full hardware bit encoding is unknown |
| Training | `10517ed8` configures PHY role `14`, `0c` low bits 3 and `50` bit 8; `1051811e` waits for state `11` through `10517212` | A functional 100 microsecond training timer reaches state `11` |
| Cancellation | Root branch `1051872e` calls `1051886a`, requests PHY `3c` bit 4, waits for event 2 and state `15`, then disables via `1051881e` | Request stops DMA forwarding, schedules state `15` and cause bit 26; native disable resets the controller |
| Interrupts | `10517aa6` registers GIC 243 for `10517a18` and 246 for `10517980`; instructions `10517046..1051705a` read and write back PHY `24` and `2c` before extracting causes | A native INTx rising event latches PHY bit 28 and GIC 243; W1C clears the captured cause even while the PCI line remains high; deassertion does not invent bit 29 |
| MSI | `10517980` reads root `830`, writes the observed bits back and dispatches the status | Native MSI-X writes reach a private destination; root enable/mask/status drive GIC 246 |
| Transaction error | `105187e4` consumes root `104` bit 14 without clearing it | Failed configuration/BAR transactions set a sticky bit until host reset; NVMe command errors remain CQ status |

PCI DMA resolves through the master engine's private memory address space.
It is gated while the link is unavailable or cancellation is pending. The
native controller, rather than the host wrapper, creates completions and
performs backing-file reads and writes.

The prepared native controller supports Power Management feature `02` for
its sole advertised state, PS0 (`NPSS=0`). Defined workload hints 0, 1 and 2
are retained for Get Features. Unsupported states, reserved fields and Save
requests fail through the normal admin CQ without changing the current value.
Current state resets on controller disable; default/saved queries return the
default zero value. This implements the finite command semantics described in
[NVMe 1.4c, sections 5.21.1.2 and 8.4.3](https://nvmexpress.org/wp-content/uploads/NVM-Express-1_4c-2021.06.28-Ratified.pdf),
without physical power consumption or transition modeling. Source preparation
checks each pinned upstream replacement and supports repeated preparation.

Training duration, root negotiated-status and PHY `210` readback, PHY cancellation timing,
PHY masking and the controller-reset binding are
functional approximations. The non-root cancellation path's earlier event
producer is unresolved. No complete PHY specification, physical card timing,
in-flight cancellation, hotplug or power-state fidelity is claimed.

## Validation

`tests/test_nvme_host.py` uses a synthetic raw image and actual native admin
and I/O queues. It checks Identify, namespace size, queue creation, WRITE,
FLUSH and READ, and reads the backing file after shutdown. Sector zero must
remain unchanged. An out-of-range LBA must fail through a CQ without setting
the host transaction-error bit.

INTx capture and W1C acknowledgement are checked before CQ acknowledgement,
including no repeated interrupt while the underlying PCI line remains high.
MSI-X table placement is discovered from the PCI capability; poisoned DMA
buffers and returned bytes distinguish real I/O from residual RAM. Host
MSI enable, mask and W1C behavior are checked. Native disable is followed by
retraining and CC/CSTS verification before whole-machine reset. Missing
selected backends must fail initialization. The existing SDSC/SDHC host
regression is run separately.

The queue test also verifies PS0 capabilities, current/default/saved queries,
workload hints, invalid states/reserved fields, Save rejection without state
mutation, and controller-disable reset. These admin round trips exercise CQ
phase wraparound. See the [device validation](../../artifacts/nvme_host_validation/report.json).
They do not establish invalid-PRP handling, cancellation with requests in
flight, I/O-queue wraparound, or DMA isolation between two running engines.

## Original firmware observation

The [native validation](../../artifacts/nvme_native_playback/validation.json)
records cold startup into shooting and a playback key press. Firmware issued
12 admin commands and 787 NVMe READs (4,672,512 backend bytes); all 799
completions succeeded and were acknowledged. The original PS0 request
succeeded. The separate SD image had no reads or writes. The master JPEG
decoder completed once, the LCD sample contained 220 distinct byte values,
and all four sampled engine cores had zero fault registers.

This establishes native startup, block reads and JPEG decode from the NVMe
path. This read-only run made no block writes. The LCD was sampled and hashed without an
independent comparison against source-photo pixels. Full local observations
are archived privately; Git retains compact validation records and no images.

The [native NVMe body-save validation](../../artifacts/nvme_body_save_ready/validation.json)
uses a new private card clone and the focused body profile. Native exposure
and silent-mode APIs run before staged half/full contacts; the settings
caller does not invoke capture. Its data/results now use laboratory RAM at
`40102000`, because native NVMe Identify occupies the previous `B5F00000`
scratch region. Occupancy checks and conditional restoration remain enabled.

Firmware saved `DCIM/100NZ7_2/DSC_0001.JPG` (3,407,179 bytes), recovered to
capture state `(2,0)` and driver state 9, then read the photo for playback in
the same guest. There were 36 NVMe writes totaling 3,535,360 bytes and 30
native Flush commands; every observed CQ status succeeded. The separate SD
backend had no I/O. Flush evidence comes from native command traces; the
controller does not account these flushes in the backend operation counter.

The [card check](../../artifacts/nvme_body_save_ready/card_check.json) independently
decodes the 8256×5504 primary image and three embedded JPEGs. All 12,288 scene
cell-center comparisons have zero RGB error; four complete encoder RAM bodies
match the saved file byte for byte. The filesystem is valid, `PROBE.TXT` is
preserved and the original card hash is unchanged. A later NTFS compression
step preserves the clone's full logical hash while reducing its allocation.

This capture still explicitly skips original DSP preprocessing and uses
modeled pixel/codec hardware with a deterministic grayscale source. It does
not establish default-browser capture, original DSP execution or all settings
and firmware versions. The exported JPG remains local and is excluded from Git.
