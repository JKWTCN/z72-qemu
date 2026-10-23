/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef NIKON_Z72_PROFILE_H
#define NIKON_Z72_PROFILE_H
#include <stdint.h>

/* CPU selection and RAM extents are laboratory choices. Only the used
 * software addresses are supported by C1.70 firmware evidence. */
#define Z72_MASTER_BASE 0x10020000u
#define Z72_MASTER_BYTES 38239098u
#define Z72_MASTER_SHA256 "478caf02dba41fa9144c0c4b6e1a051dc556d40e51a79a308bdd1169efb9dbbe"
#define Z72_SLAVE_BYTES 8834370u
#define Z72_SLAVE_SHA256 "e0d2589cf036bbf8ce6e4c32f5f2bab61fe35e863660bf6a0ee8082d8a64e1bb"
/* Laboratory private-peripheral layout; firmware derives its GIC addresses
 * from CBAR. The physical hardware base remains unconfirmed. */
#define Z72_PRIVATE_BASE 0x04000000u
#define Z72_COUNTER_BASE 0x04266000u
#define Z72_COUNTER_FREQUENCY 48000000u
typedef struct NikonZ72Window { uint32_t base, size; const char *name; } NikonZ72Window;
/* Explicit decoded-window experiment inside the cached buffer pool.
 * Bounded callers supply this address; it is not a recovered fixed flash
 * destination. Native service execution allocates its own package buffer.
 * No separate mapping: the fixture shares the 0x30000000 bus alias. */
#define Z72_UPDATE_WINDOW_BASE 0x52000000u
#define Z72_UPDATE_WINDOW_BYTES 0x02F00000u
static const NikonZ72Window nikon_z72_windows[] = {
    /* Auxiliary firmware load destinations observed in incrementing memory
     * descriptors. These are storage windows; auxiliary CPU execution and
     * its control/status handshake are not implemented yet. */
    {0x00000000, 0x00100000, "z72-auxiliary-local-memory-lab"},
    {0x50000000, 0x00300000, "z72-auxiliary-program-memory-lab"},
    /* Extended past the earlier 0x54900000 end so the decoded-window fixture
     * above fits inside one backing region. */
    {0x50300000, 0x04C00000, "z72-cached-buffer-pool-lab"},
    /* Cached capture allocation range paired with the 0x34600000 bus view. */
    {0x5F900000, 0x02E00000, "z72-capture-buffer-pool-lab"},
    {0xB1000000, 0x00300000, "z72-auxiliary-shared-memory-lab"},
    {0x04008000, 0x00001000, "z72-boot-stack-lab"},
    {0x10000000, 0x04000000, "z72-master-lab"},
    {0xB1800000, 0x00100000, "z72-scatter-lab"},
    {0xB1900000, 0x00700000, "z72-boot-clear-lab"},
    {0xB2000000, 0x00C00000, "z72-state-stack-lab"},
    /* Stock runtime heap bounds: 0xB2C00000..0xB5F00000. */
    {0xB2C00000, 0x03300000, "z72-runtime-heap-lab"},
    {0xB5F00000, 0x00100000, "z72-extra-init-lab"},
    /* Original identity sections cover the post-heap startup storage;
     * the controller response path accesses 0xB6207240 in this span. */
    {0xB6000000, 0x00F00000, "z72-startup-storage-lab"},
    /* Peer-alias physical span: the active runtime page table maps the
     * 0x15000000..0x17000000 virtual family here by 1 MiB sections
     * (observed store destination 0xB776AC48 below the message RAM). */
    {0xB6F00000, 0x00D00000, "z72-peer-alias-lab"},
    {0xB7C00000, 0x00100000, "z72-master-message-ram-lab"},
    /* Stock large-buffer pool: the firmware bump allocator starts at
     * 0xB7D00000 (allocator data table) and is bounded by 0xBAA00000. */
    {0xB7D00000, 0x02D00000, "z72-master-buffer-pool-lab"},
    /* Later buffer pools declared by the original initialization records.
     * Individual allocator extents may reserve a smaller usable portion. */
    {0xBB300000, 0x00DA0000, "z72-secondary-buffer-pool-lab"},
    {0xBC100000, 0x010E0000, "z72-tertiary-buffer-pool-lab"},
    {0xBD200000, 0x06BCB400, "z72-processing-buffer-pool-lab"},
    {0xC3E00000, 0x0883B000, "z72-image-buffer-pool-lab"},
    {0xCC700000, 0x337E5400, "z72-frame-buffer-pool-lab"},
    /* Companion serial-adjacent block beside the console interface; the
     * kernel writes it (observed at +0x560) once the handoff completes. */
    {0x2C0A0000, 0x00001000, "z72-console-companion-lab"},
    /* Controller block the release path configures: power words (bit 28 set
     * then bit 31 at 0x2C020000/0x2C030000) and computed descriptors such as
     * 0x2C018028. Ends below the console interface to keep its boundary. */
    {0x2C010000, 0x00080000, "z72-release-block-lab"},
    /* Runtime high-window physical span: the runtime page tables direct the
     * 0x10000000..0x17000000 virtual family here (the stock parameter tail
     * already mirrors into 0x24074000 inside this span). Starts above the
     * first configuration bank so its word registers keep precedence. */
    {0x20100000, 0x06F00000, "z72-runtime-window-lab"},
    {0x40100000, 0x00100000, "z72-harness-lab"},
};
/* Isolated slave context: the code base matches master, so these are separate
 * machines. Message windows are plain RAM, without a transport device. */
static const NikonZ72Window nikon_z72_slave_windows[] = {
    {0x04008000, 0x00001000, "z72-slave-boot-stack-lab"},
    {0x10000000, 0x04000000, "z72-slave-code-lab"},
    {0xC1000000, 0x00A00000, "z72-slave-state-stack-lab"},
    /* Continue the stock 0xC1940000..0xC5000000 heap beyond state RAM. */
    {0xC1A00000, 0x03600000, "z72-slave-runtime-heap-lab"},
    {0xC5000000, 0x00100000, "z72-slave-extra-init-lab"},
    /* Original initialization records extend startup storage to C5FC3140. */
    {0xC5100000, 0x00F00000, "z72-slave-startup-storage-lab"},
    /* Peer-alias physical span mirroring the master role. */
    {0xB6F00000, 0x00D00000, "z72-slave-peer-alias-lab"},
    {0xC6000000, 0x00100000, "z72-slave-message-ram-lab"},
    /* Companion serial-adjacent block beside the console interface; the
     * kernel writes it (observed at +0x560) once the handoff completes. */
    {0x2C0A0000, 0x00001000, "z72-slave-console-companion-lab"},
    /* Controller block mirroring the master release-path window. */
    {0x2C010000, 0x00080000, "z72-slave-release-block-lab"},
    /* Runtime high-window physical span mirroring the master role. */
    {0x20100000, 0x06F00000, "z72-slave-runtime-window-lab"},
    {0x40100000, 0x00100000, "z72-slave-harness-lab"},
};
#endif
