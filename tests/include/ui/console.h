/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Minimal host test adapters; production renderer is included unchanged. */
#include <glib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
typedef struct { uint8_t data[4096]; } DisplaySurface;
typedef struct { DisplaySurface surface; } QemuConsole;
typedef struct { int unused; } GraphicHwOps;
static QemuConsole test_console;
static DisplaySurface *qemu_console_surface(QemuConsole *q) { return &q->surface; }
static uint8_t *surface_data(DisplaySurface *s) { return s->data; }
static unsigned surface_stride(DisplaySurface *s) { return 32; }
static void dpy_gfx_update(QemuConsole *q, int x, int y, int w, int h) {}
static void qemu_console_resize(QemuConsole *q, int w, int h) {}
static QemuConsole *graphic_console_init(void *d, int n, const GraphicHwOps *o, void *p) { return &test_console; }
static uint8_t memory[65536];
static void cpu_physical_memory_read(uint32_t a, void *p, size_t n) {
    assert(a >= 0xa1000000 && (uint64_t)a+n <= 0xa1010000);
    memcpy(p, memory+(a-0xa1000000), n);
}
static void cpu_physical_memory_write(uint32_t a, const void *p, size_t n) {
    assert(a >= 0xa1000000 && (uint64_t)a+n <= 0xa1010000);
    memcpy(memory+(a-0xa1000000), p, n);
}
static uint32_t ldl_le_p(const void *p) { uint32_t v; memcpy(&v,p,4); return v; }
static uint16_t lduw_le_p(const void *p) { uint16_t v; memcpy(&v,p,2); return v; }
static void stl_p(void *p, uint32_t v) { memcpy(p,&v,4); }

/* Synthetic address-space adapter for the shared renderer range checks. */
typedef struct { bool ram, rom; } MemoryRegion;
typedef struct { MemoryRegion *mr; uint64_t size; } MemoryRegionSection;
static MemoryRegion test_ram = {true, false};
static void *get_system_memory(void) { return NULL; }
static MemoryRegionSection memory_region_find(void *unused, uint64_t a, uint64_t n) {
    MemoryRegionSection s = {NULL, 0};
    if (a >= 0xa1000000 && a < 0xa1010000) {
        s.mr = &test_ram; s.size = 0xa1010000-a;
    }
    return s;
}
static bool memory_region_is_ram(MemoryRegion *r) { return r->ram; }
static bool memory_region_is_rom(MemoryRegion *r) { return r->rom; }
static bool int128_ge(uint64_t a, uint64_t b) { return a >= b; }
static uint64_t int128_make64(uint64_t a) { return a; }
static void memory_region_unref(MemoryRegion *r) {}

/* Private renderer views use the same bounded synthetic backing. */
typedef uint64_t hwaddr;
typedef struct { int unused; } AddressSpace;
static MemoryRegion test_unassigned = {false, false};
#define MEMTXATTRS_UNSPECIFIED 0
static MemoryRegion *address_space_translate(AddressSpace *a, hwaddr address,
    hwaddr *offset, hwaddr *span, bool write, int attrs) {
    MemoryRegionSection section = memory_region_find(NULL, address, *span);
    *offset = address; *span = section.size;
    return section.mr ? section.mr : &test_unassigned;
}
static void address_space_read(AddressSpace *a, hwaddr address, int attrs,
    void *data, size_t bytes) { cpu_physical_memory_read(address, data, bytes); }
static void address_space_write(AddressSpace *a, hwaddr address, int attrs,
    const void *data, size_t bytes) { cpu_physical_memory_write(address, data, bytes); }
