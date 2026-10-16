/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "qemu/osdep.h"
#include "qemu/timer.h"
#include "qapi/error.h"
#include "hw/sysbus.h"
#include "hw/irq.h"
#include "hw/qdev-properties.h"
#include "hw/resettable.h"
#include "system/address-spaces.h"

#define TYPE_Z72_MEMORY "nikon-z72-memory"
OBJECT_DECLARE_SIMPLE_TYPE(Z72Memory, Z72_MEMORY)

struct Z72Memory {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    MemoryRegion *root;
    AddressSpace memory;
    uint32_t registers[0x80 / 4];
    uint32_t clear_base, clear_size;
    bool fail;
    bool pending[2];
    QEMUTimer *timers[2];
    qemu_irq irqs[2];
};

static void memory_irqs(Z72Memory *s)
{
    for (unsigned channel = 0; channel < 2; channel++) {
        unsigned base = channel * 16;
        qemu_set_irq(s->irqs[channel],
                     !!(s->registers[base + 2] &
                        s->registers[base + 1] & 0x11));
    }
}

static bool memory_range(Z72Memory *s, uint64_t address, uint32_t bytes,
                         bool write)
{
    if (address + bytes > UINT64_C(0x100000000)) {
        return false;
    }
    while (bytes) {
        hwaddr translated, available = bytes;
        MemoryRegion *region = address_space_translate(&s->memory, address,
            &translated, &available, write, MEMTXATTRS_UNSPECIFIED);
        if (!available || !memory_region_is_ram(region) ||
            (write && memory_region_is_rom(region))) {
            return false;
        }
        available = MIN(available, bytes);
        address += available;
        bytes -= available;
    }
    return true;
}

static bool memory_transfer(Z72Memory *s, unsigned channel)
{
    uint32_t *r = s->registers + channel * 16;
    uint32_t source = r[11], destination = r[12];
    uint32_t source_stride = r[7] & 0xffff;
    uint32_t stride = r[8] & 0xffff, width = r[9] & 0xffff;
    uint32_t rows = r[10] & 0xffff;
    bool fill = r[5] & 1;
    bool early = channel == 0 && r[1] == 0;
    if (s->fail || !width || !rows || stride < width ||
        (uint64_t)width * rows > 0x10000000) {
        return false;
    }
    if (early) {
        uint64_t bytes = (uint64_t)width * rows;
        if (!fill || r[0] || source || r[6] || width != 0x4000 ||
            stride != width || rows >= 0x4000 || (destination & 3) ||
            destination < s->clear_base ||
            (uint64_t)destination + bytes >
            (uint64_t)s->clear_base + s->clear_size) {
            return false;
        }
    } else if ((r[5] & ~1u) || r[6] > 0xff ||
               (!fill && source_stride < width)) {
        return false;
    }
    /* Validate every row before changing memory, including padding gaps. */
    for (unsigned row = 0; row < rows; row++) {
        if (!memory_range(s, (uint64_t)destination + (uint64_t)row * stride,
                          width, true) ||
            (!fill && !memory_range(s,
                (uint64_t)source + (uint64_t)row * source_stride, width, false))) {
            return false;
        }
    }
    g_autofree uint8_t *buffer = g_malloc(width);
    if (fill) {
        memset(buffer, r[6] & 0xff, width);
    }
    for (unsigned row = 0; row < rows; row++) {
        if ((!fill && address_space_read(&s->memory,
                (uint64_t)source + (uint64_t)row * source_stride,
                MEMTXATTRS_UNSPECIFIED, buffer, width) != MEMTX_OK) ||
            address_space_write(&s->memory,
                (uint64_t)destination + (uint64_t)row * stride,
                MEMTXATTRS_UNSPECIFIED, buffer, width) != MEMTX_OK) {
            return false;
        }
    }
    return true;
}

static void memory_complete(Z72Memory *s, unsigned channel)
{
    unsigned base = channel * 16;
    s->pending[channel] = false;
    s->registers[base + 2] |= memory_transfer(s, channel) ? 1 : 0x10;
    memory_irqs(s);
}

static void memory_complete_first(void *opaque)
{
    memory_complete(opaque, 0);
}

static void memory_complete_second(void *opaque)
{
    memory_complete(opaque, 1);
}

static bool memory_register(hwaddr offset, unsigned size, bool write)
{
    unsigned local = offset & 0x3f;
    return size == 4 && !(offset & 3) && offset < 0x80 &&
           (!write || local != 0x0c) && local < 0x34;
}

static MemTxResult memory_read(void *opaque, hwaddr offset, uint64_t *value,
                              unsigned size, MemTxAttrs attrs)
{
    Z72Memory *s = opaque;
    if (!memory_register(offset, size, false)) {
        return MEMTX_ERROR;
    }
    /* Native error handlers read +0x0c bits 16/20 for channel diagnostics.
     * Detailed classification is not modeled; this read-only word stays zero. */
    *value = s->registers[offset / 4];
    return MEMTX_OK;
}

static MemTxResult memory_write(void *opaque, hwaddr offset, uint64_t value,
                               unsigned size, MemTxAttrs attrs)
{
    Z72Memory *s = opaque;
    unsigned channel = offset / 0x40, local = offset & 0x3f;
    if (!memory_register(offset, size, true)) {
        return MEMTX_ERROR;
    }
    if (local == 8) {
        s->registers[offset / 4] &= ~(uint32_t)value;
    } else {
        s->registers[offset / 4] = value;
        if (local == 0x10) {
            if (!(value & 1)) {
                timer_del(s->timers[channel]);
                s->pending[channel] = false;
                /* The stop handshake polls the control word for state 2. */
                if (value == 0) {
                    s->registers[offset / 4] = 2;
                }
            } else if (!s->pending[channel]) {
                s->pending[channel] = true;
                if (channel == 0 && s->registers[1] == 0) {
                    memory_complete(s, channel);
                } else {
                    timer_mod(s->timers[channel],
                              qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 1000);
                }
            }
        }
    }
    memory_irqs(s);
    return MEMTX_OK;
}

static const MemoryRegionOps memory_ops = {
    .read_with_attrs = memory_read,
    .write_with_attrs = memory_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 4 },
    .impl = { .min_access_size = 1, .max_access_size = 4 },
};

static void memory_reset(Object *obj, ResetType type)
{
    Z72Memory *s = Z72_MEMORY(obj);
    memset(s->registers, 0, sizeof(s->registers));
    for (unsigned channel = 0; channel < 2; channel++) {
        timer_del(s->timers[channel]);
        s->pending[channel] = false;
    }
    memory_irqs(s);
}

static void memory_realize(DeviceState *dev, Error **errp)
{
    Z72Memory *s = Z72_MEMORY(dev);
    if (!s->root) {
        error_setg(errp, "Memory transfer requires an engine address space");
        return;
    }
    address_space_init(&s->memory, s->root, TYPE_Z72_MEMORY);
}

static void memory_unrealize(DeviceState *dev)
{
    Z72Memory *s = Z72_MEMORY(dev);
    for (unsigned channel = 0; channel < 2; channel++) {
        timer_del(s->timers[channel]);
    }
    address_space_destroy(&s->memory);
}

static void memory_finalize(Object *obj)
{
    Z72Memory *s = Z72_MEMORY(obj);
    for (unsigned channel = 0; channel < 2; channel++) {
        timer_free(s->timers[channel]);
    }
}

static void memory_init(Object *obj)
{
    Z72Memory *s = Z72_MEMORY(obj);
    memory_region_init_io(&s->iomem, obj, &memory_ops, s, TYPE_Z72_MEMORY, 0x80);
    sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->iomem);
    for (unsigned channel = 0; channel < 2; channel++) {
        sysbus_init_irq(SYS_BUS_DEVICE(s), &s->irqs[channel]);
    }
    s->timers[0] = timer_new_ns(QEMU_CLOCK_VIRTUAL, memory_complete_first, s);
    s->timers[1] = timer_new_ns(QEMU_CLOCK_VIRTUAL, memory_complete_second, s);
}

static void memory_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    static const Property properties[] = {
        DEFINE_PROP_LINK("root", Z72Memory, root, TYPE_MEMORY_REGION, MemoryRegion *),
        DEFINE_PROP_UINT32("clear-base", Z72Memory, clear_base, 0),
        DEFINE_PROP_UINT32("clear-size", Z72Memory, clear_size, 0),
        DEFINE_PROP_BOOL("fail", Z72Memory, fail, false),
    };
    dc->realize = memory_realize;
    dc->unrealize = memory_unrealize;
    device_class_set_props(dc, properties);
    RESETTABLE_CLASS(klass)->phases.hold = memory_reset;
}

static void memory_register_types(void)
{
    static const TypeInfo info = {
        .name = TYPE_Z72_MEMORY,
        .parent = TYPE_SYS_BUS_DEVICE,
        .instance_size = sizeof(Z72Memory),
        .instance_init = memory_init,
        .instance_finalize = memory_finalize,
        .class_init = memory_class_init,
    };
    type_register_static(&info);
}
type_init(memory_register_types)
