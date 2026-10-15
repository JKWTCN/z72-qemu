/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "qemu/osdep.h"
#include "qemu/timer.h"
#include "qapi/error.h"
#include "hw/sysbus.h"
#include "hw/irq.h"
#include "hw/qdev-properties.h"
#include "hw/resettable.h"
#include "system/address-spaces.h"
#include "migration/vmstate.h"

#define TYPE_Z72_CONTROLLER_DMA "nikon-z72-controller-dma"
OBJECT_DECLARE_SIMPLE_TYPE(Z72ControllerDMA, Z72_CONTROLLER_DMA)

typedef struct Z72DMAStream {
    Z72ControllerDMA *owner;
    unsigned index;
    uint32_t registers[6];
    uint32_t source;
    uint32_t destination;
    uint32_t initial_count;
    uint8_t flags;
    uint8_t requests;
    QEMUTimer *timer;
} Z72DMAStream;

struct Z72ControllerDMA {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    MemoryRegion *root;
    AddressSpace memory;
    Z72DMAStream streams[8];
    qemu_irq irqs[8];
    bool completion;
};

static unsigned dma_shift(unsigned stream)
{
    static const unsigned shifts[] = { 0, 6, 16, 22 };
    return shifts[stream % 4];
}

static void dma_irq(Z72DMAStream *stream)
{
    uint32_t cr = stream->registers[0];
    uint8_t flags = stream->flags;
    bool asserted = ((flags & 0x20) && (cr & 0x10)) ||
                    ((flags & 0x10) && (cr & 8)) ||
                    ((flags & 8) && (cr & 4)) ||
                    ((flags & 4) && (cr & 2)) ||
                    ((flags & 1) && (stream->registers[5] & 0x80));
    qemu_set_irq(stream->owner->irqs[stream->index], asserted);
}

static void dma_finish(Z72DMAStream *stream, bool success)
{
    timer_del(stream->timer);
    stream->registers[0] &= ~1u;
    stream->flags |= success ? 0x20 : 8;
    dma_irq(stream);
}

static bool dma_ram_span(Z72ControllerDMA *s, uint32_t address,
                         uint64_t length, bool write)
{
    hwaddr translated, span = length;
    if (!length || (uint64_t)address + length > UINT64_C(0x100000000)) {
        return false;
    }
    MemoryRegion *region = address_space_translate(&s->memory, address,
        &translated, &span, write, MEMTXATTRS_UNSPECIFIED);
    return span >= length && memory_region_is_ram(region) &&
           (!write || !memory_region_is_rom(region));
}

static bool dma_control_supported(uint32_t cr)
{
    return ((cr >> 6) & 3) != 3 && ((cr >> 11) & 3) <= 2 &&
           ((cr >> 13) & 3) == ((cr >> 11) & 3) &&
           !(cr & ((1u << 5) | (1u << 8) | (1u << 15) | (1u << 18) |
                   (3u << 21) | (3u << 23)));
}

static bool dma_prepare(Z72DMAStream *stream)
{
    uint32_t cr = stream->registers[0];
    unsigned direction = (cr >> 6) & 3;
    unsigned memory_width = (cr >> 13) & 3;
    uint32_t count = stream->registers[1];
    bool peripheral_increment = cr & 0x200;
    bool memory_increment = cr & 0x400;
    /* Packing, flow control, circular/double buffers and bursts need their
     * own contracts. Reject them before touching guest buffers. */
    if (!dma_control_supported(cr) || !count || count > 0xffff) {
        return false;
    }
    unsigned width = 1u << memory_width;
    uint32_t peripheral = stream->registers[2];
    uint32_t memory = stream->registers[3];
    if ((peripheral & (width - 1)) || (memory & (width - 1)) ||
        !dma_ram_span(stream->owner, memory,
            ((uint64_t)(memory_increment ? count - 1 : 0) + 1) * width,
            direction != 1)) {
        return false;
    }
    if (direction == 2 && !dma_ram_span(stream->owner, peripheral,
            ((uint64_t)(peripheral_increment ? count - 1 : 0) + 1) * width, false)) {
        return false;
    }
    if (direction != 2) {
        hwaddr translated, span = width;
        MemoryRegion *region = address_space_translate(&stream->owner->memory,
            peripheral, &translated, &span, direction == 1, MEMTXATTRS_UNSPECIFIED);
        if (span < width || memory_region_is_ram(region) || peripheral_increment) {
            return false;
        }
    }
    stream->source = direction == 1 ? memory : peripheral;
    stream->destination = direction == 1 ? peripheral : memory;
    stream->initial_count = count;
    return true;
}

static void dma_schedule(Z72DMAStream *stream)
{
    uint32_t cr = stream->registers[0];
    bool ready = ((cr >> 6) & 3) == 2 ||
                 (stream->requests & (1u << ((cr >> 25) & 7)));
    if ((cr & 1) && stream->owner->completion && ready &&
        !timer_pending(stream->timer)) {
        timer_mod(stream->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 1000);
    }
}

static void dma_transfer(void *opaque)
{
    Z72DMAStream *stream = opaque;
    uint32_t cr = stream->registers[0];
    unsigned direction = (cr >> 6) & 3;
    unsigned width = 1u << ((cr >> 13) & 3);
    uint8_t value[4];
    if (!(cr & 1)) {
        return;
    }
    if (direction != 2 && !(stream->requests & (1u << ((cr >> 25) & 7)))) {
        return;
    }
    if (address_space_read(&stream->owner->memory, stream->source,
            MEMTXATTRS_UNSPECIFIED, value, width) != MEMTX_OK ||
        address_space_write(&stream->owner->memory, stream->destination,
            MEMTXATTRS_UNSPECIFIED, value, width) != MEMTX_OK) {
        dma_finish(stream, false);
        return;
    }
    if (cr & (direction == 1 ? 0x400 : 0x200)) {
        stream->source += width;
    }
    if (cr & (direction == 1 ? 0x200 : 0x400)) {
        stream->destination += width;
    }
    if (--stream->registers[1] == 0) {
        dma_finish(stream, true);
    } else {
        if (stream->registers[1] == stream->initial_count / 2) {
            stream->flags |= 0x10;
            dma_irq(stream);
        }
        dma_schedule(stream);
    }
}

static void dma_request(void *opaque, int line, int level)
{
    Z72ControllerDMA *s = opaque;
    Z72DMAStream *stream = &s->streams[line / 8];
    uint8_t bit = 1u << (line % 8);
    stream->requests = (stream->requests & ~bit) | (level ? bit : 0);
    dma_schedule(stream);
}

static MemTxResult dma_read(void *opaque, hwaddr offset, uint64_t *value,
                           unsigned size, MemTxAttrs attrs)
{
    Z72ControllerDMA *s = opaque;
    if (size != 4 || (offset & 3) || offset >= 0xd0) {
        return MEMTX_ERROR;
    }
    *value = 0;
    if (offset < 8) {
        unsigned first = offset ? 4 : 0;
        for (unsigned i = first; i < first + 4; i++) {
            *value |= (uint32_t)s->streams[i].flags << dma_shift(i);
        }
    } else if (offset >= 0x10) {
        unsigned index = (offset - 0x10) / 0x18;
        unsigned reg = ((offset - 0x10) % 0x18) / 4;
        *value = s->streams[index].registers[reg];
        if (reg == 5) {
            *value = (*value & ~0x38u) | 0x20;
        }
    }
    return MEMTX_OK;
}

static MemTxResult dma_write(void *opaque, hwaddr offset, uint64_t value,
                            unsigned size, MemTxAttrs attrs)
{
    Z72ControllerDMA *s = opaque;
    uint64_t previous;
    if (dma_read(s, offset, &previous, size, attrs) != MEMTX_OK || offset < 8) {
        return MEMTX_ERROR;
    }
    if (offset < 0x10) {
        unsigned first = offset == 8 ? 0 : 4;
        for (unsigned i = first; i < first + 4; i++) {
            s->streams[i].flags &= ~(value >> dma_shift(i));
            dma_irq(&s->streams[i]);
        }
        return MEMTX_OK;
    }
    Z72DMAStream *stream = &s->streams[(offset - 0x10) / 0x18];
    unsigned reg = ((offset - 0x10) % 0x18) / 4;
    if (reg && (stream->registers[0] & 1)) {
        /* The original abort path masks FIFO errors before disabling the
         * stream. Keep transfer geometry fixed while allowing that mask. */
        if (reg != 5 || ((value ^ stream->registers[5]) & 7)) {
            return MEMTX_ERROR;
        }
    }
    if (reg == 0 && (stream->registers[0] & 1) && (value & 1)) {
        stream->registers[0] = (stream->registers[0] & ~0x1eu) | (value & 0x1e);
    } else {
        bool was_enabled = stream->registers[0] & 1;
        stream->registers[reg] = reg == 5 ? value & 0x87 : value;
        if (reg == 0) {
            if (!(value & 1)) {
                timer_del(stream->timer);
            } else if (!was_enabled) {
                if (!dma_prepare(stream)) {
                    dma_finish(stream, false);
                } else {
                    dma_schedule(stream);
                }
            }
        }
    }
    dma_irq(stream);
    return MEMTX_OK;
}

static const MemoryRegionOps dma_ops = {
    .read_with_attrs = dma_read, .write_with_attrs = dma_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 4 },
    .impl = { .min_access_size = 1, .max_access_size = 4 },
};

static void dma_reset(Object *obj, ResetType type)
{
    Z72ControllerDMA *s = Z72_CONTROLLER_DMA(obj);
    for (unsigned i = 0; i < 8; i++) {
        Z72DMAStream *stream = &s->streams[i];
        timer_del(stream->timer);
        memset(stream->registers, 0, sizeof(stream->registers));
        stream->registers[5] = 1;
        stream->flags = 0;
        stream->source = stream->destination = stream->initial_count = 0;
        dma_irq(stream);
    }
}

static int dma_post_load(void *opaque, int version)
{
    Z72ControllerDMA *s = opaque;
    for (unsigned i = 0; i < 8; i++) {
        Z72DMAStream *stream = &s->streams[i];
        if ((stream->flags & ~0x3d) || stream->initial_count > 0xffff ||
            ((stream->registers[0] & 1) &&
             (!dma_control_supported(stream->registers[0]) ||
              !stream->registers[1] || stream->registers[1] > stream->initial_count))) {
            return -EINVAL;
        }
        if (stream->registers[0] & 1) {
            Z72DMAStream original = *stream;
            uint32_t cr = stream->registers[0];
            unsigned direction = (cr >> 6) & 3;
            unsigned width = 1u << ((cr >> 13) & 3);
            uint32_t completed = stream->initial_count - stream->registers[1];
            /* Validate the original spans without rewinding an active stream. */
            original.registers[1] = stream->initial_count;
            if (!dma_prepare(&original) ||
                stream->source != original.source +
                    ((cr & (direction == 1 ? 0x400 : 0x200)) ? completed * width : 0) ||
                stream->destination != original.destination +
                    ((cr & (direction == 1 ? 0x200 : 0x400)) ? completed * width : 0)) {
                return -EINVAL;
            }
        }
        dma_irq(stream);
    }
    return 0;
}

static const VMStateDescription dma_stream_state = {
    .name = "z72-controller-dma-stream", .version_id = 1, .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT32_ARRAY(registers, Z72DMAStream, 6),
        VMSTATE_UINT32(source, Z72DMAStream),
        VMSTATE_UINT32(destination, Z72DMAStream),
        VMSTATE_UINT32(initial_count, Z72DMAStream),
        VMSTATE_UINT8(flags, Z72DMAStream),
        VMSTATE_UINT8(requests, Z72DMAStream),
        VMSTATE_TIMER_PTR(timer, Z72DMAStream),
        VMSTATE_END_OF_LIST()
    },
};

static const VMStateDescription dma_state = {
    .name = TYPE_Z72_CONTROLLER_DMA, .version_id = 1, .minimum_version_id = 1,
    .post_load = dma_post_load,
    .fields = (const VMStateField[]) {
        VMSTATE_STRUCT_ARRAY(streams, Z72ControllerDMA, 8, 1,
                             dma_stream_state, Z72DMAStream),
        VMSTATE_END_OF_LIST()
    },
};

static const Property dma_properties[] = {
    DEFINE_PROP_LINK("root", Z72ControllerDMA, root, TYPE_MEMORY_REGION, MemoryRegion *),
    DEFINE_PROP_BOOL("completion", Z72ControllerDMA, completion, true),
};

static void dma_realize(DeviceState *dev, Error **errp)
{
    Z72ControllerDMA *s = Z72_CONTROLLER_DMA(dev);
    if (!s->root) {
        error_setg(errp, "Controller DMA requires its physical memory view");
        return;
    }
    address_space_init(&s->memory, s->root, TYPE_Z72_CONTROLLER_DMA);
}

static void dma_init(Object *obj)
{
    Z72ControllerDMA *s = Z72_CONTROLLER_DMA(obj);
    memory_region_init_io(&s->iomem, obj, &dma_ops, s, TYPE_Z72_CONTROLLER_DMA, 0x400);
    sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->iomem);
    qdev_init_gpio_in(DEVICE(s), dma_request, 64);
    for (unsigned i = 0; i < 8; i++) {
        Z72DMAStream *stream = &s->streams[i];
        stream->owner = s;
        stream->index = i;
        stream->timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, dma_transfer, stream);
        sysbus_init_irq(SYS_BUS_DEVICE(s), &s->irqs[i]);
    }
}

static void dma_unrealize(DeviceState *dev)
{
    Z72ControllerDMA *s = Z72_CONTROLLER_DMA(dev);
    for (unsigned i = 0; i < 8; i++) {
        timer_del(s->streams[i].timer);
    }
    address_space_destroy(&s->memory);
}

static void dma_finalize(Object *obj)
{
    Z72ControllerDMA *s = Z72_CONTROLLER_DMA(obj);
    for (unsigned i = 0; i < 8; i++) {
        timer_free(s->streams[i].timer);
    }
}

static void dma_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->realize = dma_realize;
    dc->unrealize = dma_unrealize;
    dc->vmsd = &dma_state;
    device_class_set_props(dc, dma_properties);
    RESETTABLE_CLASS(klass)->phases.hold = dma_reset;
}

static void dma_register_types(void)
{
    static const TypeInfo info = {
        .name = TYPE_Z72_CONTROLLER_DMA, .parent = TYPE_SYS_BUS_DEVICE,
        .instance_size = sizeof(Z72ControllerDMA), .instance_init = dma_init,
        .instance_finalize = dma_finalize, .class_init = dma_class_init,
    };
    type_register_static(&info);
}
type_init(dma_register_types)
