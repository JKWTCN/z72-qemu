/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "qemu/osdep.h"
#include "qemu/timer.h"
#include "qapi/error.h"
#include "qapi/visitor.h"
#include "hw/sysbus.h"
#include "hw/irq.h"
#include "hw/qdev-properties.h"
#include "hw/resettable.h"
#include "system/address-spaces.h"
#include "migration/vmstate.h"
#include "nikon-gpu.h"

#define TYPE_Z72_GRAPHICS "nikon-z72-graphics"
OBJECT_DECLARE_SIMPLE_TYPE(Z72Graphics, Z72_GRAPHICS)

struct Z72Graphics {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    MemoryRegion *root;
    AddressSpace memory;
    NikonGPU *gpu;
    uint32_t registers[0x2000 / 4];
    bool pending[2];
    bool drawing;
    bool draw_complete;
    unsigned completed_draws;
    uint32_t successful_uploads;
    uint32_t render_requests;
    uint32_t failed_requests;
    QEMUTimer *timer;
    qemu_irq irqs[3];
};

static void graphics_irqs(Z72Graphics *s)
{
    qemu_set_irq(s->irqs[0], s->registers[0x1020 / 4] != 0);
    qemu_set_irq(s->irqs[1], s->draw_complete);
    qemu_set_irq(s->irqs[2], s->registers[0xc18 / 4] != 0);
}

static void graphics_complete(void *opaque)
{
    Z72Graphics *s = opaque;
    bool completed = false;
    for (unsigned channel = 0; channel < 2; channel++) {
        if (!s->pending[channel]) {
            continue;
        }
        unsigned offset = 0x10d0 + channel * 0x10;
        uint32_t source = s->registers[(offset + 4) / 4];
        uint64_t bytes = (uint64_t)s->registers[(offset + 12) / 4] * 8;
        s->pending[channel] = false;
        s->registers[offset / 4] = 0;
        if (!bytes || bytes > 0x80000 ||
            !nikon_gpu_range(s->gpu, source, bytes, false)) {
            s->registers[0xc18 / 4] = 1;
            s->failed_requests++;
            continue;
        }
        g_autofree uint8_t *commands = g_malloc(bytes);
        nikon_gpu_read(s->gpu, source, commands, bytes);
        unsigned errors = s->gpu->unsupported;
        nikon_gpu_execute(s->gpu, channel, commands, bytes);
        if (s->gpu->unsupported != errors) {
            s->registers[0xc18 / 4] = 1;
            s->failed_requests++;
        } else {
            completed = true;
            s->successful_uploads++;
        }
    }
    if (completed) {
        s->registers[0x1020 / 4] = 1;
    }
    if (s->drawing) {
        s->drawing = false;
        if (s->gpu->rendered > s->completed_draws) {
            s->completed_draws = s->gpu->rendered;
            s->draw_complete = true;
            s->registers[0x1c / 4] = 1;
        } else {
            s->registers[0xc18 / 4] = 1;
            s->failed_requests++;
        }
    }
    graphics_irqs(s);
}

static uint64_t graphics_read(void *opaque, hwaddr offset, unsigned size)
{
    Z72Graphics *s = opaque;
    if (offset == 0x58) {
        return (s->pending[0] || s->pending[1]) ? 1u << 26 : 0;
    }
    return s->registers[offset / 4];
}

static void graphics_write(void *opaque, hwaddr offset, uint64_t value,
                           unsigned size)
{
    Z72Graphics *s = opaque;
    if (offset == 0x58) {
        return;
    }
    s->registers[offset / 4] = value;
    if (offset == 0x1c) {
        s->draw_complete = false;
        s->drawing = value != 0;
        if (s->drawing) {
            s->render_requests++;
            timer_mod(s->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 100000);
        }
    }
    if (offset == 0x10d0 || offset == 0x10e0) {
        unsigned channel = (offset - 0x10d0) / 0x10;
        s->pending[channel] = value & 1;
        if (s->pending[channel]) {
            timer_mod(s->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 100000);
        }
    }
    graphics_irqs(s);
}

static const MemoryRegionOps graphics_ops = {
    .read = graphics_read,
    .write = graphics_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4,
               .unaligned = false },
    .impl = { .min_access_size = 4, .max_access_size = 4 },
};

static void graphics_reset(Object *obj, ResetType type)
{
    Z72Graphics *s = Z72_GRAPHICS(obj);
    timer_del(s->timer);
    memset(s->registers, 0, sizeof(s->registers));
    memset(s->pending, 0, sizeof(s->pending));
    s->drawing = s->draw_complete = false;
    s->completed_draws = 0;
    s->successful_uploads = 0;
    s->render_requests = s->failed_requests = 0;
    if (s->gpu) {
        g_hash_table_remove_all(s->gpu->paths);
        if (s->gpu->active) {
            nikon_gpu_path_free(s->gpu->active);
            s->gpu->active = NULL;
        }
        memset(s->gpu->regs, 0, sizeof(s->gpu->regs));
        s->gpu->present_address = 0;
        s->gpu->rendered = s->gpu->unsupported = 0;
        s->gpu->stroke_samples = s->gpu->icon_samples = 0;
        DisplaySurface *surface = qemu_console_surface(s->gpu->console);
        memset(surface_data(surface), 0, surface_stride(surface) * surface_height(surface));
        dpy_gfx_update(s->gpu->console, 0, 0, surface_width(surface), surface_height(surface));
    }
    graphics_irqs(s);
}

static void graphics_realize(DeviceState *dev, Error **errp)
{
    Z72Graphics *s = Z72_GRAPHICS(dev);
    if (!s->root) {
        error_setg(errp, "Graphics requires an engine memory view");
        return;
    }
    address_space_init(&s->memory, s->root, TYPE_Z72_GRAPHICS);
    s->gpu = nikon_gpu_new();
    s->gpu->memory = &s->memory;
}

static void graphics_init(Object *obj)
{
    Z72Graphics *s = Z72_GRAPHICS(obj);
    memory_region_init_io(&s->iomem, obj, &graphics_ops, s,
                         TYPE_Z72_GRAPHICS, 0x2000);
    sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->iomem);
    for (unsigned line = 0; line < 3; line++) {
        sysbus_init_irq(SYS_BUS_DEVICE(s), &s->irqs[line]);
    }
    s->timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, graphics_complete, s);
}

static void graphics_unrealize(DeviceState *dev)
{
    Z72Graphics *s = Z72_GRAPHICS(dev);
    timer_del(s->timer);
    graphics_reset(OBJECT(s), RESET_TYPE_COLD);
    if (s->gpu) {
        graphic_console_close(s->gpu->console);
        g_hash_table_destroy(s->gpu->paths);
        g_free(s->gpu);
        s->gpu = NULL;
        address_space_destroy(&s->memory);
    }
}

static void graphics_finalize(Object *obj)
{
    timer_free(Z72_GRAPHICS(obj)->timer);
}

static void graphics_observation(Object *obj, Visitor *visitor, const char *name,
                                 void *opaque, Error **errp)
{
    Z72Graphics *s = Z72_GRAPHICS(obj);
    uint32_t value = 0;
    unsigned field = GPOINTER_TO_UINT(opaque);
    if (field == 0) {
        value = s->successful_uploads;
    } else if (field == 4) {
        value = s->render_requests;
    } else if (field == 5) {
        value = s->failed_requests;
    } else if (s->gpu) {
        if (field == 1) {
            value = s->gpu->rendered;
        } else if (field == 2) {
            value = s->gpu->unsupported;
        } else if (field == 3) {
            value = s->gpu->present_address;
        } else {
            static const unsigned registers[] = { 0x1a4, 0x1a3, 0x1a2, 0x1b5 };
            value = s->gpu->regs[1][registers[field - 6]];
        }
    }
    visit_type_uint32(visitor, name, &value, errp);
}

/* Active path objects require a migration contract before transfer. */
static const VMStateDescription graphics_vmstate = {
    .name = TYPE_Z72_GRAPHICS,
    .unmigratable = true,
};

static void graphics_class_init(ObjectClass *klass, const void *data)
{
    static const Property properties[] = {
        DEFINE_PROP_LINK("root", Z72Graphics, root,
                         TYPE_MEMORY_REGION, MemoryRegion *),
    };
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->realize = graphics_realize;
    dc->unrealize = graphics_unrealize;
    dc->vmsd = &graphics_vmstate;
    device_class_set_props(dc, properties);
    static const char *const observations[] = {
        "successful-uploads", "rendered-commands", "unsupported-commands", "surface-address",
        "render-requests", "failed-requests",
        "target-address", "target-dimensions", "target-format", "target-second-plane",
    };
    for (unsigned field = 0; field < G_N_ELEMENTS(observations); field++) {
        object_class_property_add(klass, observations[field], "uint32",
                                  graphics_observation, NULL, NULL, GUINT_TO_POINTER(field));
    }
    RESETTABLE_CLASS(klass)->phases.hold = graphics_reset;
}

static void graphics_register(void)
{
    static const TypeInfo info = {
        .name = TYPE_Z72_GRAPHICS,
        .parent = TYPE_SYS_BUS_DEVICE,
        .instance_size = sizeof(Z72Graphics),
        .instance_init = graphics_init,
        .instance_finalize = graphics_finalize,
        .class_init = graphics_class_init,
    };
    type_register_static(&info);
}
type_init(graphics_register)
