/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Laboratory peer-notification source: raise or lower GIC lines on demand.
 * The stock handoff syscall waits on an RTOS event that some interrupt
 * produces; this device lets experiments deliver candidate lines without
 * touching the distributor through the debugger (which the interrupt
 * controller rejects). No timing or protocol of the real peer engine is
 * modeled here; every transition is explicitly requested by a write. */
#include "qemu/osdep.h"
#include "hw/sysbus.h"
#include "hw/qdev-properties.h"
#include "hw/irq.h"
#include "qom/object.h"

#define TYPE_NIKON_Z72_NOTIFY "nikon-z72-notify"
OBJECT_DECLARE_SIMPLE_TYPE(NikonZ72Notify, NIKON_Z72_NOTIFY)

struct NikonZ72Notify {
    SysBusDevice parent_obj;
    MemoryRegion mmio;
    DeviceState *intc;
    bool inject;
};

static void notify_write(void *opaque, hwaddr offset, uint64_t value, unsigned size)
{
    NikonZ72Notify *s = opaque;
    if (!s->inject || !s->intc || value >= 256) {
        return;
    }
    /* Offset 0 raises the selected line and keeps it asserted until the
     * matching release write, mirroring a level notification; offset 4
     * lowers it again. */
    qemu_set_irq(qdev_get_gpio_in(s->intc, value), offset ? 0 : 1);
}

static const MemoryRegionOps notify_ops = {
    .write = notify_write,
    .read = NULL,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4 },
    .impl = { .min_access_size = 4, .max_access_size = 4 },
};

static void notify_realize(DeviceState *dev, Error **errp)
{
    NikonZ72Notify *s = NIKON_Z72_NOTIFY(dev);
    if (s->inject) {
        memory_region_init_io(&s->mmio, OBJECT(dev), &notify_ops, s,
                              TYPE_NIKON_Z72_NOTIFY, 8);
        sysbus_init_mmio(SYS_BUS_DEVICE(dev), &s->mmio);
    }
}

static const Property notify_properties[] = {
    DEFINE_PROP_BOOL("inject", NikonZ72Notify, inject, true),
    DEFINE_PROP_LINK("intc", NikonZ72Notify, intc, TYPE_DEVICE, DeviceState *),
};

static void notify_class_init(ObjectClass *oc, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    device_class_set_props(dc, notify_properties);
    dc->realize = notify_realize;
    dc->user_creatable = false;
}

static const TypeInfo notify_info = {
    .name = TYPE_NIKON_Z72_NOTIFY,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(NikonZ72Notify),
    .class_init = notify_class_init,
};

static void notify_register_types(void)
{
    type_register_static(&notify_info);
}
type_init(notify_register_types)
