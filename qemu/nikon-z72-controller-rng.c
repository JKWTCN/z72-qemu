/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "qemu/osdep.h"
#include "qemu/guest-random.h"
#include "qemu/timer.h"
#include "hw/sysbus.h"
#include "hw/irq.h"
#include "hw/qdev-properties.h"
#include "hw/resettable.h"
#include "migration/vmstate.h"

#define TYPE_Z72_CONTROLLER_RNG "nikon-z72-controller-rng"
OBJECT_DECLARE_SIMPLE_TYPE(Z72ControllerRNG, Z72_CONTROLLER_RNG)

struct Z72ControllerRNG {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    uint32_t control;
    uint32_t status;
    uint32_t data;
    bool completion;
    QEMUTimer *timer;
    qemu_irq irq;
};

static void rng_irq(Z72ControllerRNG *s)
{
    qemu_set_irq(s->irq, !!((s->control & 8) && (s->status & 1)));
}

static void rng_schedule(Z72ControllerRNG *s)
{
    if ((s->control & 4) && !(s->status & 1) && s->completion &&
        !timer_pending(s->timer)) {
        timer_mod(s->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 1000);
    }
}

static void rng_complete(void *opaque)
{
    Z72ControllerRNG *s = opaque;
    qemu_guest_getrandom_nofail(&s->data, sizeof(s->data));
    s->status |= 1;
    rng_irq(s);
}

static MemTxResult rng_read(void *opaque, hwaddr offset, uint64_t *value,
                           unsigned size, MemTxAttrs attrs)
{
    Z72ControllerRNG *s = opaque;
    if (size != 4 || (offset & 3) || offset > 8) {
        return MEMTX_ERROR;
    }
    if (offset == 0) {
        *value = s->control;
    } else if (offset == 4) {
        *value = s->status;
    } else {
        *value = s->data;
        s->status &= ~1u;
        rng_irq(s);
        rng_schedule(s);
    }
    return MEMTX_OK;
}

static MemTxResult rng_write(void *opaque, hwaddr offset, uint64_t value,
                            unsigned size, MemTxAttrs attrs)
{
    Z72ControllerRNG *s = opaque;
    if (size != 4 || (offset & 3) || offset > 4 ||
        (offset == 0 && (value & ~0xcu))) {
        return MEMTX_ERROR;
    }
    if (offset == 0) {
        s->control = value;
        if (!(value & 4)) {
            timer_del(s->timer);
        }
        rng_schedule(s);
        rng_irq(s);
    }
    /* DRDY is read-only; seed and clock errors are not generated. */
    return MEMTX_OK;
}

static const MemoryRegionOps rng_ops = {
    .read_with_attrs = rng_read, .write_with_attrs = rng_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 4 },
    .impl = { .min_access_size = 1, .max_access_size = 4 },
};

static void rng_reset(Object *obj, ResetType type)
{
    Z72ControllerRNG *s = Z72_CONTROLLER_RNG(obj);
    timer_del(s->timer);
    s->control = s->status = s->data = 0;
    rng_irq(s);
}

static int rng_post_load(void *opaque, int version)
{
    Z72ControllerRNG *s = opaque;
    if ((s->control & ~0xcu) || (s->status & ~1u) ||
        (timer_pending(s->timer) && (!(s->control & 4) || s->status))) {
        return -EINVAL;
    }
    rng_irq(s);
    return 0;
}

static const VMStateDescription rng_state = {
    .name = TYPE_Z72_CONTROLLER_RNG, .version_id = 1, .minimum_version_id = 1,
    .post_load = rng_post_load,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT32(control, Z72ControllerRNG),
        VMSTATE_UINT32(status, Z72ControllerRNG),
        VMSTATE_UINT32(data, Z72ControllerRNG),
        VMSTATE_TIMER_PTR(timer, Z72ControllerRNG),
        VMSTATE_END_OF_LIST()
    },
};

static const Property rng_properties[] = {
    DEFINE_PROP_BOOL("completion", Z72ControllerRNG, completion, true),
};

static void rng_init(Object *obj)
{
    Z72ControllerRNG *s = Z72_CONTROLLER_RNG(obj);
    memory_region_init_io(&s->iomem, obj, &rng_ops, s, TYPE_Z72_CONTROLLER_RNG, 0x400);
    sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->iomem);
    sysbus_init_irq(SYS_BUS_DEVICE(s), &s->irq);
    s->timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, rng_complete, s);
}

static void rng_finalize(Object *obj)
{
    timer_free(Z72_CONTROLLER_RNG(obj)->timer);
}

static void rng_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->vmsd = &rng_state;
    device_class_set_props(dc, rng_properties);
    RESETTABLE_CLASS(klass)->phases.hold = rng_reset;
}

static void rng_register_types(void)
{
    static const TypeInfo info = {
        .name = TYPE_Z72_CONTROLLER_RNG, .parent = TYPE_SYS_BUS_DEVICE,
        .instance_size = sizeof(Z72ControllerRNG), .instance_init = rng_init,
        .instance_finalize = rng_finalize, .class_init = rng_class_init,
    };
    type_register_static(&info);
}
type_init(rng_register_types)
