/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "qemu/osdep.h"
#include "qemu/timer.h"
#include "qapi/error.h"
#include "hw/sysbus.h"
#include "hw/irq.h"
#include "hw/qdev-properties.h"
#include "hw/resettable.h"
#include "migration/vmstate.h"

#define TYPE_Z72_CONTROLLER_TIMER "nikon-z72-controller-timer"
OBJECT_DECLARE_SIMPLE_TYPE(Z72ControllerTimer, Z72_CONTROLLER_TIMER)

struct Z72ControllerTimer {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    uint32_t registers[20];
    uint32_t count;
    int64_t base_ns;
    uint64_t frequency;
    uint8_t channels;
    uint8_t counter_bits;
    bool advanced;
    bool completion;
    uint8_t input_levels;
    QEMUTimer *timer;
    qemu_irq irqs[4];
};

static uint32_t timer_counter_mask(Z72ControllerTimer *s)
{
    return s->counter_bits == 32 ? UINT32_MAX : 0xffff;
}

static uint64_t timer_tick_ns(Z72ControllerTimer *s)
{
    return DIV_ROUND_UP(UINT64_C(1000000000) * (s->registers[10] + 1), s->frequency);
}

static bool timer_compare_channel(Z72ControllerTimer *s, unsigned channel)
{
    uint32_t mode = s->registers[6 + channel / 2];
    return ((mode >> ((channel % 2) * 8)) & 3) == 0;
}

static void timer_irq(Z72ControllerTimer *s)
{
    uint32_t pending = s->registers[3] & s->registers[4];
    static const unsigned masks[] = { 1, 0x1e, 0x60, 0x80 };
    for (unsigned i = 0; i < 4; i++) {
        qemu_set_irq(s->irqs[i], !!(pending & masks[i]));
    }
}

static void timer_sync(Z72ControllerTimer *s)
{
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    uint64_t tick = timer_tick_ns(s);
    uint64_t period = (uint64_t)s->registers[11] + 1;
    if (!(s->registers[0] & 1) || now <= s->base_ns) {
        return;
    }
    uint64_t elapsed = (now - s->base_ns) / tick;
    uint64_t total = s->count + elapsed;
    bool overflow = total >= period;
    bool stop = overflow && (s->registers[0] & 8);
    uint64_t effective = stop ? period - s->count : elapsed;
    if (s->completion) {
        if (overflow && !(s->registers[0] & 2)) {
            s->registers[4] |= 1;
        }
        for (unsigned i = 0; i < s->channels; i++) {
            uint32_t compare = s->registers[13 + i];
            if (!timer_compare_channel(s, i)) {
                continue;
            }
            uint64_t distance = compare >= period ? period - s->count :
                                (compare + period - s->count) % period;
            if (effective >= (distance ? distance : period)) {
                s->registers[4] |= 2u << i;
            }
        }
    }
    if (stop) {
        s->registers[0] &= ~1u;
        s->count = 0;
        s->base_ns = now;
    } else {
        s->count = total % period;
        /* Keep partial ticks so frequent counter reads cannot slow time. */
        s->base_ns += elapsed * tick;
    }
    timer_irq(s);
}

static void timer_schedule(Z72ControllerTimer *s)
{
    timer_del(s->timer);
    if (!(s->registers[0] & 1) || !s->completion) {
        return;
    }
    uint64_t period = (uint64_t)s->registers[11] + 1;
    uint64_t distance = period - s->count;
    for (unsigned i = 0; i < s->channels; i++) {
        uint32_t compare = s->registers[13 + i];
        if (compare < period && timer_compare_channel(s, i)) {
            uint64_t next = (compare + period - s->count) % period;
            distance = MIN(distance, next ? next : period);
        }
    }
    uint64_t delay = distance * timer_tick_ns(s);
    timer_mod(s->timer, s->base_ns > INT64_MAX - (int64_t)delay ?
              INT64_MAX : s->base_ns + (int64_t)delay);
}

static void timer_event(void *opaque)
{
    Z72ControllerTimer *s = opaque;
    timer_sync(s);
    timer_schedule(s);
}

static void timer_capture(void *opaque, int line, int level)
{
    Z72ControllerTimer *s = opaque;
    bool previous = !!(s->input_levels & (1u << line));
    s->input_levels = (s->input_levels & ~(1u << line)) | (level ? 1u << line : 0);
    if (line >= s->channels || previous == !!level || !s->completion ||
        !(s->registers[0] & 1) || resettable_is_in_reset(OBJECT(s))) {
        return;
    }
    timer_sync(s);
    if (!(s->registers[0] & 1)) {
        timer_schedule(s);
        return;
    }
    for (unsigned channel = 0; channel < s->channels; channel++) {
        unsigned mode = (s->registers[6 + channel / 2] >> ((channel % 2) * 8)) & 0xff;
        unsigned selection = mode & 3;
        unsigned control = (s->registers[8] >> (channel * 4)) & 0xf;
        if ((mode & 0xfc) || !(control & 1) ||
            !((selection == 1 && line == channel) ||
              (selection == 2 && line == (channel ^ 1)))) {
            continue;
        }
        bool rising = !(control & 2);
        bool both = (control & 0xa) == 0xa;
        if (!both && ((control & 8) || rising != !!level)) {
            continue;
        }
        uint32_t flag = 2u << channel;
        if (s->registers[4] & flag) {
            s->registers[4] |= 0x200u << channel;
        }
        s->registers[13 + channel] = s->count;
        s->registers[4] |= flag;
    }
    timer_irq(s);
    timer_schedule(s);
}

static bool timer_register(hwaddr offset, unsigned size)
{
    return size == 4 && !(offset & 3) && offset <= 0x4c;
}

static MemTxResult timer_read(void *opaque, hwaddr offset, uint64_t *value,
                             unsigned size, MemTxAttrs attrs)
{
    Z72ControllerTimer *s = opaque;
    if (!timer_register(offset, size)) {
        return MEMTX_ERROR;
    }
    timer_sync(s);
    *value = offset == 0x24 ? s->count : offset == 0x14 ? 0 : s->registers[offset / 4];
    if (offset >= 0x34 && offset < 0x34 + s->channels * 4 &&
        !timer_compare_channel(s, (offset - 0x34) / 4)) {
        s->registers[4] &= ~(2u << ((offset - 0x34) / 4));
        timer_irq(s);
    }
    return MEMTX_OK;
}

static MemTxResult timer_write(void *opaque, hwaddr offset, uint64_t value,
                              unsigned size, MemTxAttrs attrs)
{
    Z72ControllerTimer *s = opaque;
    uint32_t events = ((1u << (s->channels + 1)) - 1) | (s->advanced ? 0xe0 : 0);
    if (!timer_register(offset, size) || offset == 0x4c ||
        (offset == 0 && (value & 0x70)) ||
        (offset == 8 && (value & 7)) ||
        (offset == 0x30 && value) ||
        (offset == 0x14 && (value & ~events))) {
        return MEMTX_ERROR;
    }
    timer_sync(s);
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    if (offset >= 0x34 && offset < 0x34 + s->channels * 4 &&
        !timer_compare_channel(s, (offset - 0x34) / 4)) {
        timer_schedule(s);
        return MEMTX_OK;
    }
    if (offset == 0x10) {
        s->registers[4] &= value;
    } else if (offset == 0x14) {
        if (value & 1) {
            s->count = 0;
            s->base_ns = now;
        }
        s->registers[4] |= value & events & ~1u;
        if ((value & 1) && !(s->registers[0] & 6)) {
            s->registers[4] |= 1;
        }
    } else if (offset == 0x24) {
        s->count = (value & timer_counter_mask(s)) % ((uint64_t)s->registers[11] + 1);
        s->base_ns = now;
    } else {
        bool was_enabled = s->registers[0] & 1;
        s->registers[offset / 4] =
            (offset == 0x28 || offset == 0x2c || (offset >= 0x34 && offset <= 0x40)) ?
            value & (offset == 0x28 ? 0xffff : timer_counter_mask(s)) : value;
        if (offset == 0 || offset == 0x28 || offset == 0x2c) {
            if (offset != 0 || !was_enabled || !(value & 1)) {
                s->base_ns = now;
            }
            s->count %= (uint64_t)s->registers[11] + 1;
        }
    }
    timer_irq(s);
    timer_schedule(s);
    return MEMTX_OK;
}

static const MemoryRegionOps timer_ops = {
    .read_with_attrs = timer_read, .write_with_attrs = timer_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 4 },
    .impl = { .min_access_size = 1, .max_access_size = 4 },
};

static void timer_reset(Object *obj, ResetType type)
{
    Z72ControllerTimer *s = Z72_CONTROLLER_TIMER(obj);
    timer_del(s->timer);
    memset(s->registers, 0, sizeof(s->registers));
    s->registers[11] = timer_counter_mask(s);
    s->count = 0;
    s->base_ns = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    timer_irq(s);
}

static int timer_post_load(void *opaque, int version)
{
    Z72ControllerTimer *s = opaque;
    if (version < 2) {
        s->input_levels = 0;
    }
    if (s->registers[10] > 0xffff || s->registers[11] > timer_counter_mask(s) ||
        s->count > s->registers[11] || (s->registers[0] & 0x70) ||
        (s->registers[2] & 7) || s->registers[12]) {
        return -EINVAL;
    }
    for (unsigned i = 0; i < 4; i++) {
        if (s->registers[13 + i] > timer_counter_mask(s)) {
            return -EINVAL;
        }
    }
    timer_irq(s);
    return 0;
}

static const VMStateDescription timer_state = {
    .name = TYPE_Z72_CONTROLLER_TIMER, .version_id = 2, .minimum_version_id = 1,
    .post_load = timer_post_load,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT32_ARRAY(registers, Z72ControllerTimer, 20),
        VMSTATE_UINT32(count, Z72ControllerTimer),
        VMSTATE_INT64(base_ns, Z72ControllerTimer),
        VMSTATE_TIMER_PTR(timer, Z72ControllerTimer),
        VMSTATE_UINT8_V(input_levels, Z72ControllerTimer, 2),
        VMSTATE_END_OF_LIST()
    },
};

static const Property timer_properties[] = {
    DEFINE_PROP_UINT64("clock-frequency", Z72ControllerTimer, frequency, 100000000),
    DEFINE_PROP_UINT8("channels", Z72ControllerTimer, channels, 4),
    DEFINE_PROP_UINT8("counter-bits", Z72ControllerTimer, counter_bits, 16),
    DEFINE_PROP_BOOL("advanced", Z72ControllerTimer, advanced, false),
    DEFINE_PROP_BOOL("completion", Z72ControllerTimer, completion, true),
};

static void timer_realize(DeviceState *dev, Error **errp)
{
    Z72ControllerTimer *s = Z72_CONTROLLER_TIMER(dev);
    if (!s->frequency || s->frequency > 1000000000 ||
        !s->channels || s->channels > 4 ||
        (s->counter_bits != 16 && s->counter_bits != 32)) {
        error_setg(errp, "Unsupported controller timer clock, channel count or counter width");
    }
}

static void controller_timer_init(Object *obj)
{
    Z72ControllerTimer *s = Z72_CONTROLLER_TIMER(obj);
    memory_region_init_io(&s->iomem, obj, &timer_ops, s, TYPE_Z72_CONTROLLER_TIMER, 0x400);
    sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->iomem);
    for (unsigned i = 0; i < 4; i++) {
        sysbus_init_irq(SYS_BUS_DEVICE(s), &s->irqs[i]);
    }
    s->timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, timer_event, s);
    qdev_init_gpio_in_named(DEVICE(obj), timer_capture, "capture", 4);
}

static void timer_finalize(Object *obj)
{
    timer_free(Z72_CONTROLLER_TIMER(obj)->timer);
}

static void timer_unrealize(DeviceState *dev)
{
    timer_del(Z72_CONTROLLER_TIMER(dev)->timer);
}

static void timer_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->realize = timer_realize;
    dc->unrealize = timer_unrealize;
    dc->vmsd = &timer_state;
    device_class_set_props(dc, timer_properties);
    RESETTABLE_CLASS(klass)->phases.hold = timer_reset;
}

static void timer_register_types(void)
{
    static const TypeInfo info = {
        .name = TYPE_Z72_CONTROLLER_TIMER, .parent = TYPE_SYS_BUS_DEVICE,
        .instance_size = sizeof(Z72ControllerTimer), .instance_init = controller_timer_init,
        .instance_finalize = timer_finalize, .class_init = timer_class_init,
    };
    type_register_static(&info);
}
type_init(timer_register_types)
