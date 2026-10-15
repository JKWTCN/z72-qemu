/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Experimental internal delay mode of the twelve-channel block.
 * The byte divider scales the internal clock; capture/compare modes retain
 * register storage without external events. See research/z7ii/delay_counter.md. */
#include "qemu/osdep.h"
#include "qemu/timer.h"
#include "hw/sysbus.h"
#include "hw/irq.h"
#include "hw/resettable.h"
#include "migration/vmstate.h"

#define TYPE_NIKON_Z72_DELAY "nikon-z72-delay"
OBJECT_DECLARE_SIMPLE_TYPE(NikonZ72Delay, NIKON_Z72_DELAY)

#define CHANNELS 12
#define WORDS (0x2000 / 4)
#define A(ch) (((ch) + 1) * 0x100)
#define B(ch) (0x1000 + A(ch))
#define REG(s, off) ((s)->regs[(off) / 4])

typedef struct Z72DelayChannel {
    NikonZ72Delay *owner;
    QEMUTimer *timer;
    qemu_irq irq;
    uint32_t index;
    uint32_t counter;
    int64_t epoch;
    bool clocked;
} Z72DelayChannel;

struct NikonZ72Delay {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    uint32_t regs[WORDS];
    Z72DelayChannel channels[CHANNELS];
};

static bool delay_enabled(Z72DelayChannel *ch)
{
    NikonZ72Delay *s = ch->owner;
    unsigned i = ch->index;

    return !(REG(s, 0) & 1) && (REG(s, 4) & 1) &&
        (REG(s, 0x1000) & (1u << i)) &&
        !(REG(s, B(i)) & 1) && REG(s, B(i) + 4) <= UINT8_MAX;
}

static uint64_t delay_tick_ns(Z72DelayChannel *ch)
{
    return ((uint64_t)REG(ch->owner, B(ch->index) + 4) + 1) * 20;
}

static void delay_irq(Z72DelayChannel *ch)
{
    NikonZ72Delay *s = ch->owner;
    unsigned i = ch->index;

    qemu_set_irq(ch->irq, !(REG(s, 0x100c) & (1u << i)) &&
                 (REG(s, A(i) + 0x10) & REG(s, A(i)) & 1) != 0);
}

static uint32_t delay_count(Z72DelayChannel *ch)
{
    if (ch->clocked) {
        uint64_t elapsed = (qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) - ch->epoch) /
                           delay_tick_ns(ch);
        uint32_t remaining = REG(ch->owner, B(ch->index) + 8) - ch->counter;
        return ch->counter + MIN(elapsed, remaining);
    }
    return ch->counter;
}

static void delay_stop(Z72DelayChannel *ch)
{
    ch->counter = delay_count(ch);
    ch->clocked = false;
    timer_del(ch->timer);
}

static void delay_schedule(Z72DelayChannel *ch)
{
    if (!delay_enabled(ch)) {
        delay_stop(ch);
    } else if (!ch->clocked) {
        uint32_t terminal = REG(ch->owner, B(ch->index) + 8);

        if (ch->counter > terminal) {
            return;
        }
        /* Firmware converts delay units to ticks by multiplying by 50.
         * A 50 MHz clock and terminal-count semantics are laboratory timing
         * assumptions, not a measured physical clock specification. */
        uint64_t ns = ((uint64_t)terminal - ch->counter + 1) * delay_tick_ns(ch);
        ch->epoch = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
        ch->clocked = true;
        timer_mod(ch->timer, ch->epoch + ns);
    }
}

static void delay_expire(void *opaque)
{
    Z72DelayChannel *ch = opaque;

    if (ch->clocked) {
        /* The preset controls the first interval. Subsequent intervals
         * count from zero to the programmed terminal, not from the preset. */
        ch->counter = 0;
        ch->clocked = false;
        REG(ch->owner, A(ch->index) + 0x10) |= 1;
        delay_irq(ch);
        delay_schedule(ch);
    }
}

static uint64_t delay_read(void *opaque, hwaddr offset, unsigned size)
{
    NikonZ72Delay *s = opaque;
    unsigned slot = (offset & 0xfff) / 0x100;

    if (offset >= 0x1100 && slot >= 1 && slot <= CHANNELS &&
        (offset & 0xff) == 0xc) {
        return delay_count(&s->channels[slot - 1]);
    }
    return REG(s, offset);
}

static void delay_clear_channel(Z72DelayChannel *ch)
{
    NikonZ72Delay *s = ch->owner;

    timer_del(ch->timer);
    ch->clocked = false;
    ch->counter = 0;
    ch->epoch = 0;
    REG(s, A(ch->index) + 0x10) = 0;
    REG(s, B(ch->index) + 0xc) = 0;
    delay_irq(ch);
}

static void delay_write(void *opaque, hwaddr offset, uint64_t value,
                        unsigned size)
{
    NikonZ72Delay *s = opaque;
    unsigned slot = (offset & 0xfff) / 0x100;
    unsigned reg = offset & 0xff;

    if (offset >= 0x1100 && slot >= 1 && slot <= CHANNELS) {
        if (reg == 0xc) {
            return;
        }
        if (reg == 4 || reg == 8) {
            delay_stop(&s->channels[slot - 1]);
        }
    }
    if (offset < 0x1000 && slot >= 1 && slot <= CHANNELS && reg == 0x10) {
        REG(s, offset) &= ~value;
    } else {
        REG(s, offset) = value;
    }
    if (offset == 0 && (value & 1)) {
        memset(s->regs, 0, sizeof(s->regs));
        REG(s, 0) = value;
        for (unsigned i = 0; i < CHANNELS; i++) {
            delay_clear_channel(&s->channels[i]);
        }
    } else if (offset >= 0x1100 && slot >= 1 && slot <= CHANNELS &&
               reg == 0 && (value & 1)) {
        delay_clear_channel(&s->channels[slot - 1]);
    } else if (offset == 0x1008) {
        for (unsigned i = 0; i < CHANNELS; i++) {
            if (value & (1u << i)) {
                Z72DelayChannel *ch = &s->channels[i];
                delay_stop(ch);
                ch->counter = REG(s, 0x1004);
            }
        }
    }
    for (unsigned i = 0; i < CHANNELS; i++) {
        delay_irq(&s->channels[i]);
        delay_schedule(&s->channels[i]);
    }
}

static const MemoryRegionOps delay_ops = {
    .read = delay_read,
    .write = delay_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4 },
    .impl = { .min_access_size = 4, .max_access_size = 4 },
};

static void delay_reset(Object *obj, ResetType type)
{
    NikonZ72Delay *s = NIKON_Z72_DELAY(obj);

    memset(s->regs, 0, sizeof(s->regs));
    for (unsigned i = 0; i < CHANNELS; i++) {
        delay_clear_channel(&s->channels[i]);
    }
}

static int delay_post_load(void *opaque, int version_id)
{
    NikonZ72Delay *s = opaque;

    for (unsigned i = 0; i < CHANNELS; i++) {
        delay_irq(&s->channels[i]);
    }
    return 0;
}

static const VMStateDescription delay_channel_vmstate = {
    .name = TYPE_NIKON_Z72_DELAY "/channel",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT32(counter, Z72DelayChannel),
        VMSTATE_INT64(epoch, Z72DelayChannel),
        VMSTATE_BOOL(clocked, Z72DelayChannel),
        VMSTATE_TIMER_PTR(timer, Z72DelayChannel),
        VMSTATE_END_OF_LIST()
    },
};

static const VMStateDescription delay_vmstate = {
    .name = TYPE_NIKON_Z72_DELAY,
    .version_id = 1,
    .minimum_version_id = 1,
    .post_load = delay_post_load,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT32_ARRAY(regs, NikonZ72Delay, WORDS),
        VMSTATE_STRUCT_ARRAY(channels, NikonZ72Delay, CHANNELS, 1,
                             delay_channel_vmstate, Z72DelayChannel),
        VMSTATE_END_OF_LIST()
    },
};

static void delay_init(Object *obj)
{
    NikonZ72Delay *s = NIKON_Z72_DELAY(obj);

    memory_region_init_io(&s->iomem, obj, &delay_ops, s,
                          TYPE_NIKON_Z72_DELAY, 0x2000);
    sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->iomem);
    for (unsigned i = 0; i < CHANNELS; i++) {
        Z72DelayChannel *ch = &s->channels[i];
        ch->owner = s;
        ch->index = i;
        ch->timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, delay_expire, ch);
        sysbus_init_irq(SYS_BUS_DEVICE(s), &ch->irq);
    }
}

static void delay_finalize(Object *obj)
{
    NikonZ72Delay *s = NIKON_Z72_DELAY(obj);

    for (unsigned i = 0; i < CHANNELS; i++) {
        timer_free(s->channels[i].timer);
    }
}

static void delay_class_init(ObjectClass *oc, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);

    dc->vmsd = &delay_vmstate;
    dc->user_creatable = false;
    RESETTABLE_CLASS(oc)->phases.hold = delay_reset;
}

static const TypeInfo delay_info = {
    .name = TYPE_NIKON_Z72_DELAY,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(NikonZ72Delay),
    .instance_init = delay_init,
    .instance_finalize = delay_finalize,
    .class_init = delay_class_init,
};

static void delay_register_types(void)
{
    type_register_static(&delay_info);
}
type_init(delay_register_types)
