/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Experimental delay and explicit capture events of the twelve-channel block.
 * See research/z7ii/delay_counter.md for recovered contracts and limitations. */
#include "qemu/osdep.h"
#include "qemu/timer.h"
#include "hw/sysbus.h"
#include "hw/irq.h"
#include "hw/resettable.h"
#include "migration/vmstate.h"

#define TYPE_NIKON_Z72_DELAY "nikon-z72-delay"
OBJECT_DECLARE_SIMPLE_TYPE(NikonZ72Delay, NIKON_Z72_DELAY)

#define CHANNELS 12
#define LIMITED_CHANNELS 5
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
    qemu_irq capture_ready[2];
    uint8_t capture_levels[4];
    uint8_t capture_pin_levels[2];
    Z72DelayChannel channels[CHANNELS];
};

/* Eligibility is derived from the same gates as an external capture. */
static void delay_capture_ready(NikonZ72Delay *s)
{
    for (unsigned i = 0; i < 2; i++) {
        unsigned channel = 5 + i;
        qemu_set_irq(s->capture_ready[i], s->channels[channel].clocked &&
            (REG(s, B(channel) + 0x10) & 1) &&
            !(REG(s, A(channel) + 8) & 0x20));
    }
}

static bool delay_enabled(Z72DelayChannel *ch)
{
    NikonZ72Delay *s = ch->owner;
    unsigned i = ch->index;

    return !(REG(s, 0) & 1) && (REG(s, 4) & 1) &&
        (REG(s, 0x1000) & (1u << i)) &&
        !(REG(s, B(i)) & 1) && REG(s, B(i) + 4) <= UINT8_MAX &&
        !(i < LIMITED_CHANNELS && (REG(s, B(i) + 0x38) & 1) &&
          REG(s, B(i) + 0x3c) != 0 &&
          REG(s, B(i) + 0x40) >= REG(s, B(i) + 0x3c));
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
                 (REG(s, A(i) + 0x10) & REG(s, A(i)) & 15) != 0);
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

static void delay_latch_capture(NikonZ72Delay *s, unsigned channel, unsigned latch)
{
    Z72DelayChannel *ch = &s->channels[channel];

    /* The alternate mode selected by A+8 bit 5 has no established semantics. */
    if (ch->clocked && (REG(s, B(channel) + 0x10) & 1) &&
        !(REG(s, A(channel) + 8) & 0x20)) {
        REG(s, B(channel) + 0x14 + latch * 4) = delay_count(ch);
        REG(s, A(channel) + 0x10) |= 2u << latch;
        delay_irq(ch);
    }
}

static void delay_capture(void *opaque, int line, int level)
{
    NikonZ72Delay *s = opaque;
    bool rising = level && !s->capture_levels[line];

    s->capture_levels[line] = !!level;
    if (rising) {
        delay_latch_capture(s, 5 + line / 2, line % 2);
    }
}

static void delay_capture_level(void *opaque, int line, int level)
{
    NikonZ72Delay *s = opaque;

    if (s->capture_pin_levels[line] != !!level) {
        s->capture_pin_levels[line] = !!level;
        /* Virtual signal convention: rise selects latch 0, fall latch 1.
         * Physical routing and electrical polarity remain unverified. */
        delay_latch_capture(s, 5 + line, level ? 0 : 1);
    }
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
        /* The first five descriptors expose a repetition limiter. C 1.70
         * enables it with a count of one for output completion timers.
         * Retain the terminal event, add the limit event, and stop scheduling
         * when that count is reached. The software run bit stays latched. */
        if (ch->index < LIMITED_CHANNELS &&
            (REG(ch->owner, B(ch->index) + 0x38) & 1) &&
            REG(ch->owner, B(ch->index) + 0x3c) != 0) {
            uint32_t *count = &REG(ch->owner, B(ch->index) + 0x40);
            (*count)++;
            if (*count >= REG(ch->owner, B(ch->index) + 0x3c)) {
                REG(ch->owner, A(ch->index) + 0x10) |= 8;
            }
        }
        delay_irq(ch);
        delay_schedule(ch);
        delay_capture_ready(ch->owner);
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
    if (ch->index == 5 || ch->index == 6) {
        REG(s, B(ch->index) + 0x14) = 0;
        REG(s, B(ch->index) + 0x18) = 0;
    }
    if (ch->index < LIMITED_CHANNELS) {
        REG(s, B(ch->index) + 0x40) = 0;
    }
    delay_irq(ch);
}

static void delay_write(void *opaque, hwaddr offset, uint64_t value,
                        unsigned size)
{
    NikonZ72Delay *s = opaque;
    unsigned slot = (offset & 0xfff) / 0x100;
    unsigned reg = offset & 0xff;

    if (offset >= 0x1100 && slot >= 1 && slot <= CHANNELS) {
        if (reg == 0xc || (reg == 0x40 && slot <= LIMITED_CHANNELS) ||
            ((slot == 6 || slot == 7) && (reg == 0x14 || reg == 0x18))) {
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
    delay_capture_ready(s);
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
    memset(s->capture_levels, 0, sizeof(s->capture_levels));
    /* Preserve external signal levels: reset does not release a held input. */
    for (unsigned i = 0; i < CHANNELS; i++) {
        delay_clear_channel(&s->channels[i]);
    }
    delay_capture_ready(s);
}

static int delay_post_load(void *opaque, int version_id)
{
    NikonZ72Delay *s = opaque;

    for (unsigned i = 0; i < CHANNELS; i++) {
        delay_irq(&s->channels[i]);
    }
    delay_capture_ready(s);
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
    .version_id = 3,
    .minimum_version_id = 3,
    .post_load = delay_post_load,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT32_ARRAY(regs, NikonZ72Delay, WORDS),
        VMSTATE_UINT8_ARRAY(capture_levels, NikonZ72Delay, 4),
        VMSTATE_UINT8_ARRAY(capture_pin_levels, NikonZ72Delay, 2),
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
    qdev_init_gpio_out_named(DEVICE(s), s->capture_ready, "capture-ready", 2);
    qdev_init_gpio_in_named(DEVICE(s), delay_capture, "capture-event", 4);
    qdev_init_gpio_in_named(DEVICE(s), delay_capture_level, "capture-level", 2);
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
