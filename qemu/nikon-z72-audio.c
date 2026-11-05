/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "qemu/osdep.h"
#include "qemu/fifo32.h"
#include "qemu/timer.h"
#include "hw/sysbus.h"
#include "hw/irq.h"
#include "hw/resettable.h"
#include "migration/vmstate.h"

#define TYPE_Z72_AUDIO "nikon-z72-audio"
OBJECT_DECLARE_SIMPLE_TYPE(Z72Audio, Z72_AUDIO)

typedef struct AudioChannel {
    Z72Audio *owner;
    unsigned index;
    uint32_t control, mode, status, divider, port;
    uint32_t monitor[2];
    Fifo32 queue[2];
    QEMUTimer *timer;
    qemu_irq irq;
} AudioChannel;

struct Z72Audio {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    uint32_t reset;
    AudioChannel channel[2];
};

/* Queue capacities, thresholds and the 48 MHz clock are functional choices.
 * The firmware establishes the register fields, not physical PCM timing. */
static unsigned audio_capacity(AudioChannel *c)
{
    return c->mode & (1u << 25) ? 16 : 1;
}

static unsigned audio_used(AudioChannel *c)
{
    unsigned used = fifo32_num_used(&c->queue[0]);
    return c->control & 2 ? MAX(used, fifo32_num_used(&c->queue[1])) : used;
}

static uint32_t audio_status(AudioChannel *c)
{
    static const unsigned thresholds[] = {1, 12, 8, 4};
    unsigned threshold = MIN(audio_capacity(c), thresholds[c->status >> 30]);
    unsigned used = fifo32_num_used(&c->queue[0]);
    /* Separate writes alternate lanes. Report room in either lane so a
     * queued first half cannot prevent polling software writing its mate.
     * The addressed lane still enforces its own capacity on every write. */
    if (c->control & 2) {
        used = MIN(used, fifo32_num_used(&c->queue[1]));
    }
    return c->status | (audio_capacity(c) - used >= threshold ?
                        1u << 25 : 0);
}

static bool audio_enabled(AudioChannel *c)
{
    return (c->control & (1u << 13)) && !(c->owner->reset & (1u << c->index));
}

static void audio_irq(AudioChannel *c)
{
    uint32_t status = audio_status(c);
    bool level = (!audio_used(c) && (c->control & (1u << 11))) ||
        ((status & (1u << 25)) && (status & (1u << 27))) ||
        ((status & (1u << 17)) && (status & (1u << 19)));
    qemu_set_irq(c->irq, audio_enabled(c) && level);
}

static void audio_schedule(AudioChannel *c)
{
    if (!audio_enabled(c) || !(c->divider & (1u << 30))) {
        timer_del(c->timer);
    } else if (!timer_pending(c->timer)) {
        uint64_t ticks = (((c->divider >> 24) & 31) + 1) *
            (4 * (((c->divider >> 18) & 7) + 1)) *
            (16 * (((c->divider >> 16) & 3) + 1));
        timer_mod(c->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                           (ticks * 1000 + 47) / 48);
    }
}

static void audio_consume(void *opaque)
{
    AudioChannel *c = opaque;
    if (!audio_enabled(c) || !(c->divider & (1u << 30))) {
        return;
    }
    bool separate = c->control & 2;
    if (fifo32_is_empty(&c->queue[0]) ||
        (separate && fifo32_is_empty(&c->queue[1]))) {
        c->status |= 1u << 17;
    } else {
        uint32_t word = fifo32_pop(&c->queue[0]);
        /* Finite word monitor, not a physical sample-format decoder. */
        c->monitor[0] = word & 0xffff;
        c->monitor[1] = separate ? fifo32_pop(&c->queue[1]) & 0xffff : word >> 16;
    }
    audio_irq(c);
    audio_schedule(c);
}

static void audio_clear(AudioChannel *c)
{
    timer_del(c->timer);
    c->control = c->mode = c->status = c->divider = c->port = 0;
    c->monitor[0] = c->monitor[1] = 0;
    fifo32_reset(&c->queue[0]);
    fifo32_reset(&c->queue[1]);
    audio_irq(c);
}

static MemTxResult audio_read(void *opaque, hwaddr offset, uint64_t *value,
                              unsigned size, MemTxAttrs attrs)
{
    Z72Audio *s = opaque;
    *value = 0;
    if (size != 4 || (offset & 3)) {
        return MEMTX_ERROR;
    }
    if (!offset) {
        *value = s->reset;
        return MEMTX_OK;
    }
    if (offset < 0x100 || offset >= 0x264) {
        return MEMTX_ERROR;
    }
    AudioChannel *c = &s->channel[(offset - 0x100) / 0x100];
    switch (offset & 0xff) {
    case 8: *value = c->control | (audio_used(c) ? 0 : 1u << 9); break;
    case 12: *value = c->mode; break;
    case 16: *value = audio_status(c); break;
    case 20: *value = c->divider; break;
    case 24: *value = c->port; break;
    case 28: case 0x54: case 0x58: break; /* Disconnected input. */
    case 32:
        for (unsigned lane = 0; lane < 2; lane++) {
            unsigned n = fifo32_num_used(&c->queue[c->control & 2 ? lane : 0]);
            for (unsigned i = 0; i < n; i++) {
                *value |= 1u << (2 * i + lane);
            }
        }
        break;
    case 0x5c: case 0x60: *value = c->monitor[((offset & 0xff) - 0x5c) / 4]; break;
    default: return MEMTX_ERROR;
    }
    return MEMTX_OK;
}

static MemTxResult audio_write(void *opaque, hwaddr offset, uint64_t value,
                               unsigned size, MemTxAttrs attrs)
{
    Z72Audio *s = opaque;
    if (size != 4 || (offset & 3)) {
        return MEMTX_ERROR;
    }
    if (!offset) {
        if (value & ~3u) {
            return MEMTX_ERROR;
        }
        s->reset = value;
        for (unsigned i = 0; i < 2; i++) {
            if (value & (1u << i)) {
                audio_clear(&s->channel[i]);
            }
        }
        return MEMTX_OK;
    }
    if (offset < 0x100 || offset >= 0x264) {
        return MEMTX_ERROR;
    }
    AudioChannel *c = &s->channel[(offset - 0x100) / 0x100];
    if (s->reset & (1u << c->index)) {
        return MEMTX_ERROR;
    }
    unsigned lane = 0;
    switch (offset & 0xff) {
    case 8:
        /* DMA output and input activation require providers not yet wired. */
        if ((value & ~0xff8fff03u) || (value & ((1u << 12) | (1u << 15))) ||
            (((value ^ c->control) & 2) && audio_used(c))) {
            return MEMTX_ERROR;
        }
        c->control = value & ~0x300u;
        break;
    case 12:
        if ((value & ~0x0f8f0000u) ||
            (((value ^ c->mode) & (1u << 25)) && audio_used(c))) {
            return MEMTX_ERROR;
        }
        c->mode = value;
        break;
    case 16:
        if ((value & ~0xff0f0000u) || (value & (1u << 29))) {
            return MEMTX_ERROR;
        }
        c->status = (value & 0xfc0c0000u) | (c->status & value & 0x30000u);
        break;
    case 20:
        if (value & ~0xdf1f0000u) {
            return MEMTX_ERROR;
        }
        c->divider = value;
        timer_del(c->timer);
        break;
    case 24:
        if (value & ~0x33030101u) {
            return MEMTX_ERROR;
        }
        c->port = value;
        break;
    case 4: case 0x3c:
        if (c->control & 2) {
            return MEMTX_ERROR;
        }
        goto enqueue;
    case 0x34:
        lane = 1;
        /* fall through */
    case 0x30:
        if (!(c->control & 2)) {
            return MEMTX_ERROR;
        }
    enqueue:
        if (fifo32_num_used(&c->queue[lane]) == audio_capacity(c)) {
            return MEMTX_ERROR;
        }
        fifo32_push(&c->queue[lane], value);
        break;
    default: return MEMTX_ERROR;
    }
    audio_irq(c);
    audio_schedule(c);
    return MEMTX_OK;
}

static const MemoryRegionOps audio_ops = {
    .read_with_attrs = audio_read, .write_with_attrs = audio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 4, .unaligned = true },
    .impl = { .min_access_size = 1, .max_access_size = 4, .unaligned = true },
};

static void audio_reset(Object *obj, ResetType type)
{
    Z72Audio *s = Z72_AUDIO(obj);
    s->reset = 0;
    for (unsigned i = 0; i < 2; i++) {
        audio_clear(&s->channel[i]);
    }
}

static void audio_init(Object *obj)
{
    Z72Audio *s = Z72_AUDIO(obj);
    memory_region_init_io(&s->iomem, obj, &audio_ops, s, TYPE_Z72_AUDIO, 0x400);
    sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->iomem);
    for (unsigned i = 0; i < 2; i++) {
        AudioChannel *c = &s->channel[i];
        c->owner = s;
        c->index = i;
        for (unsigned lane = 0; lane < 2; lane++) {
            fifo32_create(&c->queue[lane], 16);
        }
        c->timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, audio_consume, c);
        sysbus_init_irq(SYS_BUS_DEVICE(s), &c->irq);
    }
}

static void audio_finalize(Object *obj)
{
    Z72Audio *s = Z72_AUDIO(obj);
    for (unsigned i = 0; i < 2; i++) {
        timer_free(s->channel[i].timer);
        for (unsigned lane = 0; lane < 2; lane++) {
            fifo32_destroy(&s->channel[i].queue[lane]);
        }
    }
}

static const VMStateDescription audio_vmstate = {
    .name = TYPE_Z72_AUDIO, .unmigratable = true,
};

static void audio_class_init(ObjectClass *klass, const void *data)
{
    DEVICE_CLASS(klass)->vmsd = &audio_vmstate;
    RESETTABLE_CLASS(klass)->phases.hold = audio_reset;
}

static const TypeInfo audio_type = {
    .name = TYPE_Z72_AUDIO, .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(Z72Audio), .instance_init = audio_init,
    .instance_finalize = audio_finalize, .class_init = audio_class_init,
};

static void audio_register(void)
{
    type_register_static(&audio_type);
}
type_init(audio_register)
