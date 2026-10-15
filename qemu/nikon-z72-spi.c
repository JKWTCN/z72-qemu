/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "qemu/osdep.h"
#include "hw/sysbus.h"
#include "hw/irq.h"
#include "hw/qdev-properties.h"
#include "hw/resettable.h"
#include "migration/vmstate.h"
#include "qemu/timer.h"
#include "hw/ssi/ssi.h"
#include "qapi/error.h"

#define TYPE_NIKON_Z72_SPI "nikon-z72-spi"
OBJECT_DECLARE_SIMPLE_TYPE(NikonZ72Spi, NIKON_Z72_SPI)
#define SPI_CHANNELS 11
#define SPI_DEPTH 64

typedef struct NikonZ72SpiChannel {
    NikonZ72Spi *owner;
    unsigned index;
    uint32_t regs[64];
    uint16_t tx[SPI_DEPTH], rx[SPI_DEPTH];
    uint32_t tx_count, rx_count, rx_head, pending;
    QEMUTimer *timer;
} NikonZ72SpiChannel;

struct NikonZ72Spi {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    qemu_irq irq[SPI_CHANNELS * 2];
    NikonZ72SpiChannel channel[SPI_CHANNELS];
    bool enabled;
    char *bus_name;
    uint8_t peer_bits;
    bool low_byte_first;
    uint64_t word_delay_ns;
    SSIBus *buses[SPI_CHANNELS];
    uint8_t shifted[SPI_CHANNELS];
    uint16_t receiving[SPI_CHANNELS];
};

static bool spi_attached(NikonZ72SpiChannel *c)
{
    return !QTAILQ_EMPTY(&BUS(c->owner->buses[c->index])->children);
}

static void spi_irq(NikonZ72SpiChannel *c)
{
    uint32_t active = c->pending & c->regs[0x20 / 4];
    qemu_set_irq(c->owner->irq[c->index * 2], (active & 3) != 0);
    qemu_set_irq(c->owner->irq[c->index * 2 + 1], (active & 4) != 0);
}

/* Firmware polls +0x14 bits 4/5/2 for full/empty/idle, reads capacity at
 * +0x48, and acknowledges causes at +0x28. A disconnected bus samples
 * input high. Capacity and completion latency are laboratory parameters. */
static void spi_complete(void *opaque)
{
    NikonZ72SpiChannel *c = opaque;
    unsigned bits = ((c->regs[0x10 / 4] >> 8) & 31) + 1;
    uint16_t value = bits >= 16 ? UINT16_MAX : (1u << bits) - 1;
    if (spi_attached(c) && c->tx_count) {
        NikonZ72Spi *s = c->owner;
        unsigned step = s->peer_bits;
        unsigned shift = s->low_byte_first ? s->shifted[c->index] :
                         bits - step - s->shifted[c->index];
        unsigned mask = step == 16 ? 0xffff : 0xff;
        uint32_t response = ssi_transfer(s->buses[c->index], (c->tx[0] >> shift) & mask);
        s->receiving[c->index] |= (response & mask) << shift;
        s->shifted[c->index] += step;
        if (s->shifted[c->index] == bits) {
            unsigned slot = (c->rx_head + c->rx_count++) % SPI_DEPTH;
            c->rx[slot] = s->receiving[c->index];
            s->receiving[c->index] = s->shifted[c->index] = 0;
            memmove(c->tx, c->tx + 1, (--c->tx_count) * sizeof(c->tx[0]));
        }
        if (c->tx_count) {
            timer_mod(c->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + s->word_delay_ns);
        } else {
            c->pending |= 3;
        }
        if (c->rx_count >= MAX(1, c->regs[0x4c / 4] & 0xff)) {
            c->pending |= 4;
        }
        spi_irq(c);
        return;
    }
    for (unsigned i = 0; i < c->tx_count; i++) {
        unsigned slot = (c->rx_head + c->rx_count++) % SPI_DEPTH;
        c->rx[slot] = value;
    }
    c->tx_count = 0;
    c->pending |= 3;
    unsigned threshold = c->regs[0x4c / 4] & 0xff;
    if (c->rx_count >= MAX(1, threshold)) {
        c->pending |= 4;
    }
    spi_irq(c);
}

static bool spi_register(hwaddr offset, unsigned size)
{
    return size == 4 && !(offset & 3) && offset <= 0x64 &&
           offset != 0x2c && offset != 0x30 && offset != 0x40 &&
           offset != 0x44 && offset != 0x50 && offset != 0x54 &&
           offset != 0x58 && offset != 0x5c;
}

static MemTxResult spi_read(void *opaque, hwaddr offset, uint64_t *value,
                           unsigned size, MemTxAttrs attrs)
{
    NikonZ72Spi *s = opaque;
    NikonZ72SpiChannel *c = &s->channel[offset / 0x100];
    offset %= 0x100;
    if (!s->enabled || !spi_register(offset, size) || offset == 0) {
        return MEMTX_ERROR;
    }
    switch (offset) {
    case 4:
        if (!c->rx_count) {
            return MEMTX_ERROR;
        }
        *value = c->rx[c->rx_head];
        c->rx_head = (c->rx_head + 1) % SPI_DEPTH;
        if (!--c->rx_count) {
            c->pending &= ~4u;
        }
        spi_irq(c);
        break;
    case 0x14:
        *value = (!c->rx_count ? 0x20 : 0) | (!c->tx_count ? 4 : 0) |
                 (c->tx_count + c->rx_count == SPI_DEPTH ? 0x10 : 0);
        break;
    case 0x24: *value = c->pending; break;
    case 0x48: *value = SPI_DEPTH; break;
    default: *value = c->regs[offset / 4]; break;
    }
    return MEMTX_OK;
}

static MemTxResult spi_write(void *opaque, hwaddr offset, uint64_t value,
                            unsigned size, MemTxAttrs attrs)
{
    NikonZ72Spi *s = opaque;
    NikonZ72SpiChannel *c = &s->channel[offset / 0x100];
    offset %= 0x100;
    if (!s->enabled || !spi_register(offset, size) || offset == 4 ||
        offset == 0x14 || offset == 0x24 || offset == 0x48) {
        return MEMTX_ERROR;
    }
    if (offset == 0) {
        unsigned bits = ((c->regs[0x10 / 4] >> 8) & 31) + 1;
        bool attached = spi_attached(c);
        if (!(c->regs[0x3c / 4] & 1) || value > UINT16_MAX ||
            c->tx_count + c->rx_count == SPI_DEPTH ||
            (attached && ((bits != 8 && bits != 16) || bits < s->peer_bits))) {
            return MEMTX_ERROR;
        }
        c->tx[c->tx_count++] = value;
        c->pending &= ~3u;
        if (!attached || c->tx_count == 1) {
            timer_mod(c->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                      (attached ? s->word_delay_ns : 100000));
        }
    } else if (offset == 0x28) {
        c->pending &= ~value;
    } else {
        if (offset == 0x10 && c->tx_count && spi_attached(c)) {
            return MEMTX_ERROR;
        }
        c->regs[offset / 4] = value;
        if ((offset == 0x3c && !(value & 1)) || offset == 0x60) {
            timer_del(c->timer);
            c->tx_count = c->rx_count = c->rx_head = c->pending = 0;
            s->shifted[c->index] = s->receiving[c->index] = 0;
        }
        if (offset == 0x3c && (value & 1) && !spi_attached(c)) {
            timer_mod(c->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 100000);
        }
    }
    spi_irq(c);
    return MEMTX_OK;
}

static const MemoryRegionOps spi_ops = {
    .read_with_attrs = spi_read,
    .write_with_attrs = spi_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 4 },
    .impl = { .min_access_size = 1, .max_access_size = 4 },
};

static void spi_reset(Object *obj, ResetType type)
{
    NikonZ72Spi *s = NIKON_Z72_SPI(obj);
    for (unsigned i = 0; i < SPI_CHANNELS; i++) {
        NikonZ72SpiChannel *c = &s->channel[i];
        timer_del(c->timer);
        memset(c->regs, 0, sizeof(c->regs));
        memset(c->tx, 0, sizeof(c->tx));
        memset(c->rx, 0, sizeof(c->rx));
        c->tx_count = c->rx_count = c->rx_head = c->pending = 0;
        s->shifted[i] = s->receiving[i] = 0;
        spi_irq(c);
    }
}

static int spi_post_load(void *opaque, int version_id)
{
    NikonZ72Spi *s = opaque;
    if (version_id < 2) {
        memset(s->shifted, 0, sizeof(s->shifted));
        memset(s->receiving, 0, sizeof(s->receiving));
    }
    for (unsigned i = 0; i < SPI_CHANNELS; i++) {
        NikonZ72SpiChannel *c = &s->channel[i];
        if (c->tx_count + (uint64_t)c->rx_count > SPI_DEPTH ||
            c->rx_head >= SPI_DEPTH || (s->shifted[i] != 0 &&
            (s->shifted[i] != 8 || !c->tx_count || s->peer_bits != 8 ||
             ((c->regs[0x10 / 4] >> 8) & 31) != 15))) {
            return -EINVAL;
        }
        spi_irq(c);
    }
    return 0;
}

static const VMStateDescription spi_channel_state = {
    .name = TYPE_NIKON_Z72_SPI "-channel",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT32_ARRAY(regs, NikonZ72SpiChannel, 64),
        VMSTATE_UINT16_ARRAY(tx, NikonZ72SpiChannel, SPI_DEPTH),
        VMSTATE_UINT16_ARRAY(rx, NikonZ72SpiChannel, SPI_DEPTH),
        VMSTATE_UINT32(tx_count, NikonZ72SpiChannel),
        VMSTATE_UINT32(rx_count, NikonZ72SpiChannel),
        VMSTATE_UINT32(rx_head, NikonZ72SpiChannel),
        VMSTATE_UINT32(pending, NikonZ72SpiChannel),
        VMSTATE_TIMER_PTR(timer, NikonZ72SpiChannel),
        VMSTATE_END_OF_LIST()
    },
};

static const VMStateDescription spi_state = {
    .name = TYPE_NIKON_Z72_SPI,
    .version_id = 2,
    .minimum_version_id = 1,
    .post_load = spi_post_load,
    .fields = (const VMStateField[]) {
        VMSTATE_STRUCT_ARRAY(channel, NikonZ72Spi, SPI_CHANNELS, 0,
                             spi_channel_state, NikonZ72SpiChannel),
        VMSTATE_UINT8_ARRAY_V(shifted, NikonZ72Spi, SPI_CHANNELS, 2),
        VMSTATE_UINT16_ARRAY_V(receiving, NikonZ72Spi, SPI_CHANNELS, 2),
        VMSTATE_END_OF_LIST()
    },
};

static const Property spi_properties[] = {
    DEFINE_PROP_BOOL("enabled", NikonZ72Spi, enabled, true),
    DEFINE_PROP_STRING("bus-name", NikonZ72Spi, bus_name),
    DEFINE_PROP_UINT8("peer-word-bits", NikonZ72Spi, peer_bits, 8),
    DEFINE_PROP_BOOL("peer-low-byte-first", NikonZ72Spi, low_byte_first, false),
    DEFINE_PROP_UINT64("peer-word-delay-ns", NikonZ72Spi, word_delay_ns, 2000),
};

static void spi_realize(DeviceState *dev, Error **errp)
{
    NikonZ72Spi *s = NIKON_Z72_SPI(dev);
    if ((s->peer_bits != 8 && s->peer_bits != 16) ||
        !s->word_delay_ns || s->word_delay_ns > 1000000000) {
        error_setg(errp, "Unsupported serial peer width or pacing interval");
        return;
    }
    for (unsigned i = 0; i < SPI_CHANNELS; i++) {
        g_autofree char *name = g_strdup_printf("%s%u", s->bus_name ? s->bus_name : "engine-spi", i);
        s->buses[i] = ssi_create_bus(dev, name);
    }
}

static void spi_init(Object *obj)
{
    NikonZ72Spi *s = NIKON_Z72_SPI(obj);
    memory_region_init_io(&s->iomem, obj, &spi_ops, s, TYPE_NIKON_Z72_SPI,
                          SPI_CHANNELS * 0x100);
    sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->iomem);
    for (unsigned i = 0; i < SPI_CHANNELS; i++) {
        NikonZ72SpiChannel *c = &s->channel[i];
        c->owner = s;
        c->index = i;
        c->timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, spi_complete, c);
        sysbus_init_irq(SYS_BUS_DEVICE(s), &s->irq[i * 2]);
        sysbus_init_irq(SYS_BUS_DEVICE(s), &s->irq[i * 2 + 1]);
    }
}

static void spi_finalize(Object *obj)
{
    NikonZ72Spi *s = NIKON_Z72_SPI(obj);
    for (unsigned i = 0; i < SPI_CHANNELS; i++) {
        timer_free(s->channel[i].timer);
    }
}

static void spi_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->vmsd = &spi_state;
    dc->realize = spi_realize;
    dc->desc = "Z72 bounded serial bus with explicit peers";
    device_class_set_props(dc, spi_properties);
    RESETTABLE_CLASS(klass)->phases.hold = spi_reset;
}

static void spi_register_types(void)
{
    static const TypeInfo info = {
        .name = TYPE_NIKON_Z72_SPI,
        .parent = TYPE_SYS_BUS_DEVICE,
        .instance_size = sizeof(NikonZ72Spi),
        .instance_init = spi_init,
        .instance_finalize = spi_finalize,
        .class_init = spi_class_init,
    };
    type_register_static(&info);
}
type_init(spi_register_types)
