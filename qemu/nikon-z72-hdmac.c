/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Engine-local eight-channel DMA with peripheral demand and real bus accesses. */
#include "qemu/osdep.h"
#include "qemu/timer.h"
#include "qemu/main-loop.h"
#include "qemu/log.h"
#include "migration/vmstate.h"
#include "hw/irq.h"
#include "hw/sysbus.h"
#include "hw/qdev-clock.h"
#include "hw/qdev-properties.h"
#include "system/address-spaces.h"
#include "system/dma.h"
#include "qapi/error.h"

#define HDMAC_DE (1U << 31)
#define HDMAC_EB (1U << 31)
#define HDMAC_ST (1U << 29)
#define HDMAC_PB (1U << 30)
#define HDMAC_DH (1U << 24)
#define HDMAC_SS (7U << 16)
#define HDMAC_CI (1U << 19)
#define HDMAC_EI (1U << 20)
#define HDMAC_RD (1U << 21)
#define HDMAC_RS (1U << 22)
#define HDMAC_RC (1U << 23)
#define HDMAC_COUNT 0xfffffU
#define TYPE_Z72_HDMAC "nikon-z72-hdmac"
OBJECT_DECLARE_SIMPLE_TYPE(Z72HDMAC, Z72_HDMAC)

typedef struct Z72DMAChannel {
    Z72HDMAC *owner;
    uint32_t ca, cb, source, destination;
    QEMUTimer *timer;
    qemu_irq irq;
    bool running;
    int64_t ready_at;
    int64_t wait_ns;
    uint64_t generation;
    uint32_t remaining;
    uint32_t initial_count, initial_source, initial_destination;
} Z72DMAChannel;

typedef struct Z72DMAReadonlyRange {
    Int128 start;
    Int128 end;
} Z72DMAReadonlyRange;

struct Z72HDMAC {
    SysBusDevice parent_obj;
    MemoryRegion regs;
    MemoryRegion *memory;
    AddressSpace *dma;
    MemoryListener memory_listener;
    GArray *readonly;
    Clock *clock;
    QEMUBH *demand_bh;
    uint32_t bank;
    uint32_t control;
    unsigned cursor;
    Z72DMAChannel channel[8];
    bool reported_error;
    bool servicing;
    bool request[32];
};

static bool z72_hdmac_requested(Z72DMAChannel *c)
{
    unsigned selection = (c->ca >> 24) & 31;

    return !(c->ca & HDMAC_PB) && !(c->owner->control & HDMAC_DH) &&
           (!selection || c->owner->request[selection]);
}

static void z72_hdmac_service(void *opaque);

static void z72_hdmac_update(Z72DMAChannel *c)
{
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);

    if (!c->running) {
        return;
    }
    if ((c->ca >> 24) & 31) {
        z72_hdmac_service(c->owner);
        return;
    }
    if (!z72_hdmac_requested(c)) {
        if (timer_pending(c->timer)) {
            c->wait_ns = MAX(1, c->ready_at - now);
            timer_del(c->timer);
        }
    } else if (!timer_pending(c->timer)) {
        c->ready_at = now + MAX(1, c->wait_ns);
        timer_mod(c->timer, c->ready_at);
    }
}

static void z72_hdmac_irq(Z72DMAChannel *c)
{
    unsigned status = (c->cb >> 16) & 7;

    qemu_set_irq(c->irq, status == 5 ? !!(c->cb & HDMAC_CI) :
                 (status >= 1 && status <= 4 && (c->cb & HDMAC_EI)));
}

static void z72_hdmac_finish(Z72DMAChannel *c, unsigned status)
{
    timer_del(c->timer);
    c->generation++;
    c->running = false;
    c->ca &= ~HDMAC_EB;
    c->cb = (c->cb & ~HDMAC_SS) | (status << 16);
    z72_hdmac_irq(c);
}

static MemTxResult z72_hdmac_write_memory(Z72HDMAC *s,
                                           hwaddr address, const void *data,
                                           unsigned width)
{
    hwaddr current = address;
    unsigned remaining = width;
    RCU_READ_LOCK_GUARD();

    /* The listener reports the selected flat view's effective permissions,
     * including readonly aliases/containers. Translation exposes only a leaf.
     * Do not use memory_region_find(): it can ascend into another root's AS. */
    for (unsigned i = 0; i < s->readonly->len; i++) {
        Z72DMAReadonlyRange *range = &g_array_index(
            s->readonly, Z72DMAReadonlyRange, i);

        if (int128_lt(int128_make64(address), range->end) &&
            int128_lt(range->start, int128_make64(address + width))) {
            return MEMTX_ERROR;
        }
    }

    /* QEMU may intentionally ignore ROM writes. DMA must report their failure,
     * while actual MMIO sinks retain their causal device transactions.
     */
    while (remaining) {
        hwaddr offset, length = remaining;
        MemoryRegion *mr = address_space_translate(s->dma, current, &offset,
                                                  &length, true,
                                                  MEMTXATTRS_UNSPECIFIED);

        if (memory_region_is_rom(mr) || memory_region_is_romd(mr) || !length) {
            return MEMTX_ERROR;
        }
        /* Translation bounds RAM spans. MMIO lengths need not be bounded by
         * their mapping, so inspect every covered byte without bus accesses.
         * The actual write below still keeps the original complete beat width.
         */
        if (!memory_region_is_ram(mr)) {
            length = 1;
        }
        current += length;
        remaining -= length;
    }
    return dma_memory_write(s->dma, address, data, width,
                            MEMTXATTRS_UNSPECIFIED);
}

static void z72_hdmac_execute(Z72DMAChannel *c, uint32_t beats)
{
    Z72HDMAC *s = c->owner;
    unsigned width = 1U << ((c->cb >> 26) & 3);
    bool fixed_source = c->cb & (1U << 25);
    bool fixed_destination = c->cb & (1U << 24);
    uint64_t generation = c->generation;
    uint8_t data[4];
    unsigned i;

    timer_del(c->timer);
    c->wait_ns = MAX(1, clock_ticks_to_ns(s->clock, 1));

    for (i = 0; i < beats; i++) {
        MemTxResult result;

        if ((uint64_t)c->source + width > 1ULL << 32 ||
            (uint64_t)c->destination + width > 1ULL << 32) {
            z72_hdmac_finish(c, 1);
            return;
        }
        result = dma_memory_read(s->dma, c->source, data, width,
                                  MEMTXATTRS_UNSPECIFIED);
        if (!c->running || c->generation != generation) {
            return;
        }
        if (result != MEMTX_OK) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "z72.hdmac: bank%u source bus error "
                          "at 0x%08x; SS3\n", s->bank, c->source);
            z72_hdmac_finish(c, 3);
            return;
        }
        result = z72_hdmac_write_memory(s, c->destination, data, width);
        if (!c->running || c->generation != generation) {
            return;
        }
        if (result != MEMTX_OK) {
            qemu_log_mask(LOG_GUEST_ERROR, "z72.hdmac: bank%u destination bus "
                          "error at 0x%08x; SS4\n", s->bank, c->destination);
            z72_hdmac_finish(c, 4);
            return;
        }
        if (!fixed_source) {
            if ((uint64_t)c->source + width == 1ULL << 32 && c->remaining > 1) {
                z72_hdmac_finish(c, 1);
                return;
            }
            c->source += width;
        }
        if (!fixed_destination) {
            if ((uint64_t)c->destination + width == 1ULL << 32 &&
                c->remaining > 1) {
                z72_hdmac_finish(c, 1);
                return;
            }
            c->destination += width;
        }
        c->remaining--;
        /* PB/DH/DREQ can change through a genuine reentrant bus operation.
         * Commit the accepted beat once, then suspend before the next one. */
        if (c->remaining && !z72_hdmac_requested(c)) {
            return;
        }
    }
    if (c->remaining) {
        return;
    }
    /* Matching IP reloads selected fields only after normal completion.
     * EB still clears: reload does not create another peripheral request.
     * Non-reload end counters remain a functional readback convention. */
    c->ca = (c->ca & ~HDMAC_COUNT) |
            ((c->cb & HDMAC_RC) ? c->initial_count : 0);
    if (c->cb & HDMAC_RS) {
        c->source = c->initial_source;
    }
    if (c->cb & HDMAC_RD) {
        c->destination = c->initial_destination;
    }
    z72_hdmac_finish(c, 5);
}

static bool z72_hdmac_endpoint_busy(Z72DMAChannel *c)
{
    hwaddr addresses[] = { c->source, c->destination };
    unsigned width = 1U << ((c->cb >> 26) & 3);
    RCU_READ_LOCK_GUARD();

    for (unsigned i = 0; i < ARRAY_SIZE(addresses); i++) {
        for (unsigned byte = 0; byte < width; byte++) {
            hwaddr offset, length = 1;
            MemoryRegion *mr = address_space_translate(c->owner->dma,
                addresses[i] + byte, &offset, &length, i == 1,
                MEMTXATTRS_UNSPECIFIED);

            if (mr->dev && !mr->disable_reentrancy_guard && !mr->ram_device &&
                !mr->ram && !mr->rom_device && !mr->readonly &&
                mr->dev->mem_reentrancy_guard.engaged_in_io) {
                return true;
            }
        }
    }
    return false;
}

/* A DREQ is a real accepted FIFO opportunity, not another host timer delay. */
static void z72_hdmac_service(void *opaque)
{
    Z72HDMAC *s = opaque;

    if (s->servicing) {
        return;
    }
    if (DEVICE(s)->mem_reentrancy_guard.engaged_in_io) {
        qemu_bh_schedule(s->demand_bh);
        return;
    }
    qemu_bh_cancel(s->demand_bh);
    s->servicing = true;
    for (;;) {
        unsigned start = (s->control & (1U << 28)) ? s->cursor : 0;
        Z72DMAChannel *selected = NULL;

        for (unsigned i = 0; i < 8; i++) {
            unsigned index = (start + i) % 8;
            Z72DMAChannel *c = &s->channel[index];

            if (c->running && ((c->ca >> 24) & 31) &&
                z72_hdmac_requested(c)) {
                selected = c;
                s->cursor = (index + 1) % 8;
                break;
            }
        }
        if (!selected) {
            break;
        }
        if (z72_hdmac_endpoint_busy(selected)) {
            /* Finish the producer's MMIO before accessing its FIFO again. */
            qemu_bh_schedule(s->demand_bh);
            break;
        }
        /* Reentrant bus operations update requests; re-arbitrate each beat. */
        z72_hdmac_execute(selected, 1);
    }
    s->servicing = false;
}

static void z72_hdmac_transfer(void *opaque)
{
    Z72DMAChannel *trigger = opaque;
    Z72HDMAC *s = trigger->owner;
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    unsigned start = (s->control & (1U << 28)) ? s->cursor : 0;

    for (unsigned i = 0; i < 8; i++) {
        unsigned index = (start + i) % 8;
        Z72DMAChannel *c = &s->channel[index];

        if (c->running && !((c->ca >> 24) & 31) &&
            c->ready_at <= now && z72_hdmac_requested(c)) {
            s->cursor = (index + 1) % 8;
            if (c != trigger && trigger->running) {
                timer_mod(trigger->timer, now);
            }
            z72_hdmac_execute(c, c->remaining);
            if (c->running) {
                z72_hdmac_update(c);
            }
            return;
        }
    }
}

static bool z72_hdmac_start_supported(uint32_t ca, uint32_t cb,
                                       uint32_t source, uint32_t destination)
{
    unsigned beat = (ca >> 20) & 15;
    unsigned width = (cb >> 26) & 3;

    /* No wrapped bursts, transfer transforms or protection transactions. */
    return width < 3 &&
           (beat == 0 || beat == 8 || beat == 9 || beat == 11 ||
            beat == 13 || beat == 15) &&
           !(cb & 0xc000ff00U) && ((cb >> 28) & 3) < 3 &&
           !(source & ((1U << width) - 1)) &&
           !(destination & ((1U << width) - 1));
}

static void z72_hdmac_schedule(Z72DMAChannel *c)
{
    Z72HDMAC *s = c->owner;
    uint32_t beats = (((c->ca >> 16) & 15) + 1) * ((c->ca & 0xffff) + 1);

    unsigned selection = (c->ca >> 24) & 31;

    if (c->running || !(s->control & HDMAC_DE) || !(c->ca & HDMAC_EB) ||
        (!selection && !(c->ca & HDMAC_ST))) {
        return;
    }
    c->running = true;
    c->generation++;
    c->remaining = beats;
    c->initial_count = c->ca & HDMAC_COUNT;
    c->initial_source = c->source;
    c->initial_destination = c->destination;
    c->wait_ns = MAX(1, clock_ticks_to_ns(s->clock, selection ? 1 : beats));
    z72_hdmac_update(c);
}

static void z72_hdmac_request(void *opaque, int selection, int level)
{
    Z72HDMAC *s = opaque;

    s->request[selection] = level;
    if (level) {
        /* Finish delivery to every bank before a consumer changes DREQ.
         * Otherwise a nested falling edge can precede the outer rising
         * edge at another bank and leave that bank seeing stale demand. */
        qemu_bh_schedule(s->demand_bh);
    }
}

static MemTxResult z72_hdmac_error(Z72HDMAC *s, hwaddr offset,
                                   unsigned size, bool write, uint64_t value)
{
    if (!s->reported_error) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "z72 DMA: unsupported %s offset=%" HWADDR_PRIx " size=%u value=%" PRIx64 "\n",
                      write ? "write" : "read", offset, size, value);
        s->reported_error = true;
    }
    return MEMTX_ERROR;
}

static MemTxResult z72_hdmac_read(void *opaque, hwaddr offset, uint64_t *value,
                                  unsigned size, MemTxAttrs attrs)
{
    Z72HDMAC *s = opaque;
    Z72DMAChannel *c;

    *value = 0;
    if (size != 4 || (offset & 3) || (offset && offset < 0x10) ||
        offset >= 0x90) {
        return z72_hdmac_error(s, offset, size, false, 0);
    }
    if (!offset) {
        *value = s->control;
        return MEMTX_OK;
    }
    c = &s->channel[(offset - 0x10) >> 4];
    switch (offset & 15) {
    case 0:
        *value = c->ca;
        break;
    case 4:
        *value = c->cb;
        break;
    case 8:
        *value = c->source;
        break;
    case 12:
        *value = c->destination;
        break;
    }
    return MEMTX_OK;
}

static MemTxResult z72_hdmac_write(void *opaque, hwaddr offset, uint64_t value,
                                   unsigned size, MemTxAttrs attrs)
{
    Z72HDMAC *s = opaque;
    Z72DMAChannel *c;
    uint32_t old;
    unsigned i;

    if (size != 4 || (offset & 3) || (offset && offset < 0x10) ||
        offset >= 0x90) {
        return z72_hdmac_error(s, offset, size, true, value);
    }
    if (!offset) {
        /* Only the halt/resume encodings 1/0 are supported. */
        if (value & ~0x91000000U) {
            return z72_hdmac_error(s, offset, size, true, value);
        }
        /* Preflight every armed request before changing DE or any timer. */
        if (value & HDMAC_DE) {
            for (i = 0; i < 8; i++) {
                c = &s->channel[i];
                if ((c->ca & HDMAC_EB) &&
                    !z72_hdmac_start_supported(c->ca, c->cb,
                                                c->source, c->destination)) {
                    return z72_hdmac_error(s, offset, size, true, value);
                }
            }
        }
        s->control = value;
        for (i = 0; i < 8; i++) {
            c = &s->channel[i];
            if (!(value & HDMAC_DE) && c->running) {
                z72_hdmac_finish(c, 2);
            } else {
                z72_hdmac_schedule(c);
                z72_hdmac_update(c);
            }
        }
        return MEMTX_OK;
    }
    c = &s->channel[(offset - 0x10) >> 4];
    switch (offset & 15) {
    case 0:
        old = c->ca;
        if (c->running && ((value ^ old) & ~(HDMAC_EB | HDMAC_PB))) {
            return z72_hdmac_error(s, offset, size, true, value);
        }
        if ((value & HDMAC_EB) &&
            !z72_hdmac_start_supported(value, c->cb,
                                        c->source, c->destination)) {
            return z72_hdmac_error(s, offset, size, true, value);
        }
        c->ca = value;
        if (!(value & HDMAC_EB) && (old & HDMAC_EB)) {
            z72_hdmac_finish(c, 2);
        } else {
            z72_hdmac_schedule(c);
            z72_hdmac_update(c);
        }
        break;
    case 4:
        if ((value & 0xc000ffffU) || ((value >> 26) & 3) == 3 ||
            ((value >> 28) & 3) == 3 || ((value & HDMAC_SS) &&
                             (value & HDMAC_SS) != (c->cb & HDMAC_SS)) ||
            (c->running &&
             ((value ^ c->cb) & ~(HDMAC_SS | HDMAC_CI | HDMAC_EI)))) {
            return z72_hdmac_error(s, offset, size, true, value);
        }
        if ((c->ca & HDMAC_EB) &&
            !z72_hdmac_start_supported(c->ca, value,
                                        c->source, c->destination)) {
            return z72_hdmac_error(s, offset, size, true, value);
        }
        c->cb = value;
        z72_hdmac_irq(c);
        break;
    case 8:
    case 12:
        if (c->running) {
            return z72_hdmac_error(s, offset, size, true, value);
        }
        if ((c->ca & HDMAC_EB) &&
            !z72_hdmac_start_supported(c->ca, c->cb,
                                        (offset & 15) == 8 ? value : c->source,
                                        (offset & 15) == 12 ? value :
                                                            c->destination)) {
            return z72_hdmac_error(s, offset, size, true, value);
        }
        if ((offset & 15) == 8) {
            c->source = value;
        } else {
            c->destination = value;
        }
        break;
    }
    return MEMTX_OK;
}

static const MemoryRegionOps z72_hdmac_ops = {
    .read_with_attrs = z72_hdmac_read,
    .write_with_attrs = z72_hdmac_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 4, .unaligned = true },
    .impl = { .min_access_size = 1, .max_access_size = 4, .unaligned = true },
};

static void z72_hdmac_reset(DeviceState *dev)
{
    Z72HDMAC *s = Z72_HDMAC(dev);
    unsigned i;

    s->control = 0;
    s->cursor = 0;
    s->reported_error = false;
    qemu_bh_cancel(s->demand_bh);
    clock_update_hz(s->clock, 48000000);
    for (i = 0; i < 8; i++) {
        Z72DMAChannel *c = &s->channel[i];

        timer_del(c->timer);
        c->generation++;
        c->ca = c->cb = c->source = c->destination = 0;
        c->running = false;
        c->remaining = 0;
        c->initial_count = c->initial_source = c->initial_destination = 0;
        c->ready_at = c->wait_ns = 0;
        z72_hdmac_irq(c);
    }
}

static void z72_hdmac_init(Object *obj)
{
    Z72HDMAC *s = Z72_HDMAC(obj);
    unsigned i;

    s->demand_bh = aio_bh_new(qemu_get_aio_context(), z72_hdmac_service, s);
    s->clock = qdev_init_clock_out(DEVICE(obj), "nominal-hdmac-clock");
    qdev_init_gpio_in(DEVICE(obj), z72_hdmac_request, 32);
    memory_region_init_io(&s->regs, obj, &z72_hdmac_ops, s,
                          "z72.hdmac", 0x90);
    sysbus_init_mmio(SYS_BUS_DEVICE(obj), &s->regs);
    for (i = 0; i < 8; i++) {
        s->channel[i].owner = s;
        s->channel[i].timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                           z72_hdmac_transfer, &s->channel[i]);
        sysbus_init_irq(SYS_BUS_DEVICE(obj), &s->channel[i].irq);
    }
}

static void z72_hdmac_finalize(Object *obj)
{
    Z72HDMAC *s = Z72_HDMAC(obj);
    unsigned i;

    qemu_bh_delete(s->demand_bh);
    for (i = 0; i < 8; i++) {
        timer_free(s->channel[i].timer);
    }
}

static char *z72_hdmac_runtime(Object *obj, Error **errp)
{
    Z72HDMAC *s = Z72_HDMAC(obj);
    GString *text = g_string_new(NULL);
    g_string_append_printf(text, "control=%08x clock=%u\n", s->control,
                            clock_get_hz(s->clock));
    for (unsigned i = 0; i < 8; i++) {
        Z72DMAChannel *c = &s->channel[i];
        g_string_append_printf(text,
            "%u ca=%08x cb=%08x source=%08x destination=%08x running=%u "
            "remaining=%u deadline=%" PRId64 "\n", i, c->ca, c->cb,
            c->source, c->destination, c->running, c->remaining, c->ready_at);
    }
    return g_string_free(text, false);
}

static const Property z72_hdmac_properties[] = {
    DEFINE_PROP_UINT32("bank", Z72HDMAC, bank, 0),
    DEFINE_PROP_LINK("memory", Z72HDMAC, memory,
                     TYPE_MEMORY_REGION, MemoryRegion *),
};

static void z72_hdmac_region_add(MemoryListener *listener,
                                   MemoryRegionSection *section)
{
    Z72HDMAC *s = container_of(listener, Z72HDMAC,
                                     memory_listener);

    if (section->readonly) {
        Z72DMAReadonlyRange range = {
            .start = int128_make64(section->offset_within_address_space),
            .end = int128_add(int128_make64(section->offset_within_address_space),
                              section->size),
        };

        g_array_append_val(s->readonly, range);
    }
}

static void z72_hdmac_region_del(MemoryListener *listener,
                                   MemoryRegionSection *section)
{
    Z72HDMAC *s = container_of(listener, Z72HDMAC,
                                     memory_listener);
    Int128 start = int128_make64(section->offset_within_address_space);
    Int128 end = int128_add(start, section->size);

    if (!section->readonly) {
        return;
    }
    for (unsigned i = 0; i < s->readonly->len; i++) {
        Z72DMAReadonlyRange *range = &g_array_index(
            s->readonly, Z72DMAReadonlyRange, i);

        if (int128_eq(range->start, start) && int128_eq(range->end, end)) {
            g_array_remove_index_fast(s->readonly, i);
            return;
        }
    }
    g_assert_not_reached();
}

static void z72_hdmac_realize(DeviceState *dev, Error **errp)
{
    Z72HDMAC *s = Z72_HDMAC(dev);

    if (!s->memory) {
        error_setg(errp, "DMA requires its engine memory root");
        return;
    }
    s->dma = g_new0(AddressSpace, 1);
    address_space_init(s->dma, s->memory,
                       "z72.hdmac");
    s->readonly = g_array_new(false, false, sizeof(Z72DMAReadonlyRange));
    s->memory_listener = (MemoryListener) {
        .name = "z72.hdmac",
        .region_add = z72_hdmac_region_add,
        .region_del = z72_hdmac_region_del,
    };
    memory_listener_register(&s->memory_listener, s->dma);
}

static void z72_hdmac_unrealize(DeviceState *dev)
{
    Z72HDMAC *s = Z72_HDMAC(dev);

    z72_hdmac_reset(dev);
    memory_listener_unregister(&s->memory_listener);
    g_clear_pointer(&s->readonly, g_array_unref);
    address_space_destroy_free(g_steal_pointer(&s->dma));
}
static const VMStateDescription z72_hdmac_vmstate = {
    .name = "nikon-z72-hdmac", .unmigratable = true,
};

static void z72_hdmac_class_init(ObjectClass *oc, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);

    dc->vmsd = &z72_hdmac_vmstate;
    dc->realize = z72_hdmac_realize;
    dc->unrealize = z72_hdmac_unrealize;
    dc->user_creatable = false;
    device_class_set_props(dc, z72_hdmac_properties);
    device_class_set_legacy_reset(dc, z72_hdmac_reset);
    object_class_property_add_str(oc, "runtime", z72_hdmac_runtime, NULL);
}

static const TypeInfo z72_hdmac_type = {
    .name = TYPE_Z72_HDMAC,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(Z72HDMAC),
    .instance_init = z72_hdmac_init,
    .instance_finalize = z72_hdmac_finalize,
    .class_init = z72_hdmac_class_init,
};

static void z72_hdmac_register_types(void)
{
    type_register_static(&z72_hdmac_type);
}
type_init(z72_hdmac_register_types)
