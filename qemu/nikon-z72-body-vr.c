/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "qemu/osdep.h"
#include "hw/qdev-properties.h"
#include "hw/ssi/ssi.h"
#include "migration/vmstate.h"
#include "qapi/error.h"
#include "qemu/bswap.h"
#include "qemu/module.h"
#include "qemu/timer.h"

#define TYPE_Z72_BODY_VR "nikon-z72-body-vr"
OBJECT_DECLARE_SIMPLE_TYPE(Z72BodyVR, Z72_BODY_VR)
#define VR_FRAME 276
#define VR_MEMORY 0x4000

struct Z72BodyVR {
    SSIPeripheral parent_obj;
    uint8_t memory[VR_MEMORY], configuration[256];
    uint8_t input[VR_FRAME], output[VR_FRAME], read_reply[VR_FRAME];
    uint8_t job[VR_FRAME];
    unsigned offset, reply_size;
    uint8_t status;
    bool selected, overflow, busy, reply_pending, sending_reply;
    uint64_t frames, completed, rejected, truncated;
    uint64_t reads, writes, configuration_generation;
    uint64_t work_delay_ns;
    QEMUTimer *work_timer;
};

/* Only the communication memory and F1 configuration window are modeled.
 * There is no connected gyro or actuator, so telemetry and its ready bits
 * stay absent. These zero-initialized bytes are virtual RAM, not calibration. */
static void vr_normal_reply(Z72BodyVR *s)
{
    memset(s->output, 0, sizeof(s->output));
    s->output[1] = s->status;
    stw_le_p(s->output + 2, 4);
}

static void vr_reject(Z72BodyVR *s)
{
    s->rejected++;
    s->status |= 2;
}

static bool vr_range(uint16_t address, unsigned size)
{
    return size <= 256 && address <= VR_MEMORY &&
           size <= VR_MEMORY - address;
}

static void vr_work_done(void *opaque)
{
    Z72BodyVR *s = opaque;
    uint8_t *p = s->job;
    unsigned size = lduw_le_p(p + 2) - 16;
    uint16_t address = lduw_le_p(p + 6);
    uint16_t key = lduw_le_p(p + 4);

    s->busy = false;
    s->status &= ~1;
    if (p[0] == 0xf1) {
        uint8_t checksum = 0;
        for (unsigned i = 4; i < size + 20; i++) {
            checksum += p[i];
        }
        if (checksum) {
            vr_reject(s);
            return;
        }
        if (p[1] == 4) {
            memcpy(s->configuration, p + 20, size);
            s->configuration_generation++;
        } else {
            memcpy(s->memory + address, p + 20, size);
            s->writes++;
        }
    } else {
        uint8_t checksum = 0;
        memset(s->read_reply, 0, sizeof(s->read_reply));
        stw_le_p(s->read_reply + 2, size + 16);
        stw_le_p(s->read_reply + 4, key);
        stw_le_p(s->read_reply + 6, address);
        memcpy(s->read_reply + 20, s->memory + address, size);
        for (unsigned i = 4; i < 8; i++) {
            checksum -= s->read_reply[i];
        }
        for (unsigned i = 20; i < size + 20; i++) {
            checksum -= s->read_reply[i];
        }
        s->read_reply[8] = checksum;
        s->read_reply[1] = s->status;
        s->reply_size = size + 20;
        s->reply_pending = true;
        s->reads++;
    }
    s->completed++;
}

static void vr_command(Z72BodyVR *s)
{
    uint8_t *p = s->input;
    unsigned declared = lduw_le_p(p + 2);
    uint16_t key = lduw_le_p(p + 4);
    uint16_t address = lduw_le_p(p + 6);

    if (s->overflow || s->offset < 152) {
        s->truncated++;
        vr_reject(s);
        return;
    }
    /* D0 flag 0 and F2 flag 1 poll the previously prepared transmit buffer.
     * A poll does not complete a job or fabricate a control-queue response. */
    if ((p[0] == 0xd0 && p[1] == 0) ||
        (p[0] == 0xf2 && p[1] == 1)) {
        s->completed++;
        return;
    }
    if (s->busy || s->reply_pending) {
        vr_reject(s);
        return;
    }
    unsigned size = declared - 16;
    bool write = p[0] == 0xf1 && p[1] == 0;
    bool read = p[0] == 0xf2 && p[1] == 0;
    bool configure = p[0] == 0xf1 && p[1] == 4;

    if ((!write && !read && !configure) ||
        (!configure && key != 0xaa55)) {
        /* Descriptor keys, resident operations, updates and physical
         * stabilization commands require endpoints that are not present. */
        vr_reject(s);
        return;
    }
    /* The normal command family's argument is not generally a byte count.
     * F1/F2 memory requests alone use the sixteen-byte overhead. F2 carries
     * a read range, not incoming payload of that size. */
    if (declared < 16 || declared > VR_FRAME - 4 ||
        (!read && s->offset < declared + 4)) {
        s->truncated++;
        vr_reject(s);
        return;
    }
    /* F2 addresses from 0x3000 select a resident-dependent flash view in
     * the original controller. Do not alias that absent view to RAM. */
    if ((!configure && !vr_range(address, size)) ||
        (read && (address >= 0x3000 || size > 0x3000 - address)) ||
        (configure && size > sizeof(s->configuration))) {
        vr_reject(s);
        return;
    }
    memcpy(s->job, p, s->offset);
    s->busy = true;
    s->status = (s->status & ~2) | 1;
    if (configure) {
        s->status |= 0x80;
    }
    timer_mod(s->work_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
              s->work_delay_ns);
}

static int vr_select(SSIPeripheral *dev, bool high)
{
    Z72BodyVR *s = Z72_BODY_VR(dev);

    if (!high) {
        s->selected = true;
        s->offset = 0;
        s->overflow = false;
        memset(s->input, 0, sizeof(s->input));
        s->sending_reply = s->reply_pending;
        if (s->sending_reply) {
            memcpy(s->output, s->read_reply, sizeof(s->output));
        } else {
            vr_normal_reply(s);
        }
    } else if (s->selected) {
        s->selected = false;
        s->frames++;
        if (s->sending_reply && s->offset >= s->reply_size) {
            s->reply_pending = false;
        }
        vr_command(s);
    }
    return 0;
}

static uint32_t vr_transfer(SSIPeripheral *dev, uint32_t value)
{
    Z72BodyVR *s = Z72_BODY_VR(dev);

    if (!s->selected || value > UINT8_MAX) {
        return 0;
    }
    if (s->offset == sizeof(s->input)) {
        s->overflow = true;
        return 0;
    }
    unsigned offset = s->offset++;
    s->input[offset] = value;
    return s->output[offset];
}

static void vr_reset(DeviceState *dev)
{
    Z72BodyVR *s = Z72_BODY_VR(dev);

    timer_del(s->work_timer);
    memset(s->memory, 0, sizeof(s->memory));
    memset(s->configuration, 0, sizeof(s->configuration));
    s->offset = s->reply_size = 0;
    s->status = 0;
    s->selected = s->overflow = s->busy = false;
    s->reply_pending = s->sending_reply = false;
    s->frames = s->completed = s->rejected = s->truncated = 0;
    s->reads = s->writes = s->configuration_generation = 0;
    SSI_PERIPHERAL(s)->cs = true;
    vr_normal_reply(s);
}

static void vr_realize(SSIPeripheral *dev, Error **errp)
{
    Z72BodyVR *s = Z72_BODY_VR(dev);

    if (!s->work_delay_ns || s->work_delay_ns > NANOSECONDS_PER_SECOND) {
        error_setg(errp, "Unsupported body VR functional work interval");
    }
}

static char *vr_runtime(Object *obj, Error **errp)
{
    Z72BodyVR *s = Z72_BODY_VR(obj);

    return g_strdup_printf("selected=%u offset=%u busy=%u status=%02x "
        "reply-pending=%u reply-size=%u command=%02x:%02x "
        "sensor-connected=0 actuator-connected=0",
        s->selected, s->offset, s->busy, s->status,
        s->reply_pending, s->reply_size, s->input[0], s->input[1]);
}

static void vr_init(Object *obj)
{
    Z72BodyVR *s = Z72_BODY_VR(obj);

    s->work_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, vr_work_done, s);
    object_property_add_uint64_ptr(obj, "frames", &s->frames, OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "completed", &s->completed, OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "rejected", &s->rejected, OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "truncated", &s->truncated, OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "reads", &s->reads, OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "writes", &s->writes, OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "configuration-generation",
                                   &s->configuration_generation, OBJ_PROP_FLAG_READ);
    object_property_add_str(obj, "runtime", vr_runtime, NULL);
}

static void vr_finalize(Object *obj)
{
    timer_free(Z72_BODY_VR(obj)->work_timer);
}

static const Property vr_properties[] = {
    DEFINE_PROP_UINT64("work-delay-ns", Z72BodyVR, work_delay_ns, 200000),
};

static const VMStateDescription vr_vmstate = {
    .name = TYPE_Z72_BODY_VR, .unmigratable = true,
};

static void vr_class_init(ObjectClass *oc, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    SSIPeripheralClass *sc = SSI_PERIPHERAL_CLASS(oc);

    dc->vmsd = &vr_vmstate;
    dc->user_creatable = false;
    device_class_set_props(dc, vr_properties);
    device_class_set_legacy_reset(dc, vr_reset);
    sc->realize = vr_realize;
    sc->transfer = vr_transfer;
    sc->set_cs = vr_select;
    sc->cs_polarity = SSI_CS_LOW;
}

static const TypeInfo vr_type = {
    .name = TYPE_Z72_BODY_VR,
    .parent = TYPE_SSI_PERIPHERAL,
    .instance_size = sizeof(Z72BodyVR),
    .instance_init = vr_init,
    .instance_finalize = vr_finalize,
    .class_init = vr_class_init,
};

static void vr_register(void)
{
    type_register_static(&vr_type);
}
type_init(vr_register)
