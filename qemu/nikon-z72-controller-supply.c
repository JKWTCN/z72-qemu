/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Experimental two-line supply interface observed during firmware startup. */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "hw/i2c/i2c.h"
#include "hw/irq.h"
#include "hw/qdev-properties.h"
#include "hw/resettable.h"
#include "migration/vmstate.h"
#include "qemu/timer.h"

#define TYPE_Z72_CONTROLLER_SUPPLY "nikon-z72-controller-supply"
OBJECT_DECLARE_SIMPLE_TYPE(Z72ControllerSupply, Z72_CONTROLLER_SUPPLY)

struct Z72ControllerSupply {
    I2CSlave parent_obj;
    char *initial_state;
    uint8_t records[11][16];
    uint8_t controls[9][2];
    uint8_t command, position, checksum;
    uint8_t pending[2];
    bool selecting, request, ack_level;
    QEMUTimer *timer;
    qemu_irq ack;
};

/* Payload sizes exclude the trailing additive checksum. Register 6 is unused. */
static const uint8_t read_sizes[] = { 9, 1, 1, 2, 1, 3, 0, 2, 1, 16, 2 };

static void supply_ack(void *opaque)
{
    Z72ControllerSupply *s = opaque;
    s->ack_level = false;
    qemu_set_irq(s->ack, 0);
}

static void supply_request(void *opaque, int pin, int level)
{
    Z72ControllerSupply *s = opaque;
    if (level) {
        timer_del(s->timer);
        s->ack_level = true;
        qemu_set_irq(s->ack, 1);
    } else if (s->request) {
        /* Laboratory response latency; physical timing remains unconfirmed. */
        timer_mod(s->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 1000);
    }
    s->request = level;
}

static int supply_event(I2CSlave *slave, enum i2c_event event)
{
    Z72ControllerSupply *s = Z72_CONTROLLER_SUPPLY(slave);
    switch (event) {
    case I2C_START_SEND_ASYNC:
        return -1;
    case I2C_START_SEND:
        s->selecting = true;
        s->position = s->checksum = 0;
        break;
    case I2C_START_RECV:
        s->position = s->checksum = 0;
        if (s->command >= ARRAY_SIZE(read_sizes) || !read_sizes[s->command]) {
            return -1;
        }
        break;
    default:
        break;
    }
    return 0;
}

static int supply_send(I2CSlave *slave, uint8_t value)
{
    Z72ControllerSupply *s = Z72_CONTROLLER_SUPPLY(slave);
    if (s->selecting) {
        s->selecting = false;
        s->command = value;
        return (value < ARRAY_SIZE(read_sizes) && read_sizes[value]) ||
               (value >= 0xa0 && value <= 0xa8) ? 0 : -1;
    }
    if (s->command < 0xa0 || s->command > 0xa8) {
        return -1;
    }
    unsigned index = s->command - 0xa0;
    unsigned length = index == 6 ? 2 : 1;
    if (s->position < length) {
        s->pending[s->position++] = value;
        s->checksum += value;
        return 0;
    }
    if (s->position != length || value != s->checksum) {
        s->position = 18;
        return -1;
    }
    s->position++;
    /* Preserve control payloads without assuming undocumented power effects. */
    memcpy(s->controls[index], s->pending, length);
    return 0;
}

static uint8_t supply_recv(I2CSlave *slave)
{
    Z72ControllerSupply *s = Z72_CONTROLLER_SUPPLY(slave);
    if (s->command >= ARRAY_SIZE(read_sizes) || !read_sizes[s->command]) {
        return 0xff;
    }
    unsigned length = read_sizes[s->command];
    if (s->position < length) {
        uint8_t value = s->records[s->command][s->position++];
        s->checksum += value;
        return value;
    }
    if (s->position == length) {
        s->position++;
        return s->checksum;
    }
    return 0xff;
}

static void supply_reset(Object *obj, ResetType type)
{
    Z72ControllerSupply *s = Z72_CONTROLLER_SUPPLY(obj);
    timer_del(s->timer);
    memset(s->controls, 0, sizeof(s->controls));
    memset(s->pending, 0, sizeof(s->pending));
    s->command = 0xff;
    s->position = s->checksum = 0;
    s->selecting = s->request = false;
    s->ack_level = true;
    qemu_set_irq(s->ack, 1);
}

static void supply_realize(DeviceState *dev, Error **errp)
{
    Z72ControllerSupply *s = Z72_CONTROLLER_SUPPLY(dev);
    g_autofree char *data = NULL;
    g_autoptr(GError) error = NULL;
    gsize length;
    if (!s->initial_state ||
        !g_file_get_contents(s->initial_state, &data, &length, &error)) {
        error_setg(errp, "Supply interface requires a readable initial-state file");
        return;
    }
    if (length != sizeof(s->records)) {
        error_setg(errp, "Supply initial-state must contain exactly 176 bytes");
        return;
    }
    memcpy(s->records, data, length);
}

static int supply_post_load(void *opaque, int version)
{
    Z72ControllerSupply *s = opaque;
    if (s->position > 18) {
        return -EINVAL;
    }
    qemu_set_irq(s->ack, s->ack_level);
    return 0;
}

static const VMStateDescription supply_state = {
    .name = TYPE_Z72_CONTROLLER_SUPPLY,
    .version_id = 1,
    .minimum_version_id = 1,
    .post_load = supply_post_load,
    .fields = (const VMStateField[]) {
        VMSTATE_I2C_SLAVE(parent_obj, Z72ControllerSupply),
        VMSTATE_UINT8_2DARRAY(records, Z72ControllerSupply, 11, 16),
        VMSTATE_UINT8_2DARRAY(controls, Z72ControllerSupply, 9, 2),
        VMSTATE_UINT8_ARRAY(pending, Z72ControllerSupply, 2),
        VMSTATE_UINT8(command, Z72ControllerSupply),
        VMSTATE_UINT8(position, Z72ControllerSupply),
        VMSTATE_UINT8(checksum, Z72ControllerSupply),
        VMSTATE_BOOL(selecting, Z72ControllerSupply),
        VMSTATE_BOOL(request, Z72ControllerSupply),
        VMSTATE_BOOL(ack_level, Z72ControllerSupply),
        VMSTATE_TIMER_PTR(timer, Z72ControllerSupply),
        VMSTATE_END_OF_LIST()
    },
};

static void supply_init(Object *obj)
{
    Z72ControllerSupply *s = Z72_CONTROLLER_SUPPLY(obj);
    s->timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, supply_ack, s);
    qdev_init_gpio_in(DEVICE(obj), supply_request, 1);
    qdev_init_gpio_out(DEVICE(obj), &s->ack, 1);
}

static void supply_finalize(Object *obj)
{
    timer_free(Z72_CONTROLLER_SUPPLY(obj)->timer);
}

static const Property supply_properties[] = {
    DEFINE_PROP_STRING("initial-state", Z72ControllerSupply, initial_state),
};

static void supply_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    I2CSlaveClass *ic = I2C_SLAVE_CLASS(klass);
    dc->realize = supply_realize;
    dc->vmsd = &supply_state;
    device_class_set_props(dc, supply_properties);
    RESETTABLE_CLASS(klass)->phases.hold = supply_reset;
    ic->event = supply_event;
    ic->send = supply_send;
    ic->recv = supply_recv;
}

static void supply_register_types(void)
{
    static const TypeInfo info = {
        .name = TYPE_Z72_CONTROLLER_SUPPLY,
        .parent = TYPE_I2C_SLAVE,
        .instance_size = sizeof(Z72ControllerSupply),
        .instance_init = supply_init,
        .instance_finalize = supply_finalize,
        .class_init = supply_class_init,
    };
    type_register_static(&info);
}

type_init(supply_register_types)
