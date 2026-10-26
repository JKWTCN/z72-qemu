/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Shoulder-panel I2C register model for the Z72 controller lab machine.
 *
 * Firmware analysis shows the original controller drives the top LCD panel
 * through an eight-bit-register I2C device: a two-byte read of register 26
 * reports the panel class identifier in its second byte (expected families
 * 0xA9/0xAA, 0xC9/0xCA and 0xE9/0xEA), single-byte writes to register 0xD6
 * select display pages, and the firmware confirms each selection by reading
 * the register back. The model keeps one byte per register, serves reads
 * from storage so a write-then-read echoes the stored byte, and exposes
 * read-only counters with the register image for host-side observation.
 * Segment decoding of the physical glass is not modeled here.
 */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qapi/visitor.h"
#include "hw/i2c/i2c.h"
#include "hw/qdev-properties.h"
#include "hw/resettable.h"
#include "migration/vmstate.h"

#define TYPE_Z72_CONTROLLER_PANEL "nikon-z72-controller-panel"
OBJECT_DECLARE_SIMPLE_TYPE(Z72ControllerPanel, Z72_CONTROLLER_PANEL)

#define PANEL_REGISTERS 256
#define PANEL_ID_REGISTER 26
#define PANEL_PAGE_REGISTER 0xD6

struct Z72ControllerPanel {
    I2CSlave parent_obj;
    uint8_t registers[PANEL_REGISTERS];
    uint8_t pointer;
    bool expect_pointer;
    uint8_t chip_id;
    uint32_t reads;
    uint32_t writes;
    uint32_t id_reads;
    uint32_t page_writes;
};

static int panel_event(I2CSlave *dev, enum i2c_event event)
{
    Z72ControllerPanel *s = Z72_CONTROLLER_PANEL(dev);
    if (event == I2C_START_SEND || event == I2C_FINISH) {
        s->expect_pointer = true;
    }
    return event == I2C_START_SEND_ASYNC ? -1 : 0;
}

static int panel_send(I2CSlave *dev, uint8_t value)
{
    Z72ControllerPanel *s = Z72_CONTROLLER_PANEL(dev);
    if (s->expect_pointer) {
        s->pointer = value;
        s->expect_pointer = false;
        return 0;
    }
    s->registers[s->pointer] = value;
    if (s->pointer == PANEL_PAGE_REGISTER) {
        s->page_writes++;
    }
    s->writes++;
    s->pointer = (s->pointer + 1) % PANEL_REGISTERS;
    return 0;
}

static uint8_t panel_receive(I2CSlave *dev)
{
    Z72ControllerPanel *s = Z72_CONTROLLER_PANEL(dev);
    uint8_t value = s->registers[s->pointer];
    if (s->pointer == PANEL_ID_REGISTER) {
        s->id_reads++;
    }
    s->reads++;
    s->pointer = (s->pointer + 1) % PANEL_REGISTERS;
    return value;
}

static void panel_reset(Object *obj, ResetType type)
{
    Z72ControllerPanel *s = Z72_CONTROLLER_PANEL(obj);
    memset(s->registers, 0, sizeof(s->registers));
    /* The identity read fetches registers 26..27; the class byte follows. */
    s->registers[PANEL_ID_REGISTER + 1] = s->chip_id;
    s->pointer = 0;
    s->expect_pointer = true;
    s->reads = s->writes = s->id_reads = s->page_writes = 0;
}

static void panel_realize(DeviceState *dev, Error **errp)
{
    Z72ControllerPanel *s = Z72_CONTROLLER_PANEL(dev);
    if (!I2C_SLAVE(s)->address || I2C_SLAVE(s)->address > 0x7f) {
        error_setg(errp, "Controller panel requires a nonzero seven-bit address");
        return;
    }
    switch (s->chip_id) {
    case 0xa9: case 0xaa: case 0xc9: case 0xca: case 0xe9: case 0xea:
        break;
    default:
        error_setg(errp, "Controller panel chip id must be one of "
                   "0xa9, 0xaa, 0xc9, 0xca, 0xe9, 0xea");
        return;
    }
}

static void panel_image_get(Object *obj, Visitor *v, const char *name,
                            void *opaque, Error **errp)
{
    Z72ControllerPanel *s = Z72_CONTROLLER_PANEL(obj);
    char *text = g_malloc(PANEL_REGISTERS * 2 + 1);
    for (unsigned i = 0; i < PANEL_REGISTERS; i++) {
        snprintf(text + 2 * i, 3, "%02x", s->registers[i]);
    }
    visit_type_str(v, name, &text, errp);
    g_free(text);
}

static void panel_instance_init(Object *obj)
{
    Z72ControllerPanel *s = Z72_CONTROLLER_PANEL(obj);
    object_property_add_uint8_ptr(obj, "page",
        &s->registers[PANEL_PAGE_REGISTER], OBJ_PROP_FLAG_READ);
    object_property_add_uint32_ptr(obj, "reads", &s->reads,
        OBJ_PROP_FLAG_READ);
    object_property_add_uint32_ptr(obj, "writes", &s->writes,
        OBJ_PROP_FLAG_READ);
    object_property_add_uint32_ptr(obj, "id-reads", &s->id_reads,
        OBJ_PROP_FLAG_READ);
    object_property_add_uint32_ptr(obj, "page-writes", &s->page_writes,
        OBJ_PROP_FLAG_READ);
}

static const VMStateDescription panel_vmstate = {
    .name = TYPE_Z72_CONTROLLER_PANEL,
    .version_id = 1, .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_I2C_SLAVE(parent_obj, Z72ControllerPanel),
        VMSTATE_UINT8_ARRAY(registers, Z72ControllerPanel, PANEL_REGISTERS),
        VMSTATE_UINT8(pointer, Z72ControllerPanel),
        VMSTATE_BOOL(expect_pointer, Z72ControllerPanel),
        VMSTATE_UINT32(reads, Z72ControllerPanel),
        VMSTATE_UINT32(writes, Z72ControllerPanel),
        VMSTATE_UINT32(id_reads, Z72ControllerPanel),
        VMSTATE_UINT32(page_writes, Z72ControllerPanel),
        VMSTATE_END_OF_LIST()
    },
};

static const Property panel_properties[] = {
    DEFINE_PROP_UINT8("chip-id", Z72ControllerPanel, chip_id, 0xc9),
};

static void panel_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    I2CSlaveClass *ic = I2C_SLAVE_CLASS(klass);
    dc->realize = panel_realize;
    dc->vmsd = &panel_vmstate;
    device_class_set_props(dc, panel_properties);
    RESETTABLE_CLASS(klass)->phases.hold = panel_reset;
    ic->event = panel_event;
    ic->send = panel_send;
    ic->recv = panel_receive;
    object_class_property_add(klass, "image", "str", panel_image_get,
                              NULL, NULL, NULL);
}

static void panel_register_types(void)
{
    static const TypeInfo info = {
        .name = TYPE_Z72_CONTROLLER_PANEL,
        .parent = TYPE_I2C_SLAVE,
        .instance_size = sizeof(Z72ControllerPanel),
        .instance_init = panel_instance_init,
        .class_init = panel_class_init,
    };
    type_register_static(&info);
}

type_init(panel_register_types)
