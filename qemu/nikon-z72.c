/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Z7 II C1.70 instruction laboratory with bounded early boot registers. */
#include "qemu/osdep.h"
#include "qemu/cutils.h"
#include "qemu/timer.h"
#include "qapi/error.h"
#include "hw/boards.h"
#include "hw/sysbus.h"
#include "hw/qdev-properties.h"
#include "hw/arm/machines-qom.h"
#include "hw/resettable.h"
#include "system/reset.h"
#include "hw/irq.h"
#include "hw/intc/arm_gic.h"
#include "hw/sd/sdhci.h"
#include "chardev/char.h"
#include "migration/vmstate.h"
#include "system/address-spaces.h"
#include "target/arm/cpu.h"
#include "nikon-z72-profile.h"
#include "nikon-z72-controller.h"

#define TYPE_NIKON_Z72_DUAL MACHINE_TYPE_NAME("nikon-z72-dual-lab")
OBJECT_DECLARE_SIMPLE_TYPE(NikonZ72DualMachine, NIKON_Z72_DUAL)

struct NikonZ72DualMachine {
    MachineState parent_obj;
    char *controller_firmware;
    bool controller_link;
    bool controller_step_link;
    char *master_boot_image;
    char *slave_boot_image;
    char *master_boot_aux;
    char *slave_boot_aux;
    Z72ControllerInputs controller_inputs;
};

static bool dual_controller_link_get(Object *obj, Error **errp)
{
    return NIKON_Z72_DUAL(obj)->controller_link;
}

static void dual_controller_link_set(Object *obj, bool value, Error **errp)
{
    NIKON_Z72_DUAL(obj)->controller_link = value;
}

static bool dual_controller_step_link_get(Object *obj, Error **errp)
{
    return NIKON_Z72_DUAL(obj)->controller_step_link;
}

static void dual_controller_step_link_set(Object *obj, bool value, Error **errp)
{
    NIKON_Z72_DUAL(obj)->controller_step_link = value;
}

static char *dual_controller_firmware_get(Object *obj, Error **errp)
{
    return g_strdup(NIKON_Z72_DUAL(obj)->controller_firmware);
}

static void dual_controller_firmware_set(Object *obj, const char *value, Error **errp)
{
    NikonZ72DualMachine *s = NIKON_Z72_DUAL(obj);
    g_free(s->controller_firmware);
    s->controller_firmware = g_strdup(value);
}

static char *dual_controller_flash_data_get(Object *obj, Error **errp)
{
    return g_strdup(NIKON_Z72_DUAL(obj)->controller_inputs.flash_data);
}

static void dual_controller_flash_data_set(Object *obj, const char *value, Error **errp)
{
    Z72ControllerInputs *s = &NIKON_Z72_DUAL(obj)->controller_inputs;
    g_free(s->flash_data);
    s->flash_data = g_strdup(value);
}

static char *dual_controller_supply_data_get(Object *obj, Error **errp)
{
    return g_strdup(NIKON_Z72_DUAL(obj)->controller_inputs.supply_data);
}

static void dual_controller_supply_data_set(Object *obj, const char *value, Error **errp)
{
    Z72ControllerInputs *s = &NIKON_Z72_DUAL(obj)->controller_inputs;
    g_free(s->supply_data);
    s->supply_data = g_strdup(value);
}

static bool dual_controller_battery_peer_get(Object *obj, Error **errp)
{
    return NIKON_Z72_DUAL(obj)->controller_inputs.battery_peer;
}

static void dual_controller_battery_peer_set(Object *obj, bool value, Error **errp)
{
    NIKON_Z72_DUAL(obj)->controller_inputs.battery_peer = value;
}

static char *dual_boot_image_get(Object *obj, int role, Error **errp)
{
    NikonZ72DualMachine *s = NIKON_Z72_DUAL(obj);
    return g_strdup(role ? s->slave_boot_image : s->master_boot_image);
}

static void dual_boot_image_set(Object *obj, int role, const char *value, Error **errp)
{
    NikonZ72DualMachine *s = NIKON_Z72_DUAL(obj);
    char **slot = role ? &s->slave_boot_image : &s->master_boot_image;
    g_free(*slot);
    *slot = g_strdup(value);
}

static char *dual_master_boot_image_get(Object *obj, Error **errp)
{
    return dual_boot_image_get(obj, 0, errp);
}

static void dual_master_boot_image_set(Object *obj, const char *value, Error **errp)
{
    dual_boot_image_set(obj, 0, value, errp);
}

static char *dual_slave_boot_image_get(Object *obj, Error **errp)
{
    return dual_boot_image_get(obj, 1, errp);
}

static void dual_slave_boot_image_set(Object *obj, const char *value, Error **errp)
{
    dual_boot_image_set(obj, 1, value, errp);
}

static char *dual_boot_aux_get(Object *obj, int role, Error **errp)
{
    NikonZ72DualMachine *s = NIKON_Z72_DUAL(obj);
    return g_strdup(role ? s->slave_boot_aux : s->master_boot_aux);
}

static void dual_boot_aux_set(Object *obj, int role, const char *value, Error **errp)
{
    NikonZ72DualMachine *s = NIKON_Z72_DUAL(obj);
    char **slot = role ? &s->slave_boot_aux : &s->master_boot_aux;
    g_free(*slot);
    *slot = g_strdup(value);
}

static char *dual_master_boot_aux_get(Object *obj, Error **errp)
{
    return dual_boot_aux_get(obj, 0, errp);
}

static void dual_master_boot_aux_set(Object *obj, const char *value, Error **errp)
{
    dual_boot_aux_set(obj, 0, value, errp);
}

static char *dual_slave_boot_aux_get(Object *obj, Error **errp)
{
    return dual_boot_aux_get(obj, 1, errp);
}

static void dual_slave_boot_aux_set(Object *obj, const char *value, Error **errp)
{
    dual_boot_aux_set(obj, 1, value, errp);
}

/* Exact configuration words observed in stock startup. Firmware pairs command
 * writes with bit-0 polls and acknowledgements. The laboratory assumes
 * synchronous completion and zero command results; real timing and hardware
 * effects remain unconfirmed. Unsupported neighboring words stay unassigned. */
static const hwaddr boot_config_addresses[] = {
    0x04264000, 0x04264020, 0x04281020, 0x04281028,
    0x0428102c, 0x0428202c, 0x0428242c, 0x20016000,
    0x20016020, 0x20016024, 0x20016028, 0x2001602c,
    0x20016030, 0x20016034, 0x20016038, 0x2001603c,
    0x20016d40, 0x20016d50, 0x20016d54, 0x20016d58,
    0x20016d5c, 0x20020000, 0x20020100, 0x2002010c,
    0x20021004, 0x20021008, 0x2002100c, 0x20021010,
    0x20021014, 0x20021020, 0x20021024, 0x20021028,
    0x2002102c, 0x20021030, 0x20021038, 0x20022000,
    0x20022100, 0x20022300, 0x20022408, 0x20022414,
    0x20023000, 0x20023100, 0x20023118, 0x20023300,
    0x20023318, 0x20023404, 0x20023408, 0x2002340c,
    0x20023500, 0x20023504, 0x20023508, 0x2002350c,
    0x20023510, 0x20023514, 0x20023600, 0x20023604,
    0x2002360c, 0x20023610, 0x20023614, 0x20023618,
    0x2002361c, 0x20023620, 0x20023624, 0x20023628,
    0x2002362c, 0x20023630, 0x20023634, 0x20023700,
    0x20023708, 0x2002370c, 0x20023800, 0x20023804,
    0x20023808, 0x20023900, 0x20023904, 0x20023a00,
    0x20023a04, 0x20023b00, 0x20023b04, 0x20024000,
    0x20024100, 0x20024300, 0x20024400, 0x20024404,
    0x20024408, 0x20028000, 0x20028010, 0x20028030,
    0x20028040, 0x20028800, 0x20028810, 0x20028830,
    0x20028c00, 0x20028c10, 0x20028c30, 0x20029000,
    0x20029010, 0x20029030, 0x20029040, 0x20029800,
    0x20029810, 0x20029830, 0x20029c00, 0x20029c10,
    0x20029c30, 0x2002a000, 0x2002a010, 0x2002a030,
    0x2002a040, 0x2002a800, 0x2002a810, 0x2002a830,
    0x2002ac00, 0x2002ac10, 0x2002ac30, 0x2002b000,
    0x2002b010, 0x2002b030, 0x2002b040, 0x2002b800,
    0x2002b810, 0x2002b830, 0x2002bc00, 0x2002bc10,
    0x2002bc30, 0x2002c000, 0x2002c010, 0x2002c030,
    0x2002c040, 0x2002c800, 0x2002c810, 0x2002c830,
    0x2002cc00, 0x2002cc10, 0x2002cc30, 0x2002e000,
    0x2002e100, 0x2002e300, 0x2002e400, 0x2002e600,
    0x2002e604, 0x2002e608, 0x2002e700, 0x2002e704,
    0x2002e708, 0x2002e70c, 0x2002e710, 0x20030010,
    0x20030014, 0x20030018, 0x2003001c, 0x20030020,
    0x20030024, 0x20030030, 0x20030034, 0x20030040,
    0x20030044, 0x20030048, 0x20030050, 0x20030054,
    0x20030058, 0x2003005c, 0x20030060, 0x20030074,
    0x20030078, 0x2003007c, 0x20030080, 0x20030094,
    0x20030098, 0x2003009c, 0x200300a0, 0x200300b8,
    0x200300e4, 0x200300e8, 0x200300ec, 0x200300f0,
    0x20030128, 0x2003012c, 0x20030130, 0x20030134,
    0x20030148, 0x2003014c, 0x20030150, 0x20030154,
    0x2003016c, 0x20030820, 0x20030824, 0x20030828,
    0x2003082c, 0x20030840, 0x20030850, 0x20030910,
    0x20040000, 0x20040100, 0x2004010c, 0x20041004,
    0x20041008, 0x2004100c, 0x20041010, 0x20041014,
    0x20041020, 0x20041024, 0x20041028, 0x2004102c,
    0x20041030, 0x20041038, 0x20042000, 0x20042100,
    0x20042300, 0x20042408, 0x20042414, 0x20043000,
    0x20043100, 0x20043118, 0x20043300, 0x20043318,
    0x20043404, 0x20043408, 0x2004340c, 0x20043500,
    0x20043504, 0x20043508, 0x2004350c, 0x20043510,
    0x20043514, 0x20043600, 0x20043604, 0x2004360c,
    0x20043610, 0x20043614, 0x20043618, 0x2004361c,
    0x20043620, 0x20043624, 0x20043628, 0x2004362c,
    0x20043630, 0x20043634, 0x20043700, 0x20043708,
    0x2004370c, 0x20043800, 0x20043804, 0x20043808,
    0x20043900, 0x20043904, 0x20043a00, 0x20043a04,
    0x20043b00, 0x20043b04, 0x20044000, 0x20044100,
    0x20044300, 0x20044400, 0x20044404, 0x20044408,
    0x20048000, 0x20048010, 0x20048030, 0x20048040,
    0x20048800, 0x20048810, 0x20048830, 0x20048c00,
    0x20048c10, 0x20048c30, 0x20049000, 0x20049010,
    0x20049030, 0x20049040, 0x20049800, 0x20049810,
    0x20049830, 0x20049c00, 0x20049c10, 0x20049c30,
    0x2004a000, 0x2004a010, 0x2004a030, 0x2004a040,
    0x2004a800, 0x2004a810, 0x2004a830, 0x2004ac00,
    0x2004ac10, 0x2004ac30, 0x2004b000, 0x2004b010,
    0x2004b030, 0x2004b040, 0x2004b800, 0x2004b810,
    0x2004b830, 0x2004bc00, 0x2004bc10, 0x2004bc30,
    0x2004c000, 0x2004c010, 0x2004c030, 0x2004c040,
    0x2004c800, 0x2004c810, 0x2004c830, 0x2004cc00,
    0x2004cc10, 0x2004cc30, 0x2004e000, 0x2004e100,
    0x2004e300, 0x2004e400, 0x2004e600, 0x2004e604,
    0x2004e608, 0x2004e700, 0x2004e704, 0x2004e708,
    0x2004e70c, 0x2004e710, 0x20050010, 0x20050014,
    0x20050018, 0x2005001c, 0x20050020, 0x20050024,
    0x20050030, 0x20050034, 0x20050040, 0x20050044,
    0x20050048, 0x20050050, 0x20050054, 0x20050058,
    0x2005005c, 0x20050060, 0x20050074, 0x20050078,
    0x2005007c, 0x20050080, 0x20050094, 0x20050098,
    0x2005009c, 0x200500a0, 0x200500b8, 0x200500e4,
    0x200500e8, 0x200500ec, 0x200500f0, 0x20050128,
    0x2005012c, 0x20050130, 0x20050134, 0x20050148,
    0x2005014c, 0x20050150, 0x20050154, 0x2005016c,
    0x20050820, 0x20050824, 0x20050828, 0x2005082c,
    0x20050840, 0x20050850, 0x20050910, 0x20070000,
    0x20070004, 0x20070008, 0x20070010, 0x20070014, 0x20070018,
    0x20070020, 0x20070024, 0x20070028, 0x20070030,
    /* Pin-group words observed in the stock library initializer: one
     * configuration triplet plus five banks of twelve words at 0x100 stride.
     * The two words already stored by earlier stock stages stay above. */
    0x04280030, 0x04280034, 0x04280038,
    0x04282000, 0x04282004, 0x04282008, 0x0428200c,
    0x04282010, 0x04282014, 0x04282018, 0x0428201c,
    0x04282020, 0x04282024, 0x04282028,
    0x04282100, 0x04282104, 0x04282108, 0x0428210c,
    0x04282110, 0x04282114, 0x04282118, 0x0428211c,
    0x04282120, 0x04282124, 0x04282128, 0x0428212c,
    0x04282200, 0x04282204, 0x04282208, 0x0428220c,
    0x04282210, 0x04282214, 0x04282218, 0x0428221c,
    0x04282220, 0x04282224, 0x04282228, 0x0428222c,
    0x04282300, 0x04282304, 0x04282308, 0x0428230c,
    0x04282310, 0x04282314, 0x04282318, 0x0428231c,
    0x04282320, 0x04282324, 0x04282328, 0x0428232c,
    0x04282400, 0x04282404, 0x04282408, 0x0428240c,
    0x04282410, 0x04282414, 0x04282418, 0x0428241c,
    0x04282420, 0x04282424, 0x04282428,
    /* Controller-chain words observed in the stock library initializer that
     * follows the pin groups: the 0x04281000 sequence, five extra 0x04280000
     * words and the two gate words at 0x04287000. */
    0x04281000, 0x04281004, 0x04281008, 0x0428100c,
    0x04281010, 0x04281014, 0x04281024, 0x04281028,
    0x04281138, 0x0428113c, 0x04281140, 0x04281144,
    0x04281148, 0x0428114c, 0x04280078, 0x0428007c,
    0x04280080, 0x04280084, 0x04280088, 0x04287000,
    0x04287004, 0x04287010,
    /* Configuration-snapshot words from the setup that follows: the gate
     * word plus the nineteen register words read through the recovered
     * pointer list. */
    0x20010038, 0x2001003c, 0x20010044, 0x20010100,
    0x20010104, 0x20010108, 0x2001010c, 0x20010110,
    0x20010114, 0x20010118, 0x2001011c, 0x20015004,
    0x20015020, 0x20015024, 0x20015028, 0x2001502c,
    0x20015030, 0x20015034, 0x20015038, 0x2001503c,
    /* Parameter-block words from the tail restore: eight segments at
     * 0x20013000, four mirror segments at 0x20016A00+ and the trigger. */
    0x20013000, 0x20013004, 0x20013008, 0x2001300c, 0x20013010, 0x20013014,
    0x20013018, 0x2001301c, 0x20013020, 0x20013024, 0x20013028, 0x2001302c,
    0x20013030, 0x20013034, 0x20013038, 0x2001303c, 0x20013040, 0x20013044,
    0x20013048, 0x2001304c, 0x20013050, 0x20013054, 0x20013058, 0x200130bc,
    0x200130c0, 0x200130c4, 0x200130c8, 0x200130cc, 0x200130d0, 0x200130d4,
    0x200130d8, 0x20013100, 0x20013104, 0x20013108, 0x2001310c, 0x20013110,
    0x20013114, 0x20013118, 0x2001311c, 0x20013120, 0x20013124, 0x20013128,
    0x2001312c, 0x20013130, 0x20013134, 0x20013138, 0x2001313c, 0x20013140,
    0x20013144, 0x20013148, 0x2001314c, 0x20013150, 0x20013154, 0x20013158,
    0x200131bc, 0x200131c0, 0x200131c4, 0x200131c8, 0x200131cc, 0x200131d0,
    0x200131d4, 0x200131d8, 0x20013200, 0x20013204, 0x20013208, 0x2001320c,
    0x20013210, 0x20013214, 0x20013218, 0x2001321c, 0x20013220, 0x20013224,
    0x20013228, 0x2001322c, 0x20013230, 0x20013234, 0x20013238, 0x2001323c,
    0x20013240, 0x20013244, 0x20013248, 0x2001324c, 0x20013250, 0x20013254,
    0x20013258, 0x200132bc, 0x200132c0, 0x200132c4, 0x200132c8, 0x200132cc,
    0x200132d0, 0x200132d4, 0x200132d8, 0x20013300, 0x20013304, 0x20013308,
    0x2001330c, 0x20013310, 0x20013314, 0x20013318, 0x2001331c, 0x20013320,
    0x20013324, 0x20013328, 0x2001332c, 0x20013330, 0x20013334, 0x20013338,
    0x2001333c, 0x20013340, 0x20013344, 0x20013348, 0x2001334c, 0x20013350,
    0x20013354, 0x20013358, 0x200133bc, 0x200133c0, 0x200133c4, 0x200133c8,
    0x200133cc, 0x200133d0, 0x200133d4, 0x200133d8, 0x20016a00, 0x20016a04,
    0x20016a08, 0x20016a0c, 0x20016a10, 0x20016a14, 0x20016a18, 0x20016a1c,
    0x20016a20, 0x20016a24, 0x20016a28, 0x20016a2c, 0x20016a30, 0x20016a34,
    0x20016a38, 0x20016a3c, 0x20016a40, 0x20016a44, 0x20016a48, 0x20016a4c,
    0x20016a50, 0x20016a54, 0x20016a58, 0x20016a5c, 0x20016a60, 0x20016a64,
    0x20016a68, 0x20016a6c, 0x20016a70, 0x20016a74, 0x20016a78, 0x20016a7c,
    0x20010060,
    /* Tail-completion words: final status stores, two nine-word rows
     * twice per 0x20012000 block and the scattered pointer-table writes. */
    0x20010034, 0x20012000, 0x20012004, 0x20012008, 0x2001200c, 0x20012010,
    0x20012014, 0x20012018, 0x2001201c, 0x20012020, 0x20012040, 0x20012044,
    0x20012048, 0x2001204c, 0x20012050, 0x20012054, 0x20012058, 0x2001205c,
    0x20012060, 0x20012100, 0x20012104, 0x20012108, 0x2001210c, 0x20012110,
    0x20012114, 0x20012118, 0x2001211c, 0x20012120, 0x20012140, 0x20012144,
    0x20012148, 0x2001214c, 0x20012150, 0x20012154, 0x20012158, 0x2001215c,
    0x20012160, 0x20012490, 0x200124a0, 0x20012618, 0x20012628, 0x20012638,
    0x20012640, 0x20012648, 0x20012658, 0x20012660, 0x20012790, 0x20012798,
    0x200127a8, 0x200127b0, 0x20015010, 0x20015014, 0x20015018, 0x2001501c,
    /* Release-path words the kernel touches once the handoff completes:
     * the controller bit-banks (read-modify-write over 0x04281034 and the
     * 0x04281058/0x0428105C pair) and the counter-adjacent register file
     * (+0/+4/+0x10 are fault-evidenced stock stores; the remaining file
     * words accept the same stores passively). */
    0x04281034, 0x04281030, 0x04281058, 0x0428105c,
    /* Remaining clock-control words selected by the firmware's table. */
    0x04281018, 0x0428101c,
    0x0426F000, 0x0426F004, 0x0426F008, 0x0426F00c,
    0x0426F010, 0x0426F014,
    /* Auxiliary configuration words and six indexed rows recovered from
     * the original register tables; +0x34..+0x44 also carry sync events. */
    0x20060000, 0x20060004, 0x20060008, 0x2006000c,
    0x20060010, 0x20060014, 0x20060018, 0x2006001c,
    0x20060020, 0x20060024, 0x20060028, 0x2006002c,
    0x20060030, 0x20060034, 0x20060038, 0x20060040, 0x20060044,
    /* Third synchronization bank: mask +0x4c, status +0x50. Firmware
     * analysis recovered the INTID 88 handler reading and acknowledging
     * the status word at +0x50 before invoking its callback slot. */
    0x2006004c, 0x20060050,
    0x20060070, 0x20060074, 0x20060078, 0x2006007c,
    0x20060080, 0x20060084, 0x20060088, 0x2006008c,
    0x20060090, 0x20060094, 0x20060098, 0x2006009c,
    0x200600a0, 0x200600a4, 0x200600a8, 0x200600ac,
    0x200600b0, 0x200600b4, 0x200600b8, 0x200600bc,
    0x200600c0, 0x200600c4, 0x200600c8, 0x200600cc,
    0x200600d0, 0x200600d4, 0x200600d8, 0x200600dc,
    0x200600e8, 0x20060128, 0x2006012c, 0x20060130,
    0x20060134, 0x20060138, 0x2006013c, 0x20060148,
    0x20060188, 0x2006018c, 0x20060190, 0x20060194,
    0x20060198, 0x2006019c, 0x200601a8, 0x200601e8,
    0x200601ec, 0x200601f0, 0x200601f4, 0x200601f8,
    0x200601fc, 0x20060208, 0x20060248, 0x2006024c,
    0x20060250, 0x20060254, 0x20060258, 0x2006025c,
    0x20060268, 0x200602a8, 0x200602ac, 0x200602b0,
    0x200602b4, 0x200602b8, 0x200602bc, 0x200602c8,
    0x20060314, 0x20060328, 0x2006032c,
    /* Indexed auxiliary lane configuration and diagnostic words. */
    0x200632d0, 0x200632d4,
    0x20063000, 0x20063004, 0x20063008, 0x2006300c,
    0x20063010, 0x20063014, 0x20063018, 0x2006301c,
    0x20063020, 0x20063024, 0x20063040, 0x20063044,
    0x20063048, 0x2006304c, 0x20063050, 0x20063054,
    0x20063058, 0x2006305c, 0x20063060, 0x20063064,
    0x20063080, 0x20063084, 0x20063088, 0x2006308c,
    0x20063090, 0x20063094, 0x20063098, 0x2006309c,
    0x200630a0, 0x200630a4, 0x200630a8, 0x200630ac,
    0x200630b4, 0x200630b8, 0x200630d0, 0x200630d4,
    0x200630d8, 0x200630dc, 0x200630e0, 0x200630e4,
    0x200630e8, 0x200630ec, 0x200630f0, 0x200630f4,
    0x20063110, 0x20063114, 0x20063118, 0x2006311c,
    0x20063120, 0x20063124, 0x20063128, 0x2006312c,
    0x20063130, 0x20063134, 0x20063150, 0x20063154,
    0x20063158, 0x2006315c, 0x20063160, 0x20063164,
    0x20063168, 0x2006316c, 0x20063170, 0x20063174,
    0x20063190, 0x20063194, 0x20063198, 0x2006319c,
    0x200631a0, 0x200631a4, 0x200631a8, 0x200631ac,
    0x200631b0, 0x200631b4, 0x200631d0, 0x200631d4,
    0x200631d8, 0x200631dc, 0x200631e0, 0x200631e4,
    0x200631e8, 0x200631ec, 0x200631f0, 0x200631f4,
    0x20063210, 0x20063214, 0x20063218, 0x2006321c,
    0x20063220, 0x20063224, 0x20063228, 0x2006322c,
    0x20063230, 0x20063234, 0x20063250, 0x20063254,
    0x20063258, 0x2006325c, 0x20063260, 0x20063264,
    0x20063268, 0x2006326c, 0x20063270, 0x20063274,
    0x20063290, 0x20063294, 0x20063298, 0x2006329c,
    0x200632a0, 0x200632a4, 0x200632a8, 0x200632ac,
    0x200632b0, 0x200632b4, 0x200632d8, 0x200632dc,
    0x200632e0, 0x200632e4, 0x200632e8, 0x200632ec,
    0x200632f0, 0x200632f4, 0x200632f8, 0x200632fc,
    0x20063300, 0x20063304, 0x20063308, 0x2006330c,
    0x20063310, 0x20063314, 0x20063318, 0x2006331c,
    0x20063320, 0x20063324, 0x20063328, 0x2006332c,
    0x20063330,
    /* Mask and routing configuration recovered from the runtime driver. */
    0x2b100000, 0x2b100004, 0x2b100008, 0x2b10000c,
    0x2b200000, 0x2b200004, 0x2b200008, 0x2b20000c,
    0x2b200010, 0x2b200014, 0x2b200018, 0x2b20001c,
    0x2b200020, 0x2b200024, 0x2b200028, 0x2b20002c,
    /* Configuration fields read and rewritten by the peripheral driver. */
    0x2b20003c, 0x2b20004c, 0x2b200050, 0x2b200054,
    0x2b200300,
    /* Link and PHY status: no endpoint is connected in this model. */
    0x2b200058, 0x2b20005c,
    /* Input-path setup and event banks; sample production is not modeled. */
    0x20068000, 0x20068004, 0x20068008, 0x2006800c,
    0x20068010, 0x20068014, 0x20068018, 0x20068020,
    0x20068024, 0x20068028,
    0x20068060, 0x20068070, 0x20068074, 0x20068078,
    0x2006807c, 0x20068080, 0x20068084, 0x20068088,
    0x2006808c, 0x20068100, 0x20068104, 0x20068140,
    0x20068144,
    0x20068200, 0x20068210, 0x20068220, 0x20068230,
    0x20068240, 0x20068250, 0x20068260, 0x20068270,
    0x20068280, 0x20068290, 0x200682a0, 0x200682b0,
    0x200682c0, 0x200682d0, 0x200682e0, 0x200682f0,
    /* Sampling synchronization configuration, including the five indexed
     * byte-field groups. Status/result words remain unsupported. */
    0x20061000, 0x20061004, 0x20061010, 0x20061014,
    0x20061018, 0x2006101c, 0x20061020, 0x20061024,
    0x20061028, 0x2006102c, 0x20061030, 0x20061034,
    0x20061038, 0x2006103c, 0x20061040, 0x20061044,
    0x20061048, 0x2006105c, 0x20061060, 0x20061064,
    0x20061068, 0x2006106c, 0x20061070, 0x20061074,
    0x20061078, 0x2006107c, 0x20061080, 0x20061084,
    0x20061088, 0x2006108c, 0x20061090, 0x20061094,
    0x200610a0, 0x200610a4, 0x200610a8, 0x200610ac,
    0x200610b4, 0x200610b8, 0x200610bc, 0x200610c0,
    0x200610c4, 0x200610c8, 0x200610cc, 0x200610d0,
    0x200610d4, 0x200610e0, 0x200610e4, 0x200610e8,
    0x200610ec, 0x200610f4, 0x200610f8, 0x200610fc,
    0x20061100, 0x20061104, 0x20061108, 0x2006110c,
    0x20061110, 0x20061114, 0x20061118, 0x2006111c,
    0x20061120, 0x2006112c, 0x20061130, 0x20061134,
    0x20061138, 0x2006113c, 0x20061200, 0x20061204,
    0x20061208, 0x2006120c, 0x20061210, 0x20061214,
    0x20061218, 0x2006121c, 0x20061220, 0x20061224,
    0x20061228, 0x2006122c, 0x20061230, 0x20061234,
    0x20061238, 0x2006123c, 0x20061240, 0x20061244,
    0x20061248, 0x2006124c, 0x20061250, 0x20061254,
    0x20061258, 0x2006125c, 0x20061260, 0x20061264,
    0x20061268, 0x2006126c, 0x20061270, 0x20061274,
    0x20061278, 0x2006127c, 0x20061280, 0x20061284,
    0x20061288, 0x2006128c, 0x20061400, 0x20061404,
    0x20061408, 0x2006140c, 0x20061410, 0x20061420,
    0x20061424, 0x20061428, 0x2006142c, 0x20061430,
    0x20061440, 0x20061444, 0x20061448, 0x2006144c,
    0x20061450, 0x20061460, 0x20061464, 0x20061468,
    0x2006146c, 0x20061470, 0x200614a0, 0x200614a4,
    0x200614a8, 0x200614ac, 0x200614b0,
    /* Sampled result window: the readout query returns five words masked
     * by the block's word 0, and the byte/halfword accessors read the
     * trailing fields. The words are latched state; the laboratory
     * source keeps them at the reset value because no sampled line
     * semantics have been recovered yet. */
    0x20061300, 0x20061304, 0x20061308, 0x2006130c, 0x20061310,
    0x2006135c, 0x20061360, 0x20061364, 0x20061368, 0x2006136c,
    0x20061370,
};

typedef struct NikonZ72Completion {
    hwaddr control, status;
    uint32_t command, maximum_phase;
} NikonZ72Completion;

static const NikonZ72Completion boot_completions[] = {
    {0x20022100, 0x20022300, 0x1, 0},
    {0x20023100, 0x20023300, 0x10001, 0},
    {0x20023118, 0x20023318, 0x1, 4},
    {0x20024100, 0x20024300, 0x1, 0},
    {0x20028010, 0x20028030, 0x1, 0},
    {0x20028810, 0x20028830, 0x1, 0},
    {0x20028c10, 0x20028c30, 0x1, 0},
    {0x20029010, 0x20029030, 0x1, 0},
    {0x20029810, 0x20029830, 0x1, 0},
    {0x20029c10, 0x20029c30, 0x1, 0},
    {0x2002a010, 0x2002a030, 0x1, 0},
    {0x2002a810, 0x2002a830, 0x1, 0},
    {0x2002ac10, 0x2002ac30, 0x1, 0},
    {0x2002b010, 0x2002b030, 0x1, 0},
    {0x2002b810, 0x2002b830, 0x1, 0},
    {0x2002bc10, 0x2002bc30, 0x1, 0},
    {0x2002c010, 0x2002c030, 0x1, 0},
    {0x2002c810, 0x2002c830, 0x1, 0},
    {0x2002cc10, 0x2002cc30, 0x1, 0},
    {0x2002e100, 0x2002e300, 0x1, 0},
    {0x20042100, 0x20042300, 0x1, 0},
    {0x20043100, 0x20043300, 0x10001, 0},
    {0x20043118, 0x20043318, 0x1, 4},
    {0x20044100, 0x20044300, 0x1, 0},
    {0x20048010, 0x20048030, 0x1, 0},
    {0x20048810, 0x20048830, 0x1, 0},
    {0x20048c10, 0x20048c30, 0x1, 0},
    {0x20049010, 0x20049030, 0x1, 0},
    {0x20049810, 0x20049830, 0x1, 0},
    {0x20049c10, 0x20049c30, 0x1, 0},
    {0x2004a010, 0x2004a030, 0x1, 0},
    {0x2004a810, 0x2004a830, 0x1, 0},
    {0x2004ac10, 0x2004ac30, 0x1, 0},
    {0x2004b010, 0x2004b030, 0x1, 0},
    {0x2004b810, 0x2004b830, 0x1, 0},
    {0x2004bc10, 0x2004bc30, 0x1, 0},
    {0x2004c010, 0x2004c030, 0x1, 0},
    {0x2004c810, 0x2004c830, 0x1, 0},
    {0x2004cc10, 0x2004cc30, 0x1, 0},
    {0x2004e100, 0x2004e300, 0x1, 0},
};

#define BOOT_CONFIG_WORDS G_N_ELEMENTS(boot_config_addresses)
#define AUX_IMAGE_MAX_PIXELS (390 * 32 * 32)

/* Group boundaries are located at realize time by each group's unique
 * first address, so appended words can never shift an earlier gate. */
static unsigned boot_config_index_of(hwaddr address)
{
    for (unsigned i = 0; i < BOOT_CONFIG_WORDS; i++) {
        if (boot_config_addresses[i] == address) {
            return i;
        }
    }
    g_assert_not_reached();
}

#define TYPE_NIKON_Z72_BOOT_CONFIG "nikon-z72-boot-config"
OBJECT_DECLARE_SIMPLE_TYPE(NikonZ72BootConfig, NIKON_Z72_BOOT_CONFIG)

typedef struct NikonZ72ConfigWord {
    NikonZ72BootConfig *device;
    unsigned index;
} NikonZ72ConfigWord;

struct NikonZ72BootConfig {
    SysBusDevice parent_obj;
    MemoryRegion banks[2];
    MemoryRegion registers[BOOT_CONFIG_WORDS];
    uint32_t values[BOOT_CONFIG_WORDS];
    NikonZ72ConfigWord words[BOOT_CONFIG_WORDS];
    bool auto_complete;
    uint32_t blocked_control;
    uint32_t clear_base, clear_size;
    bool memory_init_error;
    bool pin_config;
    bool controller_config;
    bool snapshot_config;
    bool parameter_config;
    bool release_config;
    bool stage_config;
    bool master_role;
    MemoryRegion snapshot_source;
    uint8_t snapshot_table[0x800];
    MemoryRegion mirror_window;
    uint8_t mirror_table[0x800];
    MemoryRegion stage_ram;
    MemoryRegion file_ram;
    uint8_t file_table[0x100];
    bool file_posted[0x100];
    MemoryRegion pair_ram;
    uint8_t pair_table[0x100];
    MemoryRegion seq_ram;
    uint8_t seq_table[0x2000];
    bool sequencer_completion;
    MemoryRegion count_ram;
    MemoryRegion enable_ram;
    MemoryRegion companion_ram;
    DeviceState *timer;
    DeviceState *intc;
    DeviceState *serial;
    bool controller_connected;
    uint8_t controller_levels;
    uint32_t gpio_input_levels;
    uint32_t gpio_input_driven;
    bool input_handshake;
    bool input_handshake_output;
    QEMUTimer *input_handshake_timer;
    bool sampling_output_complete;
    uint32_t sampling_output_gates;
    uint32_t sampling_output_active;
    uint32_t sampling_output_fired;
    int64_t sampling_output_epoch[2];
    QEMUTimer *sampling_output_timers[2];
    bool controller_ack_output;
    qemu_irq controller_ack_irq;
    qemu_irq controller_step_irq;
    uint32_t timer_line, timer_tick_us;
    bool timer_tick;
    MemoryRegion gate_ram;
    uint8_t gate_table[0x1000];
    bool gate_completion;
    bool gate_pending;
    MemoryRegion transfer_ram;
    uint8_t transfer_table[0x100];
    bool transfer_reset_completion;
    MemoryRegion *root;
    bool own_file;
    ARMCPU *cpu;
    bool peer_gpio;
    bool peer_connected;
    bool peer_ready_input;
    bool peer_ready_output;
    qemu_irq peer_ready_irq;
    NikonZ72BootConfig *peer;
    bool transport_link;
    MemoryRegion transport_ram;
    uint8_t transport_table[0x10000];
    MemoryRegion auxiliary_ram;
    MemoryRegion aux_image_ram;
    uint32_t aux_image_registers[0x200 / 4];
    uint32_t aux_image_levels;
    bool aux_image_process;
    uint32_t aux_image_reference_keys[2];
    uint32_t aux_image_reference_widths[2];
    uint32_t aux_image_reference_heights[2];
    uint8_t aux_image_references[2 * AUX_IMAGE_MAX_PIXELS];
    uint64_t aux_image_process_count;
    MemoryRegion dbi_ram;
    MemoryRegion sd_config_ram;
    MemoryRegion sd_clock_status;
    MemoryRegion sd_uhs2_caps;
    DeviceState *sd_controller;
    bool sd_host;
    bool sd_irq_level;
    uint32_t dbi_table[0x8c0 / 4];
    uint32_t dbi_viewport;
    uint32_t dbi_regions[2 * 16 * 7];
    uint32_t input_levels[8];
    uint32_t sync_levels[2];
    bool frame_sync;
    bool sensor_sample;
    bool frame_phase;
    bool input_stop_complete;
    bool display_complete;
    bool sample_counter;
    bool sample_group1;
    /* Sensor frame generation state */
    bool frame_generate;
    bool frame_process;
    bool frame_notify;
    uint32_t input_running;
    uint64_t input_dma_count;
    uint32_t input_dma_address;
    uint64_t input_grid_count;
    uint32_t input_grid_address;
    uint32_t input_grid_phase;
    uint64_t primary_dma_count;
    uint32_t primary_dma_address;
    uint32_t primary_second_address;
    bool primary_frame_written;
    bool primary_exposure_sync;
    bool primary_exposure_ready;
    uint64_t processing_dma_count;
    uint64_t processing_grid_count;
    MemoryRegion image_interrupts[2];
    NikonZ72ConfigWord image_interrupt_words[2];
    uint32_t image_interrupt_masks[2];
    uint32_t image_interrupt_status[2];
    MemoryRegion image_controls[5];
    NikonZ72ConfigWord image_control_words[5];
    uint32_t image_control_values[5];
    uint32_t image_drain_requests;
    bool image_draining;
    uint64_t frame_count;
    uint32_t input_last_read;
    bool pcie_link;
    bool auto_sample_level;
    uint32_t sample_lines;
    /* Bounded access trace over the sampling-synchronization and
     * input-path configuration window, recovered as a diagnostic for
     * the capture-restart sequence. Entries are (address, value,
     * direction) triples; the ring keeps the newest 256 accesses. */
    bool input_trace;
    uint32_t input_trace_count;
    uint32_t input_trace_addresses[256];
    uint32_t input_trace_values[256];
    uint8_t input_trace_writes[256];
    uint64_t frame_sync_count;
    QEMUTimer *frame_sync_timer;
    qemu_irq display_complete_irq[2];
};

static bool dbi_accepts(void *opaque, hwaddr offset, unsigned size,
                        bool is_write, MemTxAttrs attrs)
{
    static const uint16_t offsets[] = {
        0x004, 0x010, 0x014, 0x018, 0x01c, 0x03c, 0x050,
        0x078, 0x07c, 0x080, 0x084, 0x088, 0x08c,
        0x090, 0x098, 0x0a0, 0x104, 0x168, 0x80c, 0x8a8, 0x8bc,
    };

    if (size != 4 || (offset & 3)) {
        return false;
    }
    if (offset >= 0x900 && offset <= 0x91c) {
        return true;
    }
    for (unsigned i = 0; i < G_N_ELEMENTS(offsets); i++) {
        if (offset == offsets[i]) {
            return true;
        }
    }
    return false;
}

static uint32_t *dbi_word(NikonZ72BootConfig *s, hwaddr offset)
{
    if (offset == 0x900) {
        return &s->dbi_viewport;
    }
    if (offset >= 0x904) {
        unsigned region = (s->dbi_viewport >> 31) * 16 +
                          (s->dbi_viewport & 0xf);
        return &s->dbi_regions[region * 7 + (offset - 0x904) / 4];
    }
    return &s->dbi_table[offset / 4];
}

static uint64_t dbi_read(void *opaque, hwaddr offset, unsigned size)
{
    NikonZ72BootConfig *s = opaque;
    uint32_t value = *dbi_word(s, offset);
    /* The original bus guard requires negotiated speed 2 at this offset. */
    if (s->sd_host && offset == 0x098) {
        value = (value & ~0xfu) | 2;
    }
    return value;
}

static void dbi_write(void *opaque, hwaddr offset, uint64_t value,
                      unsigned size)
{
    NikonZ72BootConfig *s = opaque;

    if (offset == 0x900) {
        s->dbi_viewport = value & 0x8000000f;
    } else if (offset == 0x104) {
        /* Uncorrectable error status is write-one-to-clear. No modeled
         * error producer sets it; software cannot manufacture an error. */
        *dbi_word(s, offset) &= ~(uint32_t)value;
    } else {
        *dbi_word(s, offset) = value;
    }
}

static const MemoryRegionOps dbi_ops = {
    .read = dbi_read,
    .write = dbi_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4,
               .accepts = dbi_accepts },
    .impl = { .min_access_size = 4, .max_access_size = 4 },
};

static uint64_t sd_clock_read(void *opaque, hwaddr offset, unsigned size)
{
    NikonZ72BootConfig *s = opaque;
    uint32_t value;
    uint8_t *config = memory_region_get_ram_ptr(&s->sd_config_ram);

    memcpy(&value, config + 0x64, 4);
    /* The original channel-0 clock wait polls endpoint configuration bit 2.
     * Tie that indication to the SDHCI internal-clock stable state. */
    return (value & ~4u) |
           ((SYSBUS_SDHCI(s->sd_controller)->clkcon & 2) ? 4 : 0);
}

static bool sd_uhs2_caps_accepts(void *opaque, hwaddr offset,
                                  unsigned size, bool is_write,
                                  MemTxAttrs attrs)
{
    return !is_write && size == 4 && !(offset & 3) && offset < 0x10;
}

static uint64_t sd_uhs2_caps_read(void *opaque, hwaddr offset,
                                  unsigned size)
{
    /* Initialization snapshots four UHS-II capability words. The generic
     * SD host implements the conventional SD path and advertises no UHS-II. */
    return 0;
}

static const MemoryRegionOps sd_uhs2_caps_ops = {
    .read = sd_uhs2_caps_read,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4,
               .accepts = sd_uhs2_caps_accepts },
    .impl = { .min_access_size = 4, .max_access_size = 4 },
};

static void sd_clock_write(void *opaque, hwaddr offset,
                           uint64_t value, unsigned size)
{
    NikonZ72BootConfig *s = opaque;
    uint8_t *config = memory_region_get_ram_ptr(&s->sd_config_ram);
    uint32_t stored = value & ~4u;

    memcpy(config + 0x64, &stored, 4);
}

static const MemoryRegionOps sd_clock_ops = {
    .read = sd_clock_read,
    .write = sd_clock_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4 },
    .impl = { .min_access_size = 4, .max_access_size = 4 },
};

static void sd_update_irq(NikonZ72BootConfig *s)
{
    if (s->sd_host && s->intc) {
        /* The original vector 243 handler decodes INTA in status bit 28,
         * then invokes the card callback registered on the bus object. */
        qemu_set_irq(qdev_get_gpio_in(s->intc, 243 - 32), s->sd_irq_level);
    }
}

static void sd_irq_input(void *opaque, int line, int level)
{
    NikonZ72BootConfig *s = opaque;
    s->sd_irq_level = level != 0;
    sd_update_irq(s);
}

static hwaddr peer_ready_address(NikonZ72BootConfig *s)
{
    return s->master_role ? 0x04282018 : 0x04282020;
}

static unsigned peer_ready_bit(NikonZ72BootConfig *s)
{
    return s->master_role ? 3 : 10;
}

static void peer_ready_input(void *opaque, int line, int level)
{
    NikonZ72BootConfig *s = opaque;
    s->peer_ready_input = level != 0;
}

static uint32_t *boot_config_value(NikonZ72BootConfig *s, hwaddr address);

static void controller_update_irqs(NikonZ72BootConfig *s)
{
    if (s->intc) {
        uint32_t pending = *boot_config_value(s, 0x0426f008);
        uint32_t masked = *boot_config_value(s, 0x0426f000);
        for (unsigned line = 0; line < 16; line++) {
            qemu_set_irq(qdev_get_gpio_in(s->intc, 65 + line - 32),
                         !!(pending & ~masked & (1u << line)));
        }
    }
}

/* C 1.70's GPIO descriptors map interrupt inputs 0..8 to GPIO word
 * 0x04282014 bits 7..15, and 9..15 to 0x04282018 bits 0..6.
 * The connected controller already drives inputs 2 and 3. Other inputs
 * are external laboratory pins; no output-to-input loopback is assumed. */
static void engine_gpio_input(void *opaque, int line, int level)
{
    NikonZ72BootConfig *s = opaque;
    uint32_t bit = 1u << line;
    bool previous = !!(s->gpio_input_levels & bit);

    if (s->controller_connected && (line == 2 || line == 3)) {
        return;
    }
    s->gpio_input_driven |= bit;
    s->gpio_input_levels = (s->gpio_input_levels & ~bit) | (level ? bit : 0);
    if (previous != !!level && !resettable_is_in_reset(OBJECT(s))) {
        bool rising = !!(*boot_config_value(s, 0x0426f014) & bit);
        if (rising == !!level) {
            *boot_config_value(s, 0x0426f008) |= bit;
        }
        controller_update_irqs(s);
    }
}

/* Optional laboratory peer for the recovered output-101 / input-84
 * handshake. Respond to a selected output rising edge through the GPIO
 * interrupt path. One millisecond is a functional timing choice; this
 * does not identify the physical peer or produce sensor pixels. */
static void input_handshake_complete(void *opaque)
{
    NikonZ72BootConfig *s = opaque;

    engine_gpio_input(s, 0, 0);
    engine_gpio_input(s, 0, 1);
    engine_gpio_input(s, 0, 0);
}

static void controller_pin_input(void *opaque, int line, int level)
{
    NikonZ72BootConfig *s = opaque;
    bool previous = !!(s->controller_levels & (1u << line));
    s->controller_levels = (s->controller_levels & ~(1u << line)) |
                           (level ? 1u << line : 0);
    if (s->controller_connected && line < 2 && previous != !!level &&
        !resettable_is_in_reset(OBJECT(s))) {
        uint32_t bit = 1u << (line + 2);
        bool rising = !!(*boot_config_value(s, 0x0426f014) & bit);
        if (rising == !!level) {
            *boot_config_value(s, 0x0426f008) |= bit;
        }
        controller_update_irqs(s);
    }
}

static uint32_t *boot_config_value(NikonZ72BootConfig *s, hwaddr address)
{
    for (unsigned i = 0; i < BOOT_CONFIG_WORDS; i++) {
        if (boot_config_addresses[i] == address) {
            return &s->values[i];
        }
    }
    g_assert_not_reached();
}

static void input_update_irqs(NikonZ72BootConfig *s)
{
    static const unsigned groups[] = { 0, 0, 1, 2, 2, 3, 3, 4 };
    bool pending[5] = { false };

    if (!s->intc) {
        return;
    }
    for (unsigned bank = 0; bank < G_N_ELEMENTS(groups); bank++) {
        hwaddr base = 0x20068200 + bank * 0x20;
        pending[groups[bank]] |= (*boot_config_value(s, base) &
                                 *boot_config_value(s, base + 0x10)) != 0;
    }
    for (unsigned group = 0; group < G_N_ELEMENTS(pending); group++) {
        qemu_set_irq(qdev_get_gpio_in(s->intc, 94 + group - 32), pending[group]);
    }
}

static void input_event(void *opaque, int line, int level)
{
    NikonZ72BootConfig *s = opaque;
    unsigned bank = line / 32;
    uint32_t bit = 1u << (line % 32);

    /* External event inputs name status bits, not physical sensor pins. */
    if (level && !(s->input_levels[bank] & bit)) {
        *boot_config_value(s, 0x20068210 + bank * 0x20) |= bit;
    }
    if (level) {
        s->input_levels[bank] |= bit;
    } else {
        s->input_levels[bank] &= ~bit;
    }
    input_update_irqs(s);
}

static void aux_image_update_irq(NikonZ72BootConfig *s)
{
    if (s->intc && s->release_config) {
        uint32_t pending = s->aux_image_registers[0x20 / 4] &
                           s->aux_image_registers[0x2c / 4];
        qemu_set_irq(qdev_get_gpio_in(s->intc, 116 - 32), pending != 0);
    }
}

static void aux_image_event(void *opaque, int line, int level)
{
    NikonZ72BootConfig *s = opaque;
    uint32_t bit = 1u << line;

    if (!s->release_config) {
        return;
    }
    /* Decoded causes for the original handler, independent of pixel DMA. */
    if (level && !(s->aux_image_levels & bit)) {
        s->aux_image_registers[0x2c / 4] |= bit;
    }
    if (level) {
        s->aux_image_levels |= bit;
    } else {
        s->aux_image_levels &= ~bit;
    }
    aux_image_update_irq(s);
}

static uint64_t aux_image_read(void *opaque, hwaddr offset, unsigned size)
{
    NikonZ72BootConfig *s = opaque;
    return s->aux_image_registers[offset / 4];
}

static bool aux_image_process_frame(NikonZ72BootConfig *s);

static void aux_image_write(void *opaque, hwaddr offset,
                            uint64_t value, unsigned size)
{
    NikonZ72BootConfig *s = opaque;

    if (offset == 0x1a0) {
        return; /* No software writes to the result register. */
    }
    if (offset == 0x2c) {
        s->aux_image_registers[offset / 4] &= ~(uint32_t)value;
    } else {
        s->aux_image_registers[offset / 4] = value;
    }
    if (s->aux_image_process && offset == 0 && value == 1) {
        s->aux_image_registers[4 / 4] = 0;
    }
    if (offset == 4 && value == 1 && aux_image_process_frame(s)) {
        s->aux_image_registers[4 / 4] = 0;
        /* Original cause 2 delivers event 4 to the native completion wait. */
        s->aux_image_registers[0x2c / 4] |= 2;
    }
    aux_image_update_irq(s);
}

static const MemoryRegionOps aux_image_ops = {
    .read = aux_image_read,
    .write = aux_image_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4 },
    .impl = { .min_access_size = 4, .max_access_size = 4 },
};

static void sync_update_irqs(NikonZ72BootConfig *s)
{
    if (s->intc && s->release_config) {
        for (unsigned bank = 0; bank < 2; bank++) {
            hwaddr mask = bank ? 0x20060040 : 0x20060034;
            uint32_t pending = *boot_config_value(s, mask) &
                               *boot_config_value(s, mask + 4);
            if (!bank) {
                pending &= 0x7ff;
            }
            qemu_set_irq(qdev_get_gpio_in(s->intc, 86 + bank - 32), pending != 0);
        }
        /* The third synchronization path is the automatic-sample event.
         * Firmware analysis recovered its handler: it reads the status
         * word at +0x50, acknowledges it by write-back, then calls the
         * callback registered in its slot. The line follows the masked
         * pending state like the two banks above. */
        uint32_t pending = *boot_config_value(s, 0x2006004c) &
                           *boot_config_value(s, 0x20060050);
        qemu_set_irq(qdev_get_gpio_in(s->intc, 88 - 32), pending != 0);
    }
}

static bool sampling_output_supported(NikonZ72BootConfig *s, unsigned index)
{
    hwaddr base = 0x200630d0 + index * 0x40;
    uint32_t bit = 8u << index;
    uint32_t control = *boot_config_value(s, base + 0x1c);

    /* Narrow functional interpretation of the observed single-comparison
     * configuration. Other periods, second comparisons and modes wait for
     * evidence rather than generating unconditional capture notifications. */
    return s->sampling_output_complete && s->master_role &&
        s->sensor_sample && s->auto_complete &&
        (s->sampling_output_active & bit) &&
        (s->sampling_output_gates & (bit << 1)) &&
        !(s->sampling_output_fired & bit) &&
        *boot_config_value(s, base) == UINT32_MAX &&
        *boot_config_value(s, base + 4) == 0xffffff &&
        *boot_config_value(s, base + 8) == 0xffff &&
        (*boot_config_value(s, base + 0xc) >> 16) == 0xffff &&
        *boot_config_value(s, base + 0x14) == 0xffffff &&
        (*boot_config_value(s, base + 0x18) >> 16) == 0xffff &&
        (control == 0x06000004 || control == 0x06000006);
}

static void sampling_output_expire(NikonZ72BootConfig *s, unsigned index)
{
    if (sampling_output_supported(s, index)) {
        uint32_t bit = 8u << index;
        s->sampling_output_fired |= bit;
        if (index == 1 && s->primary_exposure_sync &&
            (s->input_running & 0x400)) {
            s->primary_exposure_ready = true;
        }
        *boot_config_value(s, 0x20060038) |= bit;
        sync_update_irqs(s);
    }
}

static void sampling_output_first(void *opaque)
{
    sampling_output_expire(opaque, 0);
}

static void sampling_output_second(void *opaque)
{
    sampling_output_expire(opaque, 1);
}

static void sampling_output_write(NikonZ72BootConfig *s, hwaddr address,
                                  uint32_t value)
{
    if (!s->sampling_output_complete || !s->master_role) {
        return;
    }
    if (address == 0x20060008) {
        s->sampling_output_gates &= ~value;
    } else if (address == 0x2006000c) {
        s->sampling_output_gates |= value & 0x30;
    } else if (address == 0x20060024) {
        s->sampling_output_active &= ~value;
    }
    for (unsigned i = 0; i < 2; i++) {
        uint32_t bit = 8u << i;
        hwaddr base = 0x200630d0 + i * 0x40;
        if ((address == base + 0x20 && (value & 1)) ||
            (address == 0x20060020 && (value & bit) &&
             !(s->sampling_output_active & bit))) {
            s->sampling_output_epoch[i] = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
            s->sampling_output_fired &= ~bit;
            if (address == base + 0x20) {
                s->sampling_output_active &= ~bit;
            }
        }
    }
    if (address == 0x20060020) {
        s->sampling_output_active |= value & 0x18;
    }
    *boot_config_value(s, 0x20060020) =
        (*boot_config_value(s, 0x20060020) & ~0x18u) | s->sampling_output_active;
    for (unsigned i = 0; i < 2; i++) {
        hwaddr base = 0x200630d0 + i * 0x40;
        if (!sampling_output_supported(s, i)) {
            timer_del(s->sampling_output_timers[i]);
            continue;
        }
        uint64_t ticks = (*boot_config_value(s, base + 0xc) & 0xffffu) |
            ((uint64_t)(*boot_config_value(s, base + 0x10) & 0xffffffu) << 16) |
            ((uint64_t)(*boot_config_value(s, base + 0x18) & 0xffffu) << 40);
        /* Original code multiplies microseconds by 72. The functional clock
         * is 72 MHz; physical frequency and output transitions are unmeasured. */
        uint64_t ns = ticks / 72 * 1000 + (ticks % 72 * 1000 + 71) / 72;
        timer_mod(s->sampling_output_timers[i],
            MAX(qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 1,
                s->sampling_output_epoch[i] + (int64_t)ns));
    }
}

static void sync_event(void *opaque, int line, int level)
{
    NikonZ72BootConfig *s = opaque;
    unsigned bank = line >= 11;
    uint32_t bit = 1u << (bank ? line - 11 : line);

    /* External lines identify synchronization status bits, not sensor pins. */
    if (level && !(s->sync_levels[bank] & bit)) {
        *boot_config_value(s, bank ? 0x20060044 : 0x20060038) |= bit;
    }
    s->sync_levels[bank] = level ? s->sync_levels[bank] | bit :
                                  s->sync_levels[bank] & ~bit;
    sync_update_irqs(s);
}

/* One direct injection line for the automatic-sample event, edge-latched
 * like the synchronization banks above. */
static void auto_sample_event(void *opaque, int line, int level)
{
    NikonZ72BootConfig *s = opaque;

    if (level && !s->auto_sample_level) {
        *boot_config_value(s, 0x20060050) |= 1u;
        sync_update_irqs(s);
    }
    s->auto_sample_level = level != 0;
}

/* Optional laboratory timing source; no sensor pixels are produced.
 * Bank 2 bit 4 follows the pending/mask/acknowledge path of input 15.
 * With sensor-sample armed, each tick also latches one automatic-sample
 * event in the third bank. The optional phase source sets bank 2 bit 7
 * only while software enables it; neither source supplies pixel data.
 * The 30 Hz period is a functional choice, not a measured rate. */
static void transfer_update_irq(NikonZ72BootConfig *s);

static bool processing_ram_range(AddressSpace *view, uint32_t address,
                                 hwaddr length)
{
    hwaddr offset, span = length;
    MemoryRegion *region;

    if (!address || !length || (uint64_t)address + length > UINT32_MAX) {
        return false;
    }
    region = address_space_translate(view, address, &offset, &span, true,
                                     MEMTXATTRS_UNSPECIFIED);
    return memory_region_is_ram(region) && !memory_region_is_rom(region) &&
           span >= length;
}

static uint32_t aux_image_sad(const uint8_t *previous, const uint8_t *current,
                              unsigned width, unsigned height, unsigned x,
                              unsigned y, int dx, int dy, uint32_t ceiling)
{
    uint32_t score = 0;

    for (unsigned row = 0; row < 32; row++) {
        unsigned cy = MIN(MAX((int)(y + row) + dy, 0), (int)height - 1);
        for (unsigned column = 0; column < 32; column++) {
            unsigned cx = MIN(MAX((int)(x + column) + dx, 0), (int)width - 1);
            score += abs((int)previous[(y + row) * width + x + column] -
                         current[cy * width + cx]);
            if (score > ceiling) {
                return score;
            }
        }
    }
    return score;
}

/* Functional grayscale block matching, not a reconstruction of the original
 * hardware search or metric. The recovered consumer accepts 16-byte cells
 * with signed 1/32-coordinate components and a 16-bit metric. Here the metric
 * is saturated 32x32 SAD; integer search is bounded to eight pixels, with
 * replicated borders. Firmware workspace addresses identify two independent
 * reference streams; their opaque guest storage is not rewritten. */
static bool aux_image_process_frame(NikonZ72BootConfig *s)
{
    uint32_t *r = s->aux_image_registers;
    uint32_t columns = r[0x50 / 4], rows = r[0x54 / 4];
    uint32_t stride = r[0x12c / 4], source = r[0x130 / 4];
    uint32_t target = r[0x178 / 4], key = r[0x5c / 4];
    unsigned width, height, slot;
    size_t pixels, source_span, result_bytes;
    AddressSpace *view;
    uint8_t *previous;
    bool have_reference;
    g_autofree uint8_t *current = NULL;
    g_autofree uint8_t *result = NULL;

    if (!s->aux_image_process || !s->master_role || !s->cpu ||
        columns < 10 || columns > 48 || rows < 7 || rows > 32 ||
        columns * rows > 390 || r[0x4c / 4] != 1 ||
        r[0x11c / 4] != 1 || r[0x164 / 4] != 1 ||
        r[0x104 / 4] != 0 || r[0x160 / 4] != 0 || r[0x110 / 4] != 3) {
        return false;
    }
    width = columns * 32;
    height = rows * 32;
    if (stride < width || stride > 1536) {
        return false;
    }
    pixels = (size_t)width * height;
    source_span = (size_t)(height - 1) * stride + width;
    result_bytes = (size_t)columns * rows * 16;
    view = CPU(s->cpu)->as;
    if (!processing_ram_range(view, source, source_span) ||
        !processing_ram_range(view, target, result_bytes) ||
        !processing_ram_range(view, key, pixels) ||
        ((uint64_t)source < (uint64_t)target + result_bytes &&
         (uint64_t)target < (uint64_t)source + source_span)) {
        return false;
    }
    for (slot = 0; slot < 2; slot++) {
        if (s->aux_image_reference_keys[slot] == key) {
            break;
        }
    }
    if (slot == 2) {
        for (slot = 0; slot < 2; slot++) {
            if (!s->aux_image_reference_keys[slot]) {
                break;
            }
        }
    }
    if (slot == 2) {
        return false;
    }
    current = g_malloc(pixels);
    result = g_malloc0(result_bytes);
    for (unsigned row = 0; row < height; row++) {
        if (address_space_read(view, source + row * stride, MEMTXATTRS_UNSPECIFIED,
                               current + row * width, width) != MEMTX_OK) {
            return false;
        }
    }
    previous = s->aux_image_references + slot * AUX_IMAGE_MAX_PIXELS;
    have_reference = s->aux_image_reference_keys[slot] == key &&
                     s->aux_image_reference_widths[slot] == width &&
                     s->aux_image_reference_heights[slot] == height;
    for (unsigned y = 0; y < height; y += 32) {
        for (unsigned x = 0; x < width; x += 32) {
            uint8_t *cell = result + ((y / 32) * columns + x / 32) * 16;
            int best_x = 0, best_y = 0;
            uint32_t best;

            if (!have_reference) {
                stw_le_p(cell, 512);
                stw_le_p(cell + 2, 512);
                stw_le_p(cell + 4, UINT16_MAX);
                continue;
            }
            best = aux_image_sad(previous, current, width, height, x, y,
                                 0, 0, UINT32_MAX);
            for (int radius = 1; radius <= 8 && best; radius++) {
                for (int dy = -radius; dy <= radius; dy++) {
                    for (int dx = -radius; dx <= radius; dx++) {
                        uint32_t score;
                        if (abs(dx) != radius && abs(dy) != radius) {
                            continue;
                        }
                        score = aux_image_sad(previous, current, width, height,
                                              x, y, dx, dy, best);
                        if (score < best || (score == best &&
                            abs(dx) + abs(dy) < abs(best_x) + abs(best_y))) {
                            best = score;
                            best_x = dx;
                            best_y = dy;
                        }
                    }
                }
            }
            stw_le_p(cell, best_x * 32);
            stw_le_p(cell + 2, best_y * 32);
            stw_le_p(cell + 4, MIN(best, UINT16_MAX));
        }
    }
    if (address_space_write(view, target, MEMTXATTRS_UNSPECIFIED,
                            result, result_bytes) != MEMTX_OK) {
        return false;
    }
    memcpy(previous, current, pixels);
    s->aux_image_reference_keys[slot] = key;
    s->aux_image_reference_widths[slot] = width;
    s->aux_image_reference_heights[slot] = height;
    s->aux_image_process_count++;
    return true;
}

static void image_update_irqs(NikonZ72BootConfig *s)
{
    if (!s->intc) {
        return;
    }
    for (unsigned bank = 0; bank < 2; bank++) {
        qemu_set_irq(qdev_get_gpio_in(s->intc, 99 + bank - 32),
            (s->image_interrupt_status[bank] & s->image_interrupt_masks[bank]) != 0);
    }
}

static uint64_t image_interrupt_read(void *opaque, hwaddr offset, unsigned size)
{
    NikonZ72ConfigWord *word = opaque;
    NikonZ72BootConfig *s = word->device;

    return offset == 0 ? s->image_interrupt_masks[word->index] :
                         s->image_interrupt_status[word->index];
}

static void image_interrupt_write(void *opaque, hwaddr offset,
                                 uint64_t value, unsigned size)
{
    NikonZ72ConfigWord *word = opaque;
    NikonZ72BootConfig *s = word->device;

    if (offset == 0) {
        s->image_interrupt_masks[word->index] = value;
    } else {
        s->image_interrupt_status[word->index] &= ~(uint32_t)value;
    }
    image_update_irqs(s);
}

static const MemoryRegionOps image_interrupt_ops = {
    .read = image_interrupt_read,
    .write = image_interrupt_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4 },
    .impl = { .min_access_size = 4, .max_access_size = 4 },
};

/* C1.70's active bank0 input: the same four RAW buffers as sensor DMA,
 * with the native list rotated by two slots. Membership is checked here;
 * the physical ring phase remains an experimental timing assumption. */
static bool image_preview_input(NikonZ72BootConfig *s, uint32_t source,
                                uint32_t width, uint32_t height, uint32_t stride)
{
    AddressSpace *view = CPU(s->cpu)->as;
    uint8_t run[4], geometry[8], bindings[0x50];
    bool bound = false;

    if (!(s->image_control_values[0] & 1) ||
        address_space_read(view, 0x20380010, MEMTXATTRS_UNSPECIFIED,
                           run, sizeof(run)) != MEMTX_OK ||
        !(ldl_le_p(run) & 1) ||
        address_space_read(view, 0x20380044, MEMTXATTRS_UNSPECIFIED,
                           geometry, sizeof(geometry)) != MEMTX_OK ||
        ldl_le_p(geometry) != 0 || ldl_le_p(geometry + 4) != (width << 16 | height) ||
        address_space_read(view, 0x20380300, MEMTXATTRS_UNSPECIFIED,
                           bindings, sizeof(bindings)) != MEMTX_OK ||
        ldl_le_p(bindings) != 0 || ldl_le_p(bindings + 4) != 0 ||
        ldl_le_p(bindings + 8) != 0 || ldl_le_p(bindings + 12) != stride) {
        return false;
    }
    for (unsigned slot = 0; slot < 4; slot++) {
        bound |= ldl_le_p(bindings + 0x10 + slot * 4) == source;
    }
    for (unsigned offset = 0x20; offset < sizeof(bindings); offset += 4) {
        if (ldl_le_p(bindings + offset)) {
            return false;  /* Additional input planes are not implemented. */
        }
    }
    return bound;
}

static const unsigned image_control_offsets[] = {8, 0x54, 0x60, 0x6c, 0x78};

/* The native cancellation path requests four drains, then optionally runs
 * this bank0 scratch input. All raster writes are synchronous in this model,
 * so the four channels have no outstanding writes after the request batch.
 * The small input has no enabled output: read it without producing a raster.
 * Paired scratch input and other processor recipes remain unsupported. */
static bool image_drain_input(AddressSpace *view)
{
    static const struct { unsigned offset; uint32_t value; } profile[] = {
        {0, 3}, {4, 3}, {0x10, 1}, {0x44, 0}, {0x48, 0x0014000e},
        {0x4c, 0}, {0x50, 0}, {0x84, 0}, {0xbc, 1}, {0xc0, 0},
        {0xc4, 20}, {0xc8, 0}, {0xcc, 0},
        {0x120, 0}, {0x124, 0}, {0x128, 0}, {0x12c, 0}, {0x130, 0},
        {0x300, 2}, {0x30c, 32}, {0x3e8, 2}, {0x3f0, 32},
        {0x410, 0}, {0x420, 0}, {0x580, 1}, {0x67c, 0x200},
    };
    uint8_t word[4], input[32 * 20];
    uint32_t source;

    for (unsigned index = 0; index < ARRAY_SIZE(profile); index++) {
        if (address_space_read(view, 0x20380000 + profile[index].offset,
                               MEMTXATTRS_UNSPECIFIED, word, 4) != MEMTX_OK ||
            ldl_le_p(word) != profile[index].value) {
            return false;
        }
    }
    if (address_space_read(view, 0x20380310, MEMTXATTRS_UNSPECIFIED,
                           word, 4) != MEMTX_OK) {
        return false;
    }
    source = ldl_le_p(word);
    if (address_space_read(view, 0x203803ec, MEMTXATTRS_UNSPECIFIED,
                           word, 4) != MEMTX_OK || ldl_le_p(word) != source ||
        !processing_ram_range(view, source, sizeof(input))) {
        return false;
    }
    return address_space_read(view, source, MEMTXATTRS_UNSPECIFIED,
                              input, sizeof(input)) == MEMTX_OK;
}

static uint64_t image_control_read(void *opaque, hwaddr offset, unsigned size)
{
    NikonZ72ConfigWord *word = opaque;

    return word->device->image_control_values[word->index];
}

static void image_control_write(void *opaque, hwaddr offset,
                                uint64_t value, unsigned size)
{
    NikonZ72ConfigWord *word = opaque;
    NikonZ72BootConfig *s = word->device;
    uint8_t prefix[4], source[4];
    AddressSpace *view;

    s->image_control_values[word->index] = value;
    if (!s->frame_process || !s->master_role || !s->cpu || value != 1) {
        return;
    }
    view = CPU(s->cpu)->as;
    if (word->index == 0) {
        if (!s->image_draining) {
            return;
        }
        if (s->image_drain_requests == 0xf && image_drain_input(view)) {
            s->image_drain_requests = 0;
            s->image_interrupt_status[0] |= 2;
            image_update_irqs(s);
        } else if (address_space_read(view, 0x20380310, MEMTXATTRS_UNSPECIFIED,
                                      source, 4) == MEMTX_OK &&
                   image_preview_input(s, ldl_le_p(source), 1380, 918, 2080)) {
            s->image_draining = false;
            s->image_drain_requests = 0;
        }
        return;
    }
    if (address_space_read(view, 0x20380084, MEMTXATTRS_UNSPECIFIED,
                           prefix, 4) != MEMTX_OK || ldl_le_p(prefix) != 0 ||
        address_space_read(view, 0x203800f0, MEMTXATTRS_UNSPECIFIED,
                           prefix, 4) != MEMTX_OK || ldl_le_p(prefix) != 0xfc400) {
        return;
    }
    if (word->index == 1) {
        s->image_drain_requests = 0;
        s->image_draining = true;
    } else if (!s->image_draining || !(s->image_drain_requests & 1)) {
        return;
    }
    if (s->image_drain_requests & (1u << (word->index - 1))) {
        return;
    }
    s->image_drain_requests |= 1u << (word->index - 1);
    if (s->image_drain_requests == 0xf) {
        s->image_interrupt_status[0] |= 0x14a0000;
        image_update_irqs(s);
    }
}

static const MemoryRegionOps image_control_ops = {
    .read = image_control_read,
    .write = image_control_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4 },
    .impl = { .min_access_size = 4, .max_access_size = 4 },
};

/* Functional scalar grids for the observed bank0 recipe. The three
 * 16-bit views and pitches are native descriptors. Nearest sampling of
 * RAW12 codes, identical scalar planes and paired RAW12 output for channel2
 * are explicit algorithm/layout hypotheses, not the camera's metering or
 * calibration operators. The caller has validated full-scale RAW pairs. */
static bool image_generate_grids(NikonZ72BootConfig *s, const uint8_t *raw,
                                 uint32_t width, uint32_t height, uint32_t stride,
                                 const uint8_t *addresses, unsigned slot)
{
    AddressSpace *view = CPU(s->cpu)->as;
    uint8_t control[4], descriptors[2][52], scalar_row[120], packed_row[90];
    uint32_t targets[4];
    const unsigned rows[4] = {128, 128, 128, 96};
    uint64_t base = (uint32_t)ldl_le_p(addresses + (slot * 16 + 1) * 4);

    if (address_space_read(view, 0x20102000, MEMTXATTRS_UNSPECIFIED, control, 4) != MEMTX_OK ||
        (ldl_le_p(control) & 0xf) != 1 ||
        address_space_read(view, 0x20102648, MEMTXATTRS_UNSPECIFIED, control, 4) != MEMTX_OK ||
        !(ldl_le_p(control) & 1)) {
        return false;
    }
    for (unsigned index = 0; index < 2; index++) {
        uint8_t *d = descriptors[index];
        unsigned row = index ? 96 : 128;
        if (address_space_read(view, 0x20100440 + index * 0x40,
                               MEMTXATTRS_UNSPECIFIED, d, 52) != MEMTX_OK ||
            ldl_le_p(d) != (index ? 0x10621 : 0x20121) ||
            ldl_le_p(d + 0x10) != row || ldl_le_p(d + 0x14) != row ||
            ldl_le_p(d + 0x18) != (index ? 0 : 128) ||
            ldl_le_p(d + 0x20) != 0x0028003c || ldl_le_p(d + 0x24) ||
            ldl_le_p(d + 0x28) != (index ? 0 : 0x12000) ||
            ldl_le_p(d + 0x2c) != (index ? 0 : 0x24000) || ldl_le_p(d + 0x30)) {
            return false;
        }
    }
    if (!base || base + 0x24000 > UINT32_MAX) {
        return false;
    }
    for (unsigned plane = 0; plane < 3; plane++) {
        targets[plane] = base + plane * 0x12000;
    }
    targets[3] = ldl_le_p(addresses + (slot * 16 + 2) * 4);
    /* Validate every plane before modifying this bank's first destination. */
    for (unsigned plane = 0; plane < 4; plane++) {
        uint64_t end = (uint64_t)targets[plane] + rows[plane] * 40;
        if (!processing_ram_range(view, targets[plane], rows[plane] * 40) ||
            (targets[plane] < 0xbb300000 && end > 0xbaa00000)) {
            return false;
        }
        for (unsigned previous = 0; previous < plane; previous++) {
            uint64_t previous_end = (uint64_t)targets[previous] + rows[previous] * 40;
            if (targets[plane] < previous_end && targets[previous] < end) {
                return false;
            }
        }
    }
    for (unsigned y = 0; y < 40; y++) {
        unsigned sy = 2 + (uint64_t)y * (height - 4) / 40;
        for (unsigned x = 0; x < 60; x++) {
            unsigned sx = 2 + (uint64_t)x * (width - 4) / 60;
            stw_le_p(scalar_row + x * 2, raw[sy * stride + sx / 2 * 3] ? 4095 : 0);
        }
        for (unsigned x = 0; x < 60; x += 2) {
            unsigned sx = 2 + (uint64_t)x * (width - 4) / 60;
            memset(packed_row + x * 3 / 2, raw[sy * stride + sx / 2 * 3], 3);
        }
        for (unsigned plane = 0; plane < 4; plane++) {
            const uint8_t *data = plane == 3 ? packed_row : scalar_row;
            unsigned bytes = plane == 3 ? sizeof(packed_row) : sizeof(scalar_row);
            if (address_space_write(view, targets[plane] + y * rows[plane],
                                     MEMTXATTRS_UNSPECIFIED, data, bytes) != MEMTX_OK) {
                return false;
            }
        }
    }
    s->processing_grid_count++;
    return true;
}

/* The three observed output units feed DMA channels 3..5. The bounded
 * monochrome raster substitutes for their color/resize operators; report
 * each unit only after that raster has actually reached RAM. This accepts
 * the recovered recipe, not arbitrary processing descriptors or software
 * callback/event fields in the descriptor's final words. */
static uint32_t image_output_results(NikonZ72BootConfig *s,
                                     const uint32_t *widths, const uint32_t *heights)
{
    static const struct {
        unsigned offset, bit, width, height, crop, rows, scale;
    } units[] = {
        {0x9e0, 5, 1920, 1080, 0x400000, 1136, 0x1000100},
        {0x940, 0, 1024, 680, 0x70000, 716, 0x1000100},
        {0xba0, 6, 1024, 680, 0x460000, 716, 0x400040},
    };
    static const struct { unsigned offset; uint32_t value; } profile[] = {
        {0, 0x110a0000}, {8, 0}, {0x10, 0}, {0x14, 0}, {0x18, 0},
        {0x20, 0}, {0x24, 0}, {0x28, 0x11080040},
        {0x38, 0x20002}, {0x3c, 0}, {0x40, 0}, {0x44, 0},
        {0x48, 0x1110080}, {0x4c, 6}, {0x50, 0}, {0x54, 0},
        {0x58, 0xff}, {0x5c, 0}, {0x60, 0xff}, {0x64, 0}, {0x68, 0},
        {0x6c, 0}, {0x70, 0}, {0x74, 0xff}, {0x78, 0}, {0x7c, 0xff},
        {0x80, 0}, {0x84, 0}, {0x88, 0},
    };
    AddressSpace *view = CPU(s->cpu)->as;
    uint8_t registers[24], descriptor[0xa0];
    uint32_t results = 0;

    for (unsigned unit = 0; unit < ARRAY_SIZE(units); unit++) {
        uint32_t source;
        bool supported = true;
        /* Native LCD preview keeps two extra rows in unit 49. The capture
         * caller's other observed profile drops them and sets bit 9. */
        bool lcd_rows = unit == 1 && heights[unit] == 682;

        if (widths[unit] != units[unit].width ||
            heights[unit] != units[unit].height + (lcd_rows ? 2 : 0) ||
            address_space_read(view, 0x20100000 + units[unit].offset,
                               MEMTXATTRS_UNSPECIFIED, registers, sizeof(registers)) != MEMTX_OK ||
            ldl_le_p(registers) || ldl_le_p(registers + 8) != 0x200087e0 ||
            ldl_le_p(registers + 12) != 0x88000 || ldl_le_p(registers + 20)) {
            continue;
        }
        source = ldl_le_p(registers + 16);
        if (!processing_ram_range(view, source, sizeof(descriptor)) ||
            address_space_read(view, source, MEMTXATTRS_UNSPECIFIED,
                               descriptor, sizeof(descriptor)) != MEMTX_OK ||
            ldl_le_p(descriptor + 4) != units[unit].crop ||
            ldl_le_p(descriptor + 12) != (0x10003 + unit) ||
            ldl_le_p(descriptor + 0x1c) != (lcd_rows ? 0xff010000 : 0xff010200) ||
            ldl_le_p(descriptor + 0x2c) != (units[unit].width - 1) << 16 ||
            ldl_le_p(descriptor + 0x30) != (units[unit].rows - 1 + (lcd_rows ? 2 : 0)) << 16 ||
            ldl_le_p(descriptor + 0x34) != units[unit].scale ||
            ldl_le_p(descriptor + 0x94) != ldl_le_p(registers + 8) ||
            ldl_le_p(descriptor + 0x98) != ldl_le_p(registers + 12)) {
            continue;
        }
        for (unsigned index = 0; index < ARRAY_SIZE(profile); index++) {
            if (ldl_le_p(descriptor + profile[index].offset) != profile[index].value) {
                supported = false;
                break;
            }
        }
        if (supported) {
            results |= 1u << units[unit].bit;
        }
    }
    return results;
}

/* Functional monochrome preview for the observed C1.70 stream profile.
 * The 40000000 DMA operand is treated as an internal input stream here;
 * it is not read as a guest RAM pointer. Crop/nearest scaling and NV12 are
 * explicit model assumptions. Accept only full-scale RAW12 pairs, whose
 * packing is unambiguous, and retain the firmware's destination ownership. */
static void input_process_frame(NikonZ72BootConfig *s, uint32_t source,
                                uint32_t width, uint32_t height, uint32_t stride)
{
    AddressSpace *view = CPU(s->cpu)->as;
    uint8_t control[4], descriptors[3][52], addresses[256], input_descriptor[52];
    uint32_t targets[3], uv_targets[3], widths[3], heights[3], strides[3];
    unsigned slot = (s->input_dma_count - 1) & 3;
    size_t raw_length = (size_t)stride * height;
    g_autofree uint8_t *raw = NULL;

    if (!s->frame_process || s->image_draining ||
        width != 1380 || height != 918 || stride != 2080 ||
        !image_preview_input(s, source, width, height, stride) ||
        address_space_read(view, 0x20102100, MEMTXATTRS_UNSPECIFIED, control, 4) != MEMTX_OK ||
        (ldl_le_p(control) & 0xf) != 1 ||
        address_space_read(view, 0x20102608, MEMTXATTRS_UNSPECIFIED, control, 4) != MEMTX_OK ||
        !(ldl_le_p(control) & 1) ||
        address_space_read(view, 0x20100600, MEMTXATTRS_UNSPECIFIED,
                           input_descriptor, 52) != MEMTX_OK ||
        ldl_le_p(input_descriptor) != 0x09000201 ||
        ldl_le_p(input_descriptor + 0x20) != 0x03920560 ||
        address_space_read(view, 0x20102200, MEMTXATTRS_UNSPECIFIED, addresses, 256) != MEMTX_OK ||
        ldl_le_p(addresses + (slot * 16 + 8) * 4) != 0x40000000 ||
        !processing_ram_range(view, source, raw_length)) {
        return;
    }
    /* Validate all three output planes before changing any destination. */
    for (unsigned index = 0; index < 3; index++) {
        uint8_t *d = descriptors[index];
        unsigned channel = index + 3;
        if (address_space_read(view, 0x20100400 + channel * 0x40,
                               MEMTXATTRS_UNSPECIFIED, d, 52) != MEMTX_OK) {
            return;
        }
        widths[index] = ldl_le_p(d + 0x20) & 0xffff;
        heights[index] = ldl_le_p(d + 0x20) >> 16;
        strides[index] = ldl_le_p(d + 0x10);
        targets[index] = ldl_le_p(addresses + (slot * 16 + channel) * 4);
        uint64_t uv = (uint64_t)targets[index] + ldl_le_p(d + 0x28);
        hwaddr y_length = (hwaddr)strides[index] * heights[index];
        if (ldl_le_p(d) != 0x09000201 || !widths[index] || !heights[index] ||
            (widths[index] & 1) || (heights[index] & 1) ||
            widths[index] > 1920 || heights[index] > 1280 ||
            strides[index] < widths[index] || strides[index] > 2048 ||
            ldl_le_p(d + 0x14) != strides[index] ||
            ldl_le_p(d + 0x24) != 0 || ldl_le_p(d + 0x2c) != 0 ||
            ldl_le_p(d + 0x30) != 0 || ldl_le_p(d + 0x28) < y_length ||
            uv > UINT32_MAX || !processing_ram_range(view, targets[index], y_length) ||
            !processing_ram_range(view, uv, y_length / 2)) {
            return;
        }
        uv_targets[index] = uv;
    }
    raw = g_malloc(raw_length);
    if (address_space_read(view, source, MEMTXATTRS_UNSPECIFIED, raw, raw_length) != MEMTX_OK) {
        return;
    }
    for (unsigned y = 0; y < height; y++) {
        for (unsigned x = 0; x < width * 3 / 2; x += 3) {
            uint8_t *pair = raw + y * stride + x;
            if ((pair[0] != 0 && pair[0] != 255) || pair[0] != pair[1] || pair[0] != pair[2]) {
                return;
            }
        }
    }
    for (unsigned index = 0; index < 3; index++) {
        unsigned w = widths[index], h = heights[index], row = strides[index];
        size_t y_length = (size_t)row * h;
        g_autofree uint8_t *pixels = g_malloc(y_length * 3 / 2);
        memset(pixels, 16, y_length);
        memset(pixels + y_length, 128, y_length / 2);
        for (unsigned y = 0; y < h; y++) {
            unsigned sy = 2 + (uint64_t)y * (height - 4) / h;
            for (unsigned x = 0; x < w; x++) {
                unsigned sx = 2 + (uint64_t)x * (width - 4) / w;
                pixels[y * row + x] = raw[sy * stride + (sx / 2) * 3] ? 235 : 16;
            }
        }
        if (address_space_write(view, targets[index], MEMTXATTRS_UNSPECIFIED,
                                 pixels, y_length) != MEMTX_OK ||
            address_space_write(view, uv_targets[index], MEMTXATTRS_UNSPECIFIED,
                                 pixels + y_length, y_length / 2) != MEMTX_OK) {
            return;
        }
    }
    s->processing_dma_count++;
    stl_le_p(s->transfer_table + 0x1c, ldl_le_p(s->transfer_table + 0x1c) |
             image_output_results(s, widths, heights));
    /* Each bank completes only after its own output writes. A rejected grid
     * recipe retains bank0's wait while the independent NV12 bank advances. */
    uint32_t complete = 8;
    if (image_generate_grids(s, raw, width, height, stride, addresses, slot)) {
        complete |= 4;
    }
    stl_le_p(s->transfer_table + 0x20, ldl_le_p(s->transfer_table + 0x20) | complete);
    transfer_update_irq(s);
    /* Native IRQ99 -> 0x102e468a -> 0x42190805. Input was read and
     * monochrome output was written. This is the functional raster model,
     * not a claim that statistics or calibration operators were executed. */
    s->image_interrupt_status[0] |= 0x1002;
    image_update_irqs(s);
}

static void input_raw12_row(uint8_t *row, unsigned width, unsigned start_x,
                            unsigned y, uint64_t phase)
{
    for (unsigned x = 0; x < width; x += 2) {
        uint8_t level = (((start_x + x) / 64 + y / 64 + phase) & 1) ? 0xff : 0;
        memset(row + x * 3 / 2, level, 3);
    }
}

/* Domain 2 names the peer image pool. Decode the aperture locally, then
 * access the receiving engine's RAM rather than the sender's CPU view. */
static bool input_primary_remap(NikonZ72BootConfig *s, uint32_t bus,
                                uint32_t *physical, uint64_t *available)
{
    unsigned matches = 0;

    for (unsigned slot = 0; slot < 8; slot++) {
        const uint8_t *entry = s->transport_table + 0xd0b0 + slot * 4;
        uint32_t target = ldl_le_p(entry);
        uint32_t mask = ldl_le_p(entry + 0x20);
        uint32_t base = ldl_le_p(entry + 0x40);
        uint64_t span;
        uint32_t offset_mask;

        if (!mask || mask > 0xfffff || target > 0xfffff || base > 0xfffff) {
            continue;
        }
        offset_mask = ~(mask << 12);
        span = (uint64_t)offset_mask + 1;
        if ((span & (span - 1)) || (target & ~mask) || (base & ~mask) ||
            (bus & ~offset_mask) != base << 12) {
            continue;
        }
        if (ldl_le_p(entry + 0x60) || ldl_le_p(entry + 0x80)) {
            return false;  /* Extended attributes have not been recovered. */
        }
        *physical = (target << 12) | (bus & offset_mask);
        *available = span - (bus & offset_mask);
        matches++;
    }
    return matches == 1;
}

typedef struct NikonZ72PrimaryWrite {
    uint32_t address;
    uint16_t row;
    uint16_t offset;
    uint16_t length;
} NikonZ72PrimaryWrite;

static void input_generate_primary(NikonZ72BootConfig *s)
{
    uint8_t geometry[20], first[0x70] = { 0 }, second[0x70] = { 0 };
    uint8_t first_row[4224], second_row[8208];
    AddressSpace *view, *peer_view;
    uint32_t first_address, second_bus;
    unsigned index = 0;
    g_autoptr(GArray) writes = NULL;
    const unsigned height = 5520, first_size = 4224 * height;

    if (!s->frame_generate || !s->master_role || !s->sensor_sample ||
        !(s->input_running & 0x400) || !s->peer || s->peer->master_role ||
        !s->transport_link || !s->peer->transport_link) {
        return;
    }
    view = CPU(s->cpu)->as;
    peer_view = CPU(s->peer->cpu)->as;
    if (address_space_read(view, 0x20069500, MEMTXATTRS_UNSPECIFIED,
                           geometry, sizeof(geometry)) != MEMTX_OK ||
        address_space_read(view, 0x20069808, MEMTXATTRS_UNSPECIFIED,
                           first + 8, 4) != MEMTX_OK ||
        address_space_read(view, 0x20069814, MEMTXATTRS_UNSPECIFIED,
                           first + 0x14, 8) != MEMTX_OK ||
        address_space_read(view, 0x2006983c, MEMTXATTRS_UNSPECIFIED,
                           first + 0x3c, 20) != MEMTX_OK ||
        address_space_read(view, 0x20069850, MEMTXATTRS_UNSPECIFIED,
                           first + 0x50, 32) != MEMTX_OK ||
        address_space_read(view, 0x20069908, MEMTXATTRS_UNSPECIFIED,
                           second + 8, 4) != MEMTX_OK ||
        address_space_read(view, 0x20069950, MEMTXATTRS_UNSPECIFIED,
                           second + 0x50, 32) != MEMTX_OK) {
        return;
    }
    /* C1.70's observed 8288 x 5520 RAW12 split: the first 2816 columns
     * have a separate buffer, the remaining 5472 keep the full row stride.
     * Other profiles and address-group rotation remain unsupported. */
    if (ldl_le_p(geometry) != 2 || ldl_le_p(geometry + 4) != (2816u << 16) ||
        ldl_le_p(geometry + 8) != (height << 16) ||
        ldl_le_p(geometry + 12) != 1 || ldl_le_p(geometry + 16) != 5472 ||
        ldl_le_p(first + 8) != 4224 || ldl_le_p(second + 8) != 12432 ||
        ldl_le_p(first + 0x14) != 1 || ldl_le_p(first + 0x18) != 1 ||
        ldl_le_p(first + 0x3c) != 0 || ldl_le_p(first + 0x40) != 1 ||
        ldl_le_p(first + 0x44) != 0 || ldl_le_p(first + 0x48) != 3 ||
        ldl_le_p(first + 0x4c) != 0) {
        return;
    }
    for (unsigned offset = 0x54; offset < 0x70; offset += 4) {
        if (ldl_le_p(first + offset) || ldl_le_p(second + offset)) {
            return;
        }
    }
    first_address = ldl_le_p(first + 0x50);
    second_bus = ldl_le_p(second + 0x50);
    if (first_address < 0x62700000 || !second_bus ||
        (uint64_t)first_address + first_size > 0xac1c5000 ||
        !processing_ram_range(view, first_address, first_size)) {
        return;
    }
    /* Validate the entire remapped second stripe before changing either
     * buffer. Its row gaps belong to the complete-frame buffer's left part. */
    writes = g_array_sized_new(false, false, sizeof(NikonZ72PrimaryWrite), height + 8);
    for (unsigned y = 0; y < height; y++) {
        uint64_t bus = (uint64_t)second_bus + y * 12432;
        unsigned offset = 0;

        while (offset < sizeof(second_row)) {
            uint32_t physical;
            uint64_t available;
            hwaddr translated, span;
            MemoryRegion *region;
            unsigned length;

            if (bus > UINT32_MAX ||
                !input_primary_remap(s, bus, &physical, &available)) {
                return;
            }
            length = MIN(available, sizeof(second_row) - offset);
            /* The matching slave initialization record bounds this pool.
             * Equal numeric addresses in the two engines are independent. */
            if (physical < 0x83900000 ||
                (uint64_t)physical + length > 0xbee86000) {
                return;
            }
            span = length;
            region = address_space_translate(peer_view, physical, &translated, &span,
                                             true, MEMTXATTRS_UNSPECIFIED);
            if (!span || !memory_region_is_ram(region) || memory_region_is_rom(region) ||
                region == &s->stage_ram || region == &s->peer->stage_ram) {
                return;
            }
            length = span;
            NikonZ72PrimaryWrite write = {
                .address = physical, .row = y, .offset = offset, .length = length,
            };
            g_array_append_val(writes, write);
            bus += length;
            offset += length;
        }
    }
    if (s->primary_exposure_sync && !s->primary_exposure_ready) {
        /* Experimental timing: configuration boundaries can precede pixels.
         * Wait for the observed output-16 compare, not a host delay or a
         * firmware state write. Physical sensor wiring is still unverified. */
        if (s->frame_notify) {
            *boot_config_value(s, 0x20068210) |=
                *boot_config_value(s, 0x20068200) & 0x18;
            *boot_config_value(s, 0x20068270) |=
                *boot_config_value(s, 0x20068260) & 0x40000021;
            input_update_irqs(s);
        }
        return;
    }
    for (unsigned y = 0; y < height; y++) {
        input_raw12_row(first_row, 2816, 0, y, s->primary_dma_count);
        input_raw12_row(second_row, 5472, 2816, y, s->primary_dma_count);
        if (address_space_write(view, (hwaddr)first_address + y * 4224,
                                MEMTXATTRS_UNSPECIFIED, first_row,
                                sizeof(first_row)) != MEMTX_OK) {
            return;
        }
        while (index < writes->len &&
               g_array_index(writes, NikonZ72PrimaryWrite, index).row == y) {
            NikonZ72PrimaryWrite *write = &g_array_index(writes, NikonZ72PrimaryWrite, index++);
            if (address_space_write(peer_view, write->address, MEMTXATTRS_UNSPECIFIED,
                                    second_row + write->offset,
                                    write->length) != MEMTX_OK) {
                return;
            }
        }
    }
    s->primary_dma_address = first_address;
    s->primary_second_address = g_array_index(writes, NikonZ72PrimaryWrite, 0).address;
    s->primary_dma_count++;
    s->primary_frame_written = true;
    if (s->frame_notify) {
        /* Both RAW stripes were written. Do not claim statistics output
         * or processing/JPEG completion from this input transfer. */
        *boot_config_value(s, 0x20068210) |= 0x41;
        /* Native reconfiguration waits at b188814c for the enabled input
         * boundaries, including bank 3 bit 30 for this primary stream. */
        *boot_config_value(s, 0x20068210) |=
            *boot_config_value(s, 0x20068200) & 0x18;
        *boot_config_value(s, 0x20068270) |=
            *boot_config_value(s, 0x20068260) & 0x40000021;
        input_update_irqs(s);
    }
}

static void input_generate_frame(NikonZ72BootConfig *s)
{
    uint8_t geometry[12], planes[16], word[4];
    uint32_t width, height, stride, target;
    hwaddr offset, span, length;
    AddressSpace *view;
    MemoryRegion *region;
    g_autofree uint8_t *pixels = NULL;

    if (!s->frame_generate || !s->master_role || !s->sensor_sample ||
        !(s->input_running & 0x200)) {
        return;
    }
    view = CPU(s->cpu)->as;
    if (address_space_read(view, 0x20069514, MEMTXATTRS_UNSPECIFIED,
                           geometry, sizeof(geometry)) != MEMTX_OK ||
        address_space_read(view, 0x20069a08, MEMTXATTRS_UNSPECIFIED,
                           word, sizeof(word)) != MEMTX_OK ||
        address_space_read(view, 0x20069a50, MEMTXATTRS_UNSPECIFIED,
                           planes, sizeof(planes)) != MEMTX_OK) {
        return;
    }
    width = ldl_le_p(geometry + 4) >> 16;
    height = ldl_le_p(geometry + 8) >> 16;
    stride = ldl_le_p(word);
    /* C 1.70's observed RAW12 profile: zero crop origin, even width and
     * a 16-byte-aligned row. Full-scale paired samples avoid relying on
     * unverified nibble order. Other formats remain unsupported. */
    if (ldl_le_p(geometry) != 6 || (ldl_le_p(geometry + 4) & 0xffff) ||
        (ldl_le_p(geometry + 8) & 0xffff) || !width || (width & 1) ||
        width > 8192 || !height || height > 8192 ||
        stride != ((width * 3 / 2 + 15) & ~15u)) {
        return;
    }
    length = (hwaddr)stride * height;
    target = ldl_le_p(planes + (s->input_dma_count & 3) * 4);
    if (!target || length > 0x1000000 || (uint64_t)target + length > UINT32_MAX) {
        return;
    }
    /* Validate the complete destination before writing any pixels. A frame
     * must fit within one writable RAM backing, never a peripheral window. */
    span = length;
    region = address_space_translate(view, target, &offset, &span, true,
                                    MEMTXATTRS_UNSPECIFIED);
    if (!memory_region_is_ram(region) || memory_region_is_rom(region) || span < length) {
        return;
    }
    pixels = g_malloc0(length);
    for (unsigned y = 0; y < height; y++) {
        input_raw12_row(pixels + y * stride, width, 0, y, s->input_dma_count);
    }
    if (address_space_write(view, target, MEMTXATTRS_UNSPECIFIED,
                            pixels, length) == MEMTX_OK) {
        s->input_dma_address = target;
        s->input_dma_count++;
        input_process_frame(s, target, width, height, stride);
        if (s->frame_notify) {
            /* Recovered frame timing / queued-output input causes. Keep
             * this opt-in until native buffer ownership is fully verified. */
            *boot_config_value(s, 0x20068210) |= 0x41 |
                (*boot_config_value(s, 0x20068200) & 0x18);
            /* Input reconfiguration waits for these enabled boundary
             * causes at b188814c. They follow the completed RAW transfer;
             * they do not claim auxiliary output buffers were written. */
            *boot_config_value(s, 0x20068270) |=
                *boot_config_value(s, 0x20068260) & 0x21;
            *boot_config_value(s, 0x20068290) |=
                *boot_config_value(s, 0x20068280) & 0x80;
            input_update_irqs(s);
        }
    }
}

/* Bounded startup-only sensor grid. The native constructor establishes the
 * u16 pitch and the analysis registers establish the 30x12 view. Sampling
 * the laboratory checker at cell centres is a functional approximation;
 * numeric normalization and the general ring protocol remain unverified.
 * Only the observed two selected-bank configurations are accepted. */
static void input_generate_startup_grid(NikonZ72BootConfig *s)
{
    AddressSpace *view = CPU(s->cpu)->as;
    uint8_t grid[24], output[132] = {0}, row[60];
    static const uint32_t recipe[] = {3, 0x50787, 16, 6, 0x1044, 0xc1e};
    static const unsigned registers[] = {0x14, 0x18, 0x24, 0x3c, 0x40,
                                          0x44, 0x48, 0x4c, 0x50, 0x60, 0x80};
    uint32_t target, selection, extent;

    if (!s->auto_complete || !s->master_role || !s->sensor_sample ||
        !s->frame_generate || !(s->input_running & 0x10) || s->input_grid_phase >= 2 ||
        address_space_read(view, 0x2006a2bc, MEMTXATTRS_UNSPECIFIED, grid, sizeof(grid)) != MEMTX_OK) {
        return;
    }
    for (unsigned index = 0; index < G_N_ELEMENTS(registers); index++) {
        unsigned offset = registers[index];
        if (address_space_read(view, 0x2006a500 + offset, MEMTXATTRS_UNSPECIFIED,
                               output + offset, 4) != MEMTX_OK) {
            return;
        }
    }
    for (unsigned index = 0; index < G_N_ELEMENTS(recipe); index++) {
        if ((uint32_t)ldl_le_p(grid + index * 4) != recipe[index]) {
            return;
        }
    }
    selection = ldl_le_p(output + 0x3c);
    extent = ldl_le_p(output + 0x80);
    target = ldl_le_p(output + 0x50 + s->input_grid_phase * 0x10);
    if (ldl_le_p(output + 0x14) != 3 || ldl_le_p(output + 0x18) != 1 ||
        ldl_le_p(output + 0x24) || ldl_le_p(output + 0x40) != 1 ||
        ldl_le_p(output + 0x44) || ldl_le_p(output + 0x48) != 60 ||
        ldl_le_p(output + 0x4c) || selection != s->input_grid_phase ||
        extent != (s->input_grid_phase ? 0 : 0x12000) ||
        (s->input_grid_phase && target != s->input_grid_address) ||
        ldl_le_p(output + 0x50) != ldl_le_p(output + 0x60) ||
        !processing_ram_range(view, target, s->input_grid_phase ? 768 : 61 * 0x12000) ||
        (target < 0xbb300000 && (uint64_t)target + 768 > 0xbaa00000)) {
        return;
    }
    /* The active view occupies 768 bytes inside a larger allocation block.
     * Preserve row padding and all other storage in that allocation. */
    for (unsigned y = 0; y < 12; y++) {
        unsigned sy = 6 + y * 4 + 2;
        for (unsigned x = 0; x < 30; x++) {
            unsigned sx = 16 + x * 68 + 34;
            unsigned level = ((sx / 64 + sy / 64 + s->frame_sync_count) & 1) ? 4095 : 0;
            stw_le_p(row + x * 2, level);
        }
        if (address_space_write(view, target + y * 64, MEMTXATTRS_UNSPECIFIED,
                                row, sizeof(row)) != MEMTX_OK) {
            return;
        }
    }
    s->input_grid_address = target;
    s->input_grid_count++;
    s->input_grid_phase++;
    if (s->frame_notify) {
        *boot_config_value(s, 0x20068270) |= 0x80;
        input_update_irqs(s);
    }
}

static void frame_sync_tick(void *opaque)
{
    NikonZ72BootConfig *s = opaque;

    input_generate_primary(s);
    input_generate_frame(s);
    input_generate_startup_grid(s);
    *boot_config_value(s, 0x20060044) |= 0x10;
    if (s->sensor_sample) {
        if (s->frame_phase && (*boot_config_value(s, 0x20060040) & 0x80)) {
            *boot_config_value(s, 0x20060044) |= 0x80;
        }
        /* The third bank's sample-ready bit drives the auto-sample event
         * without claiming pixel data is available in bank 1; a separate
         * "sample-group1" property latches the vertical-sync line only. */
        *boot_config_value(s, 0x20060050) |= 0x01;
        if (s->sample_group1) {
            *boot_config_value(s, 0x20060038) |= 0x01;
        }
        for (unsigned index = 0; index < 5; index++) {
            *boot_config_value(s, 0x20061300 + index * 4) =
                s->sample_counter && index == 0 ?
                (uint32_t)s->frame_sync_count : s->sample_lines;
        }
        /* With the sample source armed, also re-arm the sampling
         * configuration the original firmware clears when the menu
         * opens; a running sensor would cause the restart path to
         * rewrite this word after each pause. */
        if (!*boot_config_value(s, 0x20061000) && s->frame_sync_count > 4) {
            *boot_config_value(s, 0x20061000) = 0xffff;
        }
    }
    if (s->display_complete && s->display_complete_irq[0]) {
        /* The original handler acknowledges and counts both edges; the
         * level returns to zero so the next frame latches again. */
        for (unsigned line = 0; line < 2; line++) {
            qemu_set_irq(s->display_complete_irq[line], 1);
            qemu_set_irq(s->display_complete_irq[line], 0);
        }
    }
    s->frame_sync_count++;
    sync_update_irqs(s);
    timer_mod(s->frame_sync_timer,
              qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 33333333);
}

static void frame_sync_enable(void *opaque, int line, int level)
{
    NikonZ72BootConfig *s = opaque;

    if (!level) {
        timer_del(s->frame_sync_timer);
    } else if (s->frame_sync && s->master_role &&
               !timer_pending(s->frame_sync_timer)) {
        timer_mod(s->frame_sync_timer,
                  qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 33333333);
    }
}

/* Append one sampling-synchronization / input-path access to the
 * bounded diagnostic ring. The ring keeps the newest accesses so a
 * probe can compare windows across a menu cycle without reading the
 * trace continuously. */
static void boot_config_trace(NikonZ72BootConfig *s, hwaddr address,
                              uint32_t value, bool is_write)
{
    if (!s->input_trace ||
        address < 0x20060000 || address >= 0x20070000) {
        return;
    }
    unsigned slot = s->input_trace_count % 256;
    s->input_trace_addresses[slot] = address;
    s->input_trace_values[slot] = value;
    s->input_trace_writes[slot] = is_write;
    s->input_trace_count++;
}

static uint64_t boot_config_read(void *opaque, hwaddr offset, unsigned size)
{
    NikonZ72ConfigWord *word = opaque;
    uint32_t value = word->device->values[word->index];
    NikonZ72BootConfig *s = word->device;
    if (boot_config_addresses[word->index] == 0x04282014) {
        uint32_t mask = (s->gpio_input_driven & 0x1ff) << 7;
        value = (value & ~mask) | ((s->gpio_input_levels << 7) & mask);
    } else if (boot_config_addresses[word->index] == 0x04282018) {
        uint32_t mask = (s->gpio_input_driven >> 9) & 0x7f;
        value = (value & ~mask) | ((s->gpio_input_levels >> 9) & mask);
    }
    if (s->controller_connected) {
        hwaddr address = boot_config_addresses[word->index];
        if (address == 0x04282014) {
            value = (value & ~0x600u) | ((s->controller_levels & 3) << 9);
        } else if (address == 0x04282018) {
            value = (value & ~0x9000u) | ((s->controller_levels & 4) << 13) |
                    (s->controller_ack_output ? 0x1000 : 0);
        }
    }
    if (s->peer_connected &&
        boot_config_addresses[word->index] == peer_ready_address(s)) {
        uint32_t bit = 1u << peer_ready_bit(s);
        value = (value & ~bit) |
                ((s->peer_gpio && s->peer_ready_input) ? bit : 0);
    }
    /* The gate sequence polls bit 0 of 0x04287004 before acknowledging.
     * The laboratory reports it ready synchronously; real timing and
     * hardware completion causes remain unconfirmed. */
    if (boot_config_addresses[word->index] == 0x04287004 ||
        boot_config_addresses[word->index] == 0x20010038) {
        value |= 1;
    }
    /* Firmware analysis recovered the original link poll: 0x1008b32e
     * checks bits 16..21 of the link status for the trained state 0x11
     * for up to 500 sleep units. The optional link profiles report the
     * trained state so the original initialization can proceed; only the
     * SD-host profile also supplies an endpoint window. */
    if ((s->pcie_link || s->sd_host) &&
        boot_config_addresses[word->index] == 0x2b200058) {
        value = (value & ~0x3f0000u) | 0x110000u;
    }
    if (s->sd_host && boot_config_addresses[word->index] == 0x2b200024) {
        value = (value & ~(1u << 28)) | (s->sd_irq_level ? 1u << 28 : 0);
    }
    /* The firmware polls the input-path status word 0x20068060 on every
     * frame period; a running sensor interface would latch a ready
     * pattern here so the capture initialization can proceed. */
    if (boot_config_addresses[word->index] == 0x20068060) {
        value |= 0x1;
    }
    /* Diagnostic: log reads from the input-path configuration region so
     * the firmware's sensor-interface polling can be traced. */
    if (boot_config_addresses[word->index] >= 0x20068000 &&
        boot_config_addresses[word->index] <= 0x20068300) {
        s->frame_count++;
        s->input_last_read = boot_config_addresses[word->index];
    }
    boot_config_trace(s, boot_config_addresses[word->index], value, false);
    return value;
}

static void boot_config_write(void *opaque, hwaddr offset,
                              uint64_t value, unsigned size)
{
    NikonZ72ConfigWord *word = opaque;
    NikonZ72BootConfig *s = word->device;
    hwaddr address = boot_config_addresses[word->index];
    uint32_t *stored = &s->values[word->index];
    boot_config_trace(s, address, (uint32_t)value, true);
    if (s->sd_host && address == 0x2b200024) {
        /* INTA follows its source. A status acknowledgement cannot clear
         * an asserted source or create an interrupt while it is low. */
        *stored = (uint32_t)value & ~(1u << 28);
        return;
    }
    if (address == 0x20060038 || address == 0x20060044 ||
        address == 0x20060050) {
        *stored &= ~(uint32_t)value;
        sync_update_irqs(s);
        return;
    }
    /* The sampled result window is latched state: the readout only reads
     * it, and no laboratory source writes sampled line values yet. */
    if (address >= 0x20061300 && address <= 0x20061370) {
        return;
    }
    if (address == 0x2b200058 || address == 0x2b20005c) {
        return;
    }
    if (address == 0x2006807c || address == 0x20068084 ||
        address == 0x20068140 || address == 0x20068144) {
        return;
    }
    /* The native enable command changes running channels. Interrupt masks
     * remain owned by the firmware's separate mask-register writes. */
    if (address == 0x20068008 && value) {
        *stored = (uint32_t)value;
        if ((value & 0x10) && !(s->input_running & 0x10)) {
            s->input_grid_phase = 0;
        }
        if ((value & 0x400) && !(s->input_running & 0x400)) {
            s->primary_frame_written = false;
            s->primary_exposure_ready = false;
        }
        s->input_running |= value;
        input_update_irqs(s);
        return;
    }
    if (address == 0x2006800c) {
        uint32_t disabled = s->input_running & (uint32_t)value;

        /* The source completes transfers synchronously. Report only actual
         * enabled-to-disabled transitions, using the native disable-end
         * causes (distinct from the hard-stop/flush causes at 0x68060). */
        *stored = (uint32_t)value;
        s->input_running &= ~(uint32_t)value;
        if (s->input_stop_complete && s->master_role && s->sensor_sample &&
            s->auto_complete) {
            uint32_t first = 0, second = 0;

            if (disabled & 1) { first |= 1u << 9; }
            if (disabled & 4) { first |= 1u << 13; }
            if (disabled & 8) { first |= 1u << 15; }
            if (disabled & 0x10) { first |= 1u << 31; }
            if (disabled & 0x20) { first |= 1u << 27; }
            if (disabled & 0x40) { first |= 1u << 17; }
            if (disabled & 0x80) { first |= 1u << 19; }
            if (disabled & 0x200) { second |= 1u << 7; }
            if (disabled & 0x400) { second |= 1u << 3; }
            /* The native finite stop arms bank 0 bit 7 at 102389fa before
             * disabling input. End only a primary frame actually written in
             * this run; the per-channel disable acknowledgement is separate. */
            if ((disabled & 0x400) && s->primary_frame_written && s->frame_notify) {
                first |= *boot_config_value(s, 0x20068200) & 0x80;
            }
            if (disabled & 0x800) { second |= 1u << 11; }
            *boot_config_value(s, 0x20068210) |= first;
            *boot_config_value(s, 0x20068230) |= second;
            /* This channel ends through its own task event, independently
             * of the other channels' aggregate disable pending word. */
            if (disabled & 2) {
                *boot_config_value(s, 0x200682f0) |= 8;
            }
            input_update_irqs(s);
        }
        if (value & 0x400) {
            s->primary_frame_written = false;
            s->primary_exposure_ready = false;
        }
        return;
    }
    if (address == 0x20068000 || address == 0x20068004 ||
        address == 0x20068010 || address == 0x20068014) {
        hwaddr base = address & ~0x4u;
        uint32_t *state = boot_config_value(s, base);
        bool set = address == 0x20068004 || address == 0x20068010;
        *state = set ? *state | (uint32_t)value : *state & ~(uint32_t)value;
        *boot_config_value(s, base + 4) = *state;
        return;
    }
    if (address >= 0x20068210 && address <= 0x200682f0 &&
        (address & 0x1f) == 0x10) {
        *stored &= ~(uint32_t)value;
        input_update_irqs(s);
        return;
    }
    if (s->controller_connected) {
        if (address == 0x04282018 && (value & (1u << 28))) {
            s->controller_ack_output = !!(value & 0x1000);
            qemu_set_irq(s->controller_ack_irq, s->controller_ack_output);
        }
    }
    if (address == 0x04282018 && (value & (1u << 24))) {
        bool level = !!(value & (1u << 8));

        if (level && !s->input_handshake_output && s->input_handshake &&
            s->auto_complete && s->master_role &&
            !timer_pending(s->input_handshake_timer)) {
            timer_mod(s->input_handshake_timer,
                      qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 1000000);
        }
        s->input_handshake_output = level;
        qemu_set_irq(s->controller_step_irq, level);
    }
    if (address == 0x0426f008) {
        *stored = (value & ~0xffffu) | (*stored & 0xffff);
        return;
    }
    if (address == 0x0426f010) {
        *boot_config_value(s, 0x0426f008) &= ~(value & 0xffffu);
        *stored = value;
        controller_update_irqs(s);
        return;
    }
    /* The upper half selects output bits to update. A connected engine's
     * communication-ready output drives its peer's corresponding input. */
    if (s->peer_connected && address == peer_ready_address(s)) {
        unsigned bit = peer_ready_bit(s);
        if (value & (1u << (bit + 16))) {
            s->peer_ready_output = (value & (1u << bit)) != 0;
            qemu_set_irq(s->peer_ready_irq,
                         s->peer_gpio && s->peer_ready_output);
        }
    }
    if (address == 0x04287004 && (value & 1)) {
        s->gate_pending = false;
        if (s->intc) {
            qemu_set_irq(qdev_get_gpio_in(s->intc, 250 - 32), 0);
        }
    }
    if (address == 0x04287010 && value == 0xa1 &&
        s->release_config && s->gate_completion &&
        (ldl_le_p(s->gate_table + 8) & 1)) {
        uint32_t control = *boot_config_value(s, 0x04287000);
        uint32_t bank = (control >> 12) & 7;
        uint32_t status = ldl_le_p(s->gate_table + 0xc);
        status = (control & 0x100) ? status | (1u << bank) :
                                    status & ~(1u << bank);
        stl_le_p(s->gate_table + 0xc, status);
        s->gate_pending = true;
        qemu_set_irq(qdev_get_gpio_in(s->intc, 250 - 32), 1);
    }
    if (address == 0x2003016c || address == 0x2005016c) {
        return; /* Result word is read-only; zero is the success assumption. */
    }
    for (unsigned i = 0; i < G_N_ELEMENTS(boot_completions); i++) {
        const NikonZ72Completion *c = &boot_completions[i];
        if (address == c->status) {
            *stored &= ~(uint32_t)value;
            return;
        }
        if (address == c->control) {
            bool accepted = c->maximum_phase ?
                (value & 0xffff) == c->command &&
                (value >> 16) <= c->maximum_phase : value == c->command;
            *stored = value;
            *boot_config_value(s, c->status) = accepted && s->auto_complete &&
                address != s->blocked_control ? 1 : 0;
            return;
        }
    }
    *stored = value;
    if ((address >= 0x20060000 && address <= 0x20060028) ||
        (address >= 0x200630d0 && address <= 0x20063134)) {
        sampling_output_write(s, address, value);
    }
    if (address == 0x20068060) {
        switch (value) {
        case 3:
            s->input_running &= ~0x600u;
            s->primary_frame_written = false;
            s->primary_exposure_ready = false;
            break;
        case 4: s->input_running &= ~0x10u; break;
        case 8: s->input_running &= ~0x20u; break;
        case 0x10: s->input_running &= ~0x800u; break;
        case 0x60: s->input_running &= ~2u; break;
        }
    }
    if (address == 0x20068060 && s->input_stop_complete && s->master_role &&
        s->sensor_sample && s->auto_complete) {
        /* Recovered stop requests enable these status causes before writing
         * the command. The laboratory input source has no in-flight DMA;
         * quiesce it synchronously and use the normal mask/acknowledge path.
         * These causes release stop waiters, not pixel-ready consumers. */
        switch (value) {
        case 3:
            *boot_config_value(s, 0x20068230) |= 0x110;
            break;
        case 4:
            *boot_config_value(s, 0x20068230) |= 1;
            break;
        case 8:
            *boot_config_value(s, 0x20068210) |= 0x10000000;
            break;
        case 0x10:
            *boot_config_value(s, 0x20068230) |= 0x1000;
            break;
        case 0x60:
            *boot_config_value(s, 0x200682f0) |= 0x30;
            break;
        }
        input_update_irqs(s);
    }
    if (address == 0x200632e4 && (value & 1) && s->master_role &&
        s->sensor_sample && s->auto_complete) {
        /* The laboratory sampling source applies the recovered control
         * batches synchronously. C 1.70 submits 0x107 before waiting for
         * group 2 bit 10, or 0x101 before waiting for bit 18. Consume only
         * the supported batch bits; unrelated request bits stay pending.
         * These are configuration completions, not pixel DMA events. */
        uint32_t *request = boot_config_value(s, 0x200632e0);
        uint32_t accepted = 0;
        uint32_t completion = 0;

        if ((*request & 0x107) == 0x107) {
            accepted = 0x107;
            completion = 1u << 10;
        } else if ((*request & 0x101) == 0x101) {
            accepted = 0x101;
            completion = 1u << 18;
        }
        *request &= ~accepted;
        *boot_config_value(s, 0x20060044) |= completion;
        sync_update_irqs(s);
    }
    if (address == 0x20060034 || address == 0x20060040 ||
        address == 0x2006004c) {
        sync_update_irqs(s);
    }
    if (address >= 0x20068200 && address <= 0x200682e0 &&
        (address & 0x1f) == 0) {
        input_update_irqs(s);
    }
    if (address == 0x0426f000) {
        controller_update_irqs(s);
    }
}

static const MemoryRegionOps boot_config_ops = {
    .read = boot_config_read,
    .write = boot_config_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4 },
    .impl = { .min_access_size = 4, .max_access_size = 4 },
};

/* One sparse decode region avoids exhausting the address-space section
 * table while retaining faults for unobserved neighboring words. */
static bool auxiliary_accepts(void *opaque, hwaddr offset, unsigned size,
                              bool is_write, MemTxAttrs attrs)
{
    if (size != 4 || (offset & 3)) {
        return false;
    }
    hwaddr address = 0x20060000 + offset;
    for (unsigned i = 0; i < BOOT_CONFIG_WORDS; i++) {
        if (boot_config_addresses[i] == address) {
            return true;
        }
    }
    return false;
}

static uint64_t auxiliary_read(void *opaque, hwaddr offset, unsigned size)
{
    NikonZ72BootConfig *s = opaque;
    unsigned index = boot_config_index_of(0x20060000 + offset);
    return boot_config_read(&s->words[index], 0, size);
}

static void auxiliary_write(void *opaque, hwaddr offset, uint64_t value,
                            unsigned size)
{
    NikonZ72BootConfig *s = opaque;
    unsigned index = boot_config_index_of(0x20060000 + offset);
    boot_config_write(&s->words[index], 0, value, size);
}

static const MemoryRegionOps auxiliary_ops = {
    .read = auxiliary_read,
    .write = auxiliary_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4,
               .accepts = auxiliary_accepts },
    .impl = { .min_access_size = 4, .max_access_size = 4 },
};

static uint64_t snapshot_source_read(void *opaque, hwaddr offset, unsigned size)
{
    NikonZ72BootConfig *s = opaque;
    uint64_t value = 0;
    memcpy(&value, s->snapshot_table + offset, size);
    return value;
}

static void snapshot_source_write(void *opaque, hwaddr offset,
                                  uint64_t value, unsigned size)
{
    NikonZ72BootConfig *s = opaque;
    memcpy(s->snapshot_table + offset, &value, size);
}

/* The stock setup reads the 512-word table in word units and never writes it
 * through this window; stores stay accepted for completeness. Content origin
 * in hardware is unconfirmed, so the laboratory exposes a zero table. */
static const MemoryRegionOps snapshot_source_ops = {
    .read = snapshot_source_read,
    .write = snapshot_source_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4 },
    .impl = { .min_access_size = 4, .max_access_size = 4 },
};

static uint64_t mirror_read(void *opaque, hwaddr offset, unsigned size)
{
    NikonZ72BootConfig *s = opaque;
    uint64_t value = 0;
    memcpy(&value, s->mirror_table + offset, size);
    return value;
}

static void mirror_write(void *opaque, hwaddr offset,
                         uint64_t value, unsigned size)
{
    NikonZ72BootConfig *s = opaque;
    memcpy(s->mirror_table + offset, &value, size);
}

/* Eight 0x100-byte regions observed as a table in later drivers; the tail
 * copy fills them before returning to the initializer chain. */
static const MemoryRegionOps mirror_ops = {
    .read = mirror_read,
    .write = mirror_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4 },
    .impl = { .min_access_size = 4, .max_access_size = 4 },
};

/* Peer-descriptor contract of the release-path register file: the local
 * engine posts its own descriptor (+0x30) and then polls the peer-ready
 * word (+0x2C). The laboratory answers ready once the local descriptor is
 * posted; real peer timing and content remain unconfirmed. */
static uint64_t file_read(void *opaque, hwaddr offset, unsigned size)
{
    NikonZ72BootConfig *s = opaque;
    uint32_t value;
    memcpy(&value, s->file_table+offset, 4);
    if (offset == 0x2C && s->file_posted[0x30]) {
        value = 1;

    }
    return value;
}

static void file_write(void *opaque, hwaddr offset, uint64_t value, unsigned size)
{
    NikonZ72BootConfig *s = opaque;
    memcpy(s->file_table+offset, &value, size);
    if (offset + size <= sizeof(s->file_table)) {
        for (unsigned i = 0; i < size; i++) {
            s->file_posted[offset+i] = true;
        }
    }
}

static const MemoryRegionOps file_ops = {
    .read = file_read,
    .write = file_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4 },
    .impl = { .min_access_size = 4, .max_access_size = 4 },
};

/* Paired set/clear descriptor registers: the +0x100 partners
 * (0x04281238..0x0428124C) of the registered 0x042811xx words, walked by
 * the kernel after the peer release. Only the partner half is covered so a
 * disabled controller chain keeps its unmapped first-store boundary. */
static uint64_t pair_read(void *opaque, hwaddr offset, unsigned size)
{
    NikonZ72BootConfig *s = opaque;
    uint64_t value = 0;
    memcpy(&value, s->pair_table + offset, size);
    return value;
}

static void pair_write(void *opaque, hwaddr offset, uint64_t value, unsigned size)
{
    NikonZ72BootConfig *s = opaque;
    memcpy(s->pair_table + offset, &value, size);
}

static const MemoryRegionOps pair_ops = {
    .read = pair_read,
    .write = pair_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4 },
    .impl = { .min_access_size = 4, .max_access_size = 4 },
};

static void seq_update_irqs(NikonZ72BootConfig *s)
{
    for (unsigned channel = 0; channel < 4; channel++) {
        uint32_t status = ldl_le_p(s->seq_table + 0x1030 + channel * 0x30);
        qemu_set_irq(qdev_get_gpio_in(s->intc, 45 + channel - 32),
                     (status & 0xf) != 0);
    }
}

/* Incrementing memory channels encode byte count minus one, source and
 * destination in their first three words. Transfer through the engine's
 * physical address space so firmware page-table changes do not affect DMA. */
static bool seq_transfer(NikonZ72BootConfig *s, unsigned channel)
{
    const uint8_t *regs = s->seq_table + 0x1010 + channel * 0x30;
    uint64_t length = (uint64_t)(uint32_t)ldl_le_p(regs) + 1;
    hwaddr source = (uint32_t)ldl_le_p(regs + 4);
    hwaddr destination = (uint32_t)ldl_le_p(regs + 8);
    uint8_t buffer[4096];
    AddressSpace *view = CPU(s->cpu)->as;

    /* Bound synchronous work and reject the fixed-address peripheral modes
     * until their individual bus contracts are implemented. */
    if (length > 0x1000000 || (ldl_le_p(regs + 12) & 1) ||
        (ldl_le_p(regs + 16) & 1) || source + length > UINT32_MAX ||
        destination + length > UINT32_MAX) {
        return false;
    }
    while (length) {
        unsigned chunk = MIN(length, sizeof(buffer));
        hwaddr source_offset, destination_offset;
        hwaddr source_span = chunk, destination_span = chunk;
        MemoryRegion *source_region = address_space_translate(view, source,
            &source_offset, &source_span, false, MEMTXATTRS_UNSPECIFIED);
        MemoryRegion *destination_region = address_space_translate(view,
            destination, &destination_offset, &destination_span, true,
            MEMTXATTRS_UNSPECIFIED);

        if (!memory_region_is_ram(source_region) ||
            !memory_region_is_ram(destination_region) ||
            memory_region_is_rom(destination_region)) {
            return false;
        }
        chunk = MIN(chunk, MIN(source_span, destination_span));
        if (!chunk) {
            return false;
        }
        if (address_space_read(view, source, MEMTXATTRS_UNSPECIFIED,
                               buffer, chunk) != MEMTX_OK ||
            address_space_write(view, destination, MEMTXATTRS_UNSPECIFIED,
                                buffer, chunk) != MEMTX_OK) {
            return false;
        }
        source += chunk;
        destination += chunk;
        length -= chunk;
    }
    return true;
}

static uint64_t seq_read(void *opaque, hwaddr offset, unsigned size)
{
    NikonZ72BootConfig *s = opaque;
    uint64_t value = 0;
    memcpy(&value, s->seq_table + offset, size);
    return value;
}

static void seq_write(void *opaque, hwaddr offset, uint64_t value, unsigned size)
{
    NikonZ72BootConfig *s = opaque;
    memcpy(s->seq_table + offset, &value, size);
    if (s->master_role && s->sequencer_completion && size == 4) {
        for (unsigned channel = 0; channel < 4; channel++) {
            hwaddr command = 0x1028 + channel * 0x30;
            if (offset == command && (value & 0x10000003) == 0x10000003) {
                uint32_t status = ldl_le_p(s->seq_table + command + 8);
                bool success = seq_transfer(s, channel);
                stl_le_p(s->seq_table + command + 8,
                         (status & ~0xfu) | (success ? 8 : 1));
            }
        }
        seq_update_irqs(s);
    }
}

static const MemoryRegionOps seq_ops = {
    .read = seq_read,
    .write = seq_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4 },
    .impl = { .min_access_size = 4, .max_access_size = 4 },
};

/* Runtime gate requests select a bank in bits 12..14 of the control word.
 * The completion handler acknowledges bit 0 at +4 and signals its event
 * object. Keep the completed bank bits at +0xc for subsequent users. */
static uint64_t gate_read(void *opaque, hwaddr offset, unsigned size)
{
    NikonZ72BootConfig *s = opaque;
    uint64_t value = 0;
    memcpy(&value, s->gate_table + offset, size);
    return value;
}

static void gate_write(void *opaque, hwaddr offset, uint64_t value, unsigned size)
{
    NikonZ72BootConfig *s = opaque;
    memcpy(s->gate_table + offset, &value, size);
}

static const MemoryRegionOps gate_ops = {
    .read = gate_read,
    .write = gate_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4 },
    .impl = { .min_access_size = 4, .max_access_size = 4 },
};

static void transfer_update_irq(NikonZ72BootConfig *s)
{
    uint32_t status = ldl_le_p(s->transfer_table + 0x18) |
                      ldl_le_p(s->transfer_table + 0x1c) |
                      ldl_le_p(s->transfer_table + 0x20);
    qemu_set_irq(qdev_get_gpio_in(s->intc, 102 - 32), status != 0);
}

static uint64_t transfer_read(void *opaque, hwaddr offset, unsigned size)
{
    NikonZ72BootConfig *s = opaque;
    return ldl_le_p(s->transfer_table + offset);
}

static void transfer_write(void *opaque, hwaddr offset, uint64_t value,
                           unsigned size)
{
    NikonZ72BootConfig *s = opaque;
    if (offset == 0x18 || offset == 0x1c || offset == 0x20) {
        /* The original shared handler acknowledges each status word by
         * writing the observed bits back before dispatching callbacks. */
        stl_le_p(s->transfer_table + offset,
                 ldl_le_p(s->transfer_table + offset) & ~(uint32_t)value);
    } else {
        stl_le_p(s->transfer_table + offset, value);
        if (offset == 4 && value == 0 && s->transfer_reset_completion) {
            /* Reset request: the shared handler maps status bit 0 at
             * +0x18 to callback bit 0, which signals the reset wait.
             * Data transfers remain unmodeled. */
            stl_le_p(s->transfer_table + 0x18,
                     ldl_le_p(s->transfer_table + 0x18) | 1);
        }
    }
    transfer_update_irq(s);
}

static const MemoryRegionOps transfer_ops = {
    .read = transfer_read,
    .write = transfer_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4 },
    .impl = { .min_access_size = 4, .max_access_size = 4 },
};

static void transport_update_irq(NikonZ72BootConfig *s)
{
    uint32_t pending = ldl_le_p(s->transport_table + 0xd020);
    uint32_t enabled = ldl_le_p(s->transport_table + 0xd024);
    /* Notification events latch at submission and are acknowledged by the
     * native handler at +0xd028. Message bits remain available separately
     * until the receiver clears them through its remote status view. */
    qemu_set_irq(qdev_get_gpio_in(s->intc, 127 - 32),
                 (pending & enabled) != 0);
}

static uint64_t transport_read(void *opaque, hwaddr offset, unsigned size)
{
    NikonZ72BootConfig *s = opaque;
    if (s->peer && (offset == 0xe000 || offset == 0xe004)) {
        return ldl_le_p(s->peer->transport_table + 0x6000);
    }
    if (offset == 0x6004) {
        /* The native receiver consumes the second status word. Both
         * status views expose the pending set/clear bits; independent
         * notification masking has not yet been recovered. */
        return ldl_le_p(s->transport_table + 0x6000);
    }
    return ldl_le_p(s->transport_table + offset);
}

static void transport_write(void *opaque, hwaddr offset, uint64_t value,
                            unsigned size)
{
    NikonZ72BootConfig *s = opaque;
    if (offset == 0x6008 || offset == 0x600c ||
        offset == 0xe008 || offset == 0xe00c) {
        NikonZ72BootConfig *owner = offset >= 0xe000 ? s->peer : s;
        if (owner) {
            uint32_t pending = ldl_le_p(owner->transport_table + 0x6000);
            pending = (offset & 4) ? pending & ~(uint32_t)value :
                                    pending | (uint32_t)value;
            stl_le_p(owner->transport_table + 0x6000, pending);
            if (!(offset & 4) && value && owner->peer &&
                owner->transport_link && owner->peer->transport_link) {
                NikonZ72BootConfig *receiver = owner->peer;
                stl_le_p(receiver->transport_table + 0xd020,
                         ldl_le_p(receiver->transport_table + 0xd020) | 0x8000);
                transport_update_irq(receiver);
            }
            if (owner->peer) {
                transport_update_irq(owner->peer);
            }
        }
        return;
    }
    if (offset == 0xd020) {
        return;
    }
    if (offset == 0xd028) {
        stl_le_p(s->transport_table + 0xd020,
                 ldl_le_p(s->transport_table + 0xd020) & ~(uint32_t)value);
    } else {
        stl_le_p(s->transport_table + offset, value);
    }
    if (offset == 0x4128 || offset == 0xc128) {
        /* Stop masks select transmit lanes in bits 0..3 and receive lanes
         * in bits 12..15. With no in-flight lane transaction, the native
         * stop poll observes state 3 in the per-lane status word. */
        for (unsigned lane = 0; lane < 4; lane++) {
            if (value & (1u << lane)) {
                stl_le_p(s->transport_table + 0x8104 + lane * 0x400, 3);
            }
            if (value & (1u << (lane + 12))) {
                stl_le_p(s->transport_table + 0x8304 + lane * 0x400, 3);
            }
        }
    }
    /* The initiator submits 6; the responder waits for event 1 before
     * submitting 4. The latter completes event 2 on both endpoints.
     * This functional link models the recovered startup exchange only. */
    if (s->peer && s->transport_link && s->peer->transport_link &&
        (offset == 0xc90c || offset == 0xc13c)) {
        NikonZ72BootConfig *peer = s->peer;
        if (offset == 0xc90c && s->master_role && value == 6) {
            stl_le_p(peer->transport_table + 0xd020,
                     ldl_le_p(peer->transport_table + 0xd020) | 1);
        } else if (offset == 0xc90c && !s->master_role && value == 4 &&
                   ldl_le_p(peer->transport_table + 0xc90c) == 6) {
            stl_le_p(s->transport_table + 0xd020,
                     ldl_le_p(s->transport_table + 0xd020) | 2);
            stl_le_p(peer->transport_table + 0xd020,
                     ldl_le_p(peer->transport_table + 0xd020) | 2);
            stl_le_p(peer->transport_table + 0x4908,
                     ldl_le_p(peer->transport_table + 0x4908) | 1);
        } else if (offset == 0xc13c && s->master_role && value == 2 &&
                   ldl_le_p(s->transport_table + 0xc90c) == 6 &&
                   ldl_le_p(peer->transport_table + 0xc90c) == 4) {
            /* The next startup phase submits a channel reset and waits
             * for event 4, supplied by status bit 5 on each endpoint. */
            stl_le_p(s->transport_table + 0xd020,
                     ldl_le_p(s->transport_table + 0xd020) | 0x20);
            stl_le_p(peer->transport_table + 0xd020,
                     ldl_le_p(peer->transport_table + 0xd020) | 0x20);
        }
        transport_update_irq(peer);
    }
    transport_update_irq(s);
}

static const MemoryRegionOps transport_ops = {
    .read = transport_read,
    .write = transport_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4 },
    .impl = { .min_access_size = 4, .max_access_size = 4 },
};

static void boot_config_reset(Object *obj, ResetType type)
{
    NikonZ72BootConfig *s = NIKON_Z72_BOOT_CONFIG(obj);
    memset(s->values, 0, sizeof(s->values));
    s->sampling_output_gates = 0;
    s->sampling_output_active = 0;
    s->sampling_output_fired = 0;
    memset(s->sampling_output_epoch, 0, sizeof(s->sampling_output_epoch));
    for (unsigned i = 0; i < 2; i++) {
        timer_del(s->sampling_output_timers[i]);
    }
    memset(s->snapshot_table, 0, sizeof(s->snapshot_table));
    memset(s->mirror_table, 0, sizeof(s->mirror_table));
    memset(s->file_table, 0, sizeof(s->file_table));
    memset(s->file_posted, 0, sizeof(s->file_posted));
    memset(s->gate_table, 0, sizeof(s->gate_table));
    s->gate_pending = false;
    memset(s->transfer_table, 0, sizeof(s->transfer_table));
    memset(s->dbi_table, 0, sizeof(s->dbi_table));
    memset(s->dbi_regions, 0, sizeof(s->dbi_regions));
    s->dbi_viewport = 0;
    s->sd_irq_level = false;
    sd_update_irq(s);
    if (s->sd_host && s->release_config) {
        memset(memory_region_get_ram_ptr(&s->sd_config_ram), 0, 0x2000);
    }
    memset(s->input_levels, 0, sizeof(s->input_levels));
    memset(s->sync_levels, 0, sizeof(s->sync_levels));
    memset(s->aux_image_registers, 0, sizeof(s->aux_image_registers));
    s->aux_image_levels = 0;
    memset(s->aux_image_reference_keys, 0, sizeof(s->aux_image_reference_keys));
    memset(s->aux_image_reference_widths, 0, sizeof(s->aux_image_reference_widths));
    memset(s->aux_image_reference_heights, 0, sizeof(s->aux_image_reference_heights));
    memset(s->aux_image_references, 0, sizeof(s->aux_image_references));
    s->aux_image_process_count = 0;
    aux_image_update_irq(s);
    s->auto_sample_level = false;
    timer_del(s->frame_sync_timer);
    s->frame_sync_count = 0;
    s->input_running = 0;
    s->input_dma_count = 0;
    s->input_dma_address = 0;
    s->input_grid_count = 0;
    s->input_grid_address = 0;
    s->input_grid_phase = 0;
    s->primary_dma_count = 0;
    s->primary_dma_address = 0;
    s->primary_second_address = 0;
    s->primary_frame_written = false;
    s->primary_exposure_ready = false;
    s->processing_dma_count = 0;
    s->processing_grid_count = 0;
    memset(s->image_interrupt_masks, 0, sizeof(s->image_interrupt_masks));
    memset(s->image_interrupt_status, 0, sizeof(s->image_interrupt_status));
    memset(s->image_control_values, 0, sizeof(s->image_control_values));
    s->image_drain_requests = 0;
    s->image_draining = false;
    image_update_irqs(s);
    input_update_irqs(s);
    sync_update_irqs(s);
    if (s->intc) {
        qemu_set_irq(qdev_get_gpio_in(s->intc, 250 - 32), 0);
        if (s->release_config) {
            transfer_update_irq(s);
        }
    }
    memset(s->pair_table, 0, sizeof(s->pair_table));
    memset(s->seq_table, 0, sizeof(s->seq_table));
    if (s->intc && s->master_role && s->release_config) {
        seq_update_irqs(s);
    }
    s->peer_ready_input = false;
    s->peer_ready_output = false;
    s->controller_ack_output = false;
    timer_del(s->input_handshake_timer);
    s->input_handshake_output = false;
    qemu_set_irq(s->controller_ack_irq, 0);
    qemu_set_irq(s->controller_step_irq, 0);
    controller_update_irqs(s);
    qemu_set_irq(s->peer_ready_irq, 0);
    memset(s->transport_table, 0, sizeof(s->transport_table));
    if (s->intc) {
        transport_update_irq(s);
    }
}

static int boot_config_post_load(void *opaque, int version_id)
{
    NikonZ72BootConfig *s = opaque;
    if (version_id < 25) {
        s->controller_levels = 0;
    }
    if (version_id < 26) {
        s->controller_ack_output = false;
    }
    qemu_set_irq(s->controller_ack_irq, s->controller_ack_output);
    qemu_set_irq(s->controller_step_irq, s->input_handshake_output);
    controller_update_irqs(s);
    qemu_set_irq(s->peer_ready_irq, s->peer_gpio && s->peer_ready_output);
    transport_update_irq(s);
    input_update_irqs(s);
    sync_update_irqs(s);
    sd_update_irq(s);
    aux_image_update_irq(s);
    image_update_irqs(s);
    if (s->intc) {
        qemu_set_irq(qdev_get_gpio_in(s->intc, 250 - 32), s->gate_pending);
        if (s->release_config) {
            transfer_update_irq(s);
        }
        if (s->master_role && s->release_config) {
            seq_update_irqs(s);
        }
    }
    return 0;
}

static const VMStateDescription boot_config_vmstate = {
    .name = TYPE_NIKON_Z72_BOOT_CONFIG,
    .version_id = 49,
    .minimum_version_id = 49,
    .post_load = boot_config_post_load,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT32_ARRAY(values, NikonZ72BootConfig, BOOT_CONFIG_WORDS),
        VMSTATE_UINT32(gpio_input_levels, NikonZ72BootConfig),
        VMSTATE_UINT32(gpio_input_driven, NikonZ72BootConfig),
        VMSTATE_BOOL(input_handshake, NikonZ72BootConfig),
        VMSTATE_BOOL(input_handshake_output, NikonZ72BootConfig),
        VMSTATE_TIMER_PTR(input_handshake_timer, NikonZ72BootConfig),
        VMSTATE_BOOL(sampling_output_complete, NikonZ72BootConfig),
        VMSTATE_UINT32(sampling_output_gates, NikonZ72BootConfig),
        VMSTATE_UINT32(sampling_output_active, NikonZ72BootConfig),
        VMSTATE_UINT32(sampling_output_fired, NikonZ72BootConfig),
        VMSTATE_INT64_ARRAY(sampling_output_epoch, NikonZ72BootConfig, 2),
        VMSTATE_TIMER_PTR_ARRAY(sampling_output_timers, NikonZ72BootConfig, 2),
        VMSTATE_UINT32_ARRAY(dbi_table, NikonZ72BootConfig, 0x8c0 / 4),
        VMSTATE_UINT32(dbi_viewport, NikonZ72BootConfig),
        VMSTATE_UINT32_ARRAY(dbi_regions, NikonZ72BootConfig, 2 * 16 * 7),
        VMSTATE_UINT32_ARRAY(input_levels, NikonZ72BootConfig, 8),
        VMSTATE_UINT32_ARRAY(sync_levels, NikonZ72BootConfig, 2),
        VMSTATE_UINT32_ARRAY(aux_image_registers, NikonZ72BootConfig, 0x200 / 4),
        VMSTATE_UINT32(aux_image_levels, NikonZ72BootConfig),
        VMSTATE_UINT32_ARRAY(aux_image_reference_keys, NikonZ72BootConfig, 2),
        VMSTATE_UINT32_ARRAY(aux_image_reference_widths, NikonZ72BootConfig, 2),
        VMSTATE_UINT32_ARRAY(aux_image_reference_heights, NikonZ72BootConfig, 2),
        VMSTATE_UINT8_ARRAY(aux_image_references, NikonZ72BootConfig, 2 * AUX_IMAGE_MAX_PIXELS),
        VMSTATE_UINT64(aux_image_process_count, NikonZ72BootConfig),
        VMSTATE_BOOL(auto_sample_level, NikonZ72BootConfig),
        VMSTATE_BOOL(sample_counter, NikonZ72BootConfig),
        VMSTATE_BOOL(sample_group1, NikonZ72BootConfig),
        VMSTATE_BOOL(pcie_link, NikonZ72BootConfig),
        VMSTATE_BOOL(sd_host, NikonZ72BootConfig),
        VMSTATE_BOOL(sd_irq_level, NikonZ72BootConfig),
        VMSTATE_UINT32(sample_lines, NikonZ72BootConfig),
        VMSTATE_TIMER_PTR(frame_sync_timer, NikonZ72BootConfig),
        VMSTATE_UINT64(frame_sync_count, NikonZ72BootConfig),
        VMSTATE_UINT32(input_running, NikonZ72BootConfig),
        VMSTATE_UINT64(input_dma_count, NikonZ72BootConfig),
        VMSTATE_UINT32(input_dma_address, NikonZ72BootConfig),
        VMSTATE_UINT64(input_grid_count, NikonZ72BootConfig),
        VMSTATE_UINT32(input_grid_address, NikonZ72BootConfig),
        VMSTATE_UINT32(input_grid_phase, NikonZ72BootConfig),
        VMSTATE_UINT64(primary_dma_count, NikonZ72BootConfig),
        VMSTATE_UINT32(primary_dma_address, NikonZ72BootConfig),
        VMSTATE_UINT32(primary_second_address, NikonZ72BootConfig),
        VMSTATE_BOOL(primary_frame_written, NikonZ72BootConfig),
        VMSTATE_BOOL(primary_exposure_sync, NikonZ72BootConfig),
        VMSTATE_BOOL(primary_exposure_ready, NikonZ72BootConfig),
        VMSTATE_UINT64_V(processing_dma_count, NikonZ72BootConfig, 39),
        VMSTATE_UINT64(processing_grid_count, NikonZ72BootConfig),
        VMSTATE_UINT32_ARRAY(image_interrupt_masks, NikonZ72BootConfig, 2),
        VMSTATE_UINT32_ARRAY(image_interrupt_status, NikonZ72BootConfig, 2),
        VMSTATE_UINT32_ARRAY(image_control_values, NikonZ72BootConfig, 5),
        VMSTATE_UINT32(image_drain_requests, NikonZ72BootConfig),
        VMSTATE_BOOL(image_draining, NikonZ72BootConfig),
        VMSTATE_UINT8_ARRAY(snapshot_table, NikonZ72BootConfig, 0x800),
        VMSTATE_UINT8_ARRAY(mirror_table, NikonZ72BootConfig, 0x800),
        VMSTATE_UINT8_ARRAY(file_table, NikonZ72BootConfig, 0x100),
        VMSTATE_BOOL_ARRAY(file_posted, NikonZ72BootConfig, 0x100),
        VMSTATE_UINT8_ARRAY(pair_table, NikonZ72BootConfig, 0x100),
        VMSTATE_UINT8_ARRAY(seq_table, NikonZ72BootConfig, 0x2000),
        VMSTATE_UINT8_ARRAY(gate_table, NikonZ72BootConfig, 0x1000),
        VMSTATE_BOOL(gate_pending, NikonZ72BootConfig),
        VMSTATE_UINT8_ARRAY(transfer_table, NikonZ72BootConfig, 0x100),
        VMSTATE_BOOL(peer_ready_input, NikonZ72BootConfig),
        VMSTATE_BOOL(peer_ready_output, NikonZ72BootConfig),
        VMSTATE_UINT8_ARRAY(transport_table, NikonZ72BootConfig, 0x10000),
        VMSTATE_BOOL_V(input_trace, NikonZ72BootConfig, 27),
        VMSTATE_UINT32_V(input_trace_count, NikonZ72BootConfig, 27),
        VMSTATE_UINT32_ARRAY_V(input_trace_addresses, NikonZ72BootConfig, 256, 27),
        VMSTATE_UINT32_ARRAY_V(input_trace_values, NikonZ72BootConfig, 256, 27),
        VMSTATE_UINT8_ARRAY_V(input_trace_writes, NikonZ72BootConfig, 256, 27),
        VMSTATE_UINT8_V(controller_levels, NikonZ72BootConfig, 25),
        VMSTATE_BOOL_V(controller_ack_output, NikonZ72BootConfig, 26),
        VMSTATE_END_OF_LIST()
    },
};

/* Diagnostic view of the access ring: oldest kept entry first, each
 * entry as "<address>:<value><r|w>". The string is hex-coded pairs so
 * the gdb console can carry it without separators colliding. */
static char *boot_config_input_trace_get(Object *obj, Error **errp)
{
    NikonZ72BootConfig *s = NIKON_Z72_BOOT_CONFIG(obj);
    unsigned total = s->input_trace_count;
    unsigned kept = total < 256 ? total : 256;
    unsigned first = total % 256;
    GString *text = g_string_sized_new(kept * 16 + 1);
    for (unsigned i = 0; i < kept; i++) {
        unsigned slot = (first + i) % 256;
        g_string_append_printf(text, "%08x:%08x%c",
                               s->input_trace_addresses[slot],
                               s->input_trace_values[slot],
                               s->input_trace_writes[slot] ? 'w' : 'r');
        if (i + 1 < kept) {
            g_string_append_c(text, ',');
        }
    }
    return g_string_free(text, false);
}

static void boot_config_init(Object *obj)
{
    NikonZ72BootConfig *s = NIKON_Z72_BOOT_CONFIG(obj);
    s->frame_sync_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, frame_sync_tick, s);
    s->input_handshake_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, input_handshake_complete, s);
    s->sampling_output_timers[0] = timer_new_ns(QEMU_CLOCK_VIRTUAL, sampling_output_first, s);
    s->sampling_output_timers[1] = timer_new_ns(QEMU_CLOCK_VIRTUAL, sampling_output_second, s);
    object_property_add_uint64_ptr(obj, "frame-sync-count", &s->frame_sync_count,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint32_ptr(obj, "input-running", &s->input_running,
                                  OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "input-dma-count", &s->input_dma_count,
                                  OBJ_PROP_FLAG_READ);
    object_property_add_uint32_ptr(obj, "input-dma-address", &s->input_dma_address,
                                  OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "input-grid-count", &s->input_grid_count,
                                  OBJ_PROP_FLAG_READ);
    object_property_add_uint32_ptr(obj, "input-grid-address", &s->input_grid_address,
                                  OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "primary-input-dma-count", &s->primary_dma_count,
                                  OBJ_PROP_FLAG_READ);
    object_property_add_uint32_ptr(obj, "primary-input-dma-address", &s->primary_dma_address,
                                  OBJ_PROP_FLAG_READ);
    object_property_add_uint32_ptr(obj, "primary-input-second-dma-address", &s->primary_second_address,
                                  OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "processing-dma-count", &s->processing_dma_count,
                                  OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "processing-grid-count", &s->processing_grid_count,
                                  OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "aux-image-process-count", &s->aux_image_process_count,
                                  OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "frame-count", &s->frame_count,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint32_ptr(obj, "input-last-read", &s->input_last_read,
                                  OBJ_PROP_FLAG_READ);
    object_property_add_uint32_ptr(obj, "input-trace-count", &s->input_trace_count,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_str(obj, "input-trace-log",
                            boot_config_input_trace_get, NULL);
    qdev_init_gpio_in(DEVICE(obj), peer_ready_input, 1);
    qdev_init_gpio_in_named(DEVICE(obj), controller_pin_input, "controller-input", 3);
    qdev_init_gpio_in_named(DEVICE(obj), engine_gpio_input, "gpio-input", 16);
    qdev_init_gpio_in_named(DEVICE(obj), input_event, "input-event", 8 * 32);
    qdev_init_gpio_in_named(DEVICE(obj), aux_image_event, "aux-image-event", 8);
    qdev_init_gpio_in_named(DEVICE(obj), sync_event, "sync-event", 11 + 32);
    qdev_init_gpio_in_named(DEVICE(obj), frame_sync_enable, "frame-sync-enable", 1);
    qdev_init_gpio_in_named(DEVICE(obj), auto_sample_event, "auto-sample-event", 1);
    qdev_init_gpio_in_named(DEVICE(obj), sd_irq_input, "sd-irq", 1);
    qdev_init_gpio_out(DEVICE(obj), &s->peer_ready_irq, 1);
    qdev_init_gpio_out_named(DEVICE(obj), &s->controller_ack_irq, "controller-ack", 1);
    qdev_init_gpio_out_named(DEVICE(obj), &s->controller_step_irq, "controller-step", 1);
    /* One rising edge per frame on the two recovered display completion
     * lines; wired to the master display device when it exists. */
    qdev_init_gpio_out_named(DEVICE(obj), s->display_complete_irq,
                             "display-complete", 2);
    /* Sparse containers keep unsupported words unassigned and avoid the
     * system bus limit on the number of exported MMIO regions. */
    for (unsigned i = 0; i < G_N_ELEMENTS(s->banks); i++) {
        memory_region_init(&s->banks[i], obj, TYPE_NIKON_Z72_BOOT_CONFIG,
                           0x00100000);
        sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->banks[i]);
    }
    for (unsigned i = 0; i < G_N_ELEMENTS(s->registers); i++) {
        s->words[i].device = s;
        s->words[i].index = i;
    }
}

static void boot_config_finalize(Object *obj)
{
    NikonZ72BootConfig *s = NIKON_Z72_BOOT_CONFIG(obj);

    timer_del(s->frame_sync_timer);
    timer_free(s->frame_sync_timer);
    timer_del(s->input_handshake_timer);
    timer_free(s->input_handshake_timer);
    for (unsigned i = 0; i < 2; i++) {
        timer_free(s->sampling_output_timers[i]);
    }
}

static void boot_config_realize(DeviceState *dev, Error **errp)
{
    NikonZ72BootConfig *s = NIKON_Z72_BOOT_CONFIG(dev);
    MemoryRegion *root = s->root ? s->root : get_system_memory();
    /* RAM-block names must stay unique when both engines exist in one
     * machine; the role suffix keeps the dual machine's blocks apart. */
    const char *tag = s->master_role ? "master" : "slave";
    if (s->release_config) {
        memory_region_init_io(&s->aux_image_ram, OBJECT(dev), &aux_image_ops, s,
                              "z72-auxiliary-image", 0x200);
        memory_region_add_subregion_overlap(root, 0x20201000,
                                            &s->aux_image_ram, 1);
        /* Configuration readback and banked translation descriptors only;
         * this block does not create a link, an endpoint or DMA completion. */
        memory_region_init_io(&s->dbi_ram, OBJECT(dev), &dbi_ops, s,
                              "z72-pcie-configuration", 0x1000);
        memory_region_add_subregion(root, 0x2a900000, &s->dbi_ram);
        if (s->sd_host) {
            DeviceState *sd = qdev_new("generic-sdhci");

            sd->id = g_strdup_printf("z72-sd-%s", tag);
            s->sd_controller = sd;

            /* Fixed windows recovered from the original board setup:
             * endpoint configuration followed by the first host BAR.
             * Configuration is passive storage, without PCI enumeration. */
            memory_region_init_ram(&s->sd_config_ram, OBJECT(dev),
                                   g_strdup_printf("z72-sd-config-%s", tag),
                                   0x2000, &error_fatal);
            memory_region_add_subregion(root, 0x2a800000, &s->sd_config_ram);
            object_property_add_child(OBJECT(dev), "sd-controller", OBJECT(sd));
            object_property_set_link(OBJECT(sd), "dma", OBJECT(root),
                                     &error_fatal);
            sysbus_realize_and_unref(SYS_BUS_DEVICE(sd), &error_fatal);
            memory_region_add_subregion(root, 0x2a810000,
                                        sysbus_mmio_get_region(
                                            SYS_BUS_DEVICE(sd), 0));
            sysbus_connect_irq(SYS_BUS_DEVICE(sd), 0,
                               qdev_get_gpio_in_named(dev, "sd-irq", 0));
            memory_region_init_io(&s->sd_clock_status, OBJECT(dev),
                                  &sd_clock_ops, s, "z72-sd-clock-status", 4);
            memory_region_add_subregion_overlap(root, 0x2a800064,
                                                &s->sd_clock_status, 1);
            memory_region_init_io(&s->sd_uhs2_caps, OBJECT(dev),
                                  &sd_uhs2_caps_ops, s,
                                  "z72-sd-uhs2-capabilities", 0x10);
            memory_region_add_subregion(root, 0x2a810150,
                                        &s->sd_uhs2_caps);
        }
        memory_region_init_io(&s->transport_ram, OBJECT(dev), &transport_ops, s,
                              "z72-transport-control", 0x10000);
        memory_region_add_subregion_overlap(root, 0x20130000,
                                            &s->transport_ram, 1);
    }
    const unsigned pin_first = boot_config_index_of(0x04280030);
    const unsigned chain_first = boot_config_index_of(0x04281000);
    const unsigned snapshot_first = boot_config_index_of(0x20010038);
    const unsigned parameter_first = boot_config_index_of(0x20013000);
    const unsigned release_first = boot_config_index_of(0x04281034);
    if (s->release_config) {
        for (unsigned index = 0; index < ARRAY_SIZE(image_control_offsets); index++) {
            s->image_control_words[index] = (NikonZ72ConfigWord) { s, index };
            memory_region_init_io(&s->image_controls[index], OBJECT(dev),
                &image_control_ops, &s->image_control_words[index],
                "z72-image-control-bank0", 4);
            memory_region_add_subregion_overlap(root,
                0x20380000 + image_control_offsets[index], &s->image_controls[index], 1);
        }
        for (unsigned bank = 0; bank < 2; bank++) {
            s->image_interrupt_words[bank] = (NikonZ72ConfigWord) { s, bank };
            memory_region_init_io(&s->image_interrupts[bank], OBJECT(dev),
                &image_interrupt_ops, &s->image_interrupt_words[bank],
                bank ? "z72-image-interrupt-bank1" : "z72-image-interrupt-bank0", 8);
            memory_region_add_subregion_overlap(root, 0x20380020 + bank * 0x40000,
                                                &s->image_interrupts[bank], 1);
        }
        memory_region_init_io(&s->transfer_ram, OBJECT(dev), &transfer_ops,
                              s, "z72-transfer-control-lab", 0x100);
        memory_region_add_subregion_overlap(root, 0x20100000,
                                            &s->transfer_ram, 1);
        /* Register file addressed 0x04280004-relative (single words plus the
         * indexed +0x30/+0x60 arrays), read by the kernel after the handoff.
         * Added below the word registers so exact words keep precedence and
         * the remaining file bytes fall through to passive storage. */
        memory_region_init_io(&s->file_ram, OBJECT(dev), &file_ops, s,
                              "z72-file-lab", 0x100);
        if (s->own_file) {
            /* The peer-descriptor file is shared hardware: in the dual
             * machine one instance serves both views (the peer's readiness
             * answer lands in the same words the local engine polls). */
            memory_region_add_subregion(&s->banks[0], 0x080000, &s->file_ram);
        }
        memory_region_init_io(&s->pair_ram, OBJECT(dev), &pair_ops, s,
                              TYPE_NIKON_Z72_BOOT_CONFIG "-pairs", 0x100);
        if (s->own_file) {
            memory_region_add_subregion(&s->banks[0], 0x081200, &s->pair_ram);
        }
        /* Sequencer register file (0x04251000..0x042510BC descriptor series
         * plus the 0x04250080 banks) driven after the release; passive. */
        memory_region_init_io(&s->seq_ram, OBJECT(dev), &seq_ops, s,
                              TYPE_NIKON_Z72_BOOT_CONFIG "-sequencer", 0x2000);
        memory_region_add_subregion(&s->banks[0], 0x050000, &s->seq_ram);
        /* Counter-adjacent file continuation (0x0426F018 and following RMW
         * words) below the registered counter words, as passive RAM. */
        memory_region_init_ram(&s->count_ram, OBJECT(dev),
                               g_strdup_printf("z72-counter-file-lab-%s", tag), 0x1000, &error_fatal);
        memory_region_add_subregion(&s->banks[0], 0x06F000, &s->count_ram);
        /* Enable-block controller (0x2013xxxx words, 0xF000F-style masks)
         * past the first configuration bank, as passive RAM. */
        memory_region_init_ram(&s->enable_ram, OBJECT(dev),
                               g_strdup_printf("z72-enable-block-lab-%s", tag), 0x10000, &error_fatal);
        memory_region_add_subregion(root, 0x20130000,
                                    &s->enable_ram);
        /* Timer-family block (channel-start word +0, period +4, event/status
         * words +8/+0x10, channel pages from +0x1000) driven after the
         * release: recovered as line 237 of the interrupt dispatch table,
         * with the dispatcher reading +8 and writing the serviced bits back.
         * The periodic contract is experimental; the companion sequencer
         * page at 0x28000000 stays passive RAM. */
        s->timer = qdev_new("nikon-z72-timer");
        object_property_set_link(OBJECT(s->timer), "intc", OBJECT(s->intc),
                                 &error_fatal);
        qdev_prop_set_uint32(s->timer, "line", s->timer_line);
        qdev_prop_set_uint32(s->timer, "tick-us", s->timer_tick_us);
        qdev_prop_set_bit(s->timer, "tick-enabled", s->timer_tick);
        qdev_prop_set_bit(s->timer, "pcie-clock", s->sd_host);
        object_property_add_child(OBJECT(dev), "z72-timer", OBJECT(s->timer));
        sysbus_realize_and_unref(SYS_BUS_DEVICE(s->timer), &error_fatal);
        memory_region_add_subregion(root, 0x2B000000,
                                    sysbus_mmio_get_region(
                                        SYS_BUS_DEVICE(s->timer), 0));
        memory_region_init_ram(&s->companion_ram, OBJECT(dev),
                               g_strdup_printf("z72-timer-companion-lab-%s", tag), 0x1000, &error_fatal);
        memory_region_add_subregion(root, 0x28000000,
                                    &s->companion_ram);
        /* Gate block page at 0x04287000 below the registered gate words. */
        memory_region_init_io(&s->gate_ram, OBJECT(dev), &gate_ops, s,
                              "z72-gate-block-lab", 0x1000);
        memory_region_add_subregion(&s->banks[0], 0x087000, &s->gate_ram);
    }
    for (unsigned i = 0; i < G_N_ELEMENTS(s->registers); i++) {
        /* The pin-group and controller blocks stay unassigned when disabled,
         * retaining the earlier startup boundaries with their original
         * unmapped faults. */
        if (!s->pin_config && i >= pin_first) {
            continue;
        }
        if (!s->controller_config && i >= chain_first) {
            continue;
        }
        if (!s->snapshot_config && i >= snapshot_first) {
            continue;
        }
        if (!s->parameter_config && i >= parameter_first) {
            continue;
        }
        if (!s->release_config && i >= release_first) {
            continue;
        }
        if (boot_config_addresses[i] >= 0x20060000 &&
            boot_config_addresses[i] < 0x20064000) {
            continue;
        }
        unsigned bank = boot_config_addresses[i] >= 0x20000000;
        hwaddr base = bank ? 0x20000000 : 0x04200000;
        memory_region_init_io(&s->registers[i], OBJECT(dev), &boot_config_ops,
                              &s->words[i], TYPE_NIKON_Z72_BOOT_CONFIG, 4);
        bool outside_bank = boot_config_addresses[i] >= 0x24000000;
        memory_region_add_subregion(outside_bank ? root : &s->banks[bank],
                                    boot_config_addresses[i] -
                                        (outside_bank ? 0 : base),
                                    &s->registers[i]);
    }
    if (s->release_config) {
        memory_region_init_io(&s->auxiliary_ram, OBJECT(dev), &auxiliary_ops, s,
                              "z72-auxiliary-configuration", 0x4000);
        memory_region_add_subregion(&s->banks[1], 0x60000, &s->auxiliary_ram);
    }
    if (s->snapshot_config) {
        memory_region_init_io(&s->snapshot_source, OBJECT(dev),
                              &snapshot_source_ops, s,
                              TYPE_NIKON_Z72_BOOT_CONFIG "-snapshot", 0x800);
        memory_region_add_subregion(&s->banks[1], 0x14800,
                                    &s->snapshot_source);
    }
    if (s->parameter_config) {
        /* The stock tail mirrors the snapshot table into eight 0x100-byte
         * regions at 0x24074000 before the scattered completion stores. */
        memory_region_init_io(&s->mirror_window, OBJECT(dev),
                              &mirror_ops, s,
                              TYPE_NIKON_Z72_BOOT_CONFIG "-mirror", 0x800);
        memory_region_add_subregion(root, 0x24074000,
                                    &s->mirror_window);
    }
    if (s->stage_config && s->master_role) {
        /* The native nine-MiB code cache includes the reset payload staging
         * page at +1 MiB and later remapped execution windows. */
        memory_region_init_ram(&s->stage_ram, OBJECT(dev),
                               g_strdup_printf("z72-stage-ram-lab-%s", tag), 0x900000,
                               &error_fatal);
        memory_region_add_subregion(root, 0xBAA00000,
                                    &s->stage_ram);
    }
}

static void boot_config_class_init(ObjectClass *oc, const void *data)
{
    static const Property properties[] = {
        DEFINE_PROP_BOOL("auto-complete", NikonZ72BootConfig, auto_complete, true),
        DEFINE_PROP_BOOL("input-handshake", NikonZ72BootConfig, input_handshake, false),
        DEFINE_PROP_BOOL("sampling-output-complete", NikonZ72BootConfig, sampling_output_complete, false),
        DEFINE_PROP_BOOL("primary-exposure-sync", NikonZ72BootConfig, primary_exposure_sync, false),
        DEFINE_PROP_UINT32("blocked-control", NikonZ72BootConfig, blocked_control, 0),
        DEFINE_PROP_UINT32("clear-base", NikonZ72BootConfig, clear_base, 0),
        DEFINE_PROP_UINT32("clear-size", NikonZ72BootConfig, clear_size, 0),
        DEFINE_PROP_BOOL("memory-init-error", NikonZ72BootConfig, memory_init_error, false),
        DEFINE_PROP_BOOL("pin-config", NikonZ72BootConfig, pin_config, true),
        DEFINE_PROP_BOOL("controller-config", NikonZ72BootConfig, controller_config, true),
        DEFINE_PROP_BOOL("snapshot-config", NikonZ72BootConfig, snapshot_config, true),
        DEFINE_PROP_BOOL("parameter-config", NikonZ72BootConfig, parameter_config, true),
        DEFINE_PROP_BOOL("release-config", NikonZ72BootConfig, release_config, true),
        DEFINE_PROP_UINT32("timer-line", NikonZ72BootConfig, timer_line, 237),
        /* A 10 ms laboratory interval leaves time for lower-priority
         * device completions while the guest runs under software execution. */
        DEFINE_PROP_UINT32("timer-tick-us", NikonZ72BootConfig, timer_tick_us, 10000),
        DEFINE_PROP_BOOL("timer-tick", NikonZ72BootConfig, timer_tick, true),
        DEFINE_PROP_BOOL("frame-sync", NikonZ72BootConfig, frame_sync, false),
        DEFINE_PROP_BOOL("sensor-sample", NikonZ72BootConfig, sensor_sample, false),
        DEFINE_PROP_BOOL("frame-phase", NikonZ72BootConfig, frame_phase, false),
        DEFINE_PROP_BOOL("input-stop-complete", NikonZ72BootConfig, input_stop_complete, false),
        DEFINE_PROP_BOOL("display-complete", NikonZ72BootConfig,
                         display_complete, false),
        DEFINE_PROP_BOOL("input-trace", NikonZ72BootConfig, input_trace, false),
        DEFINE_PROP_BOOL("frame-generate", NikonZ72BootConfig, frame_generate, false),
        DEFINE_PROP_BOOL("frame-process", NikonZ72BootConfig, frame_process, false),
        DEFINE_PROP_BOOL("aux-image-process", NikonZ72BootConfig, aux_image_process, false),
        DEFINE_PROP_BOOL("frame-notify", NikonZ72BootConfig, frame_notify, false),
        DEFINE_PROP_BOOL("sample-counter", NikonZ72BootConfig, sample_counter, false),
        DEFINE_PROP_BOOL("sample-group1", NikonZ72BootConfig, sample_group1, false),
        DEFINE_PROP_BOOL("pcie-link", NikonZ72BootConfig, pcie_link, false),
        DEFINE_PROP_BOOL("sd-host", NikonZ72BootConfig, sd_host, false),
        DEFINE_PROP_UINT32("sample-lines", NikonZ72BootConfig, sample_lines, 0),
        DEFINE_PROP_LINK("intc", NikonZ72BootConfig, intc, TYPE_DEVICE, DeviceState *),
        DEFINE_PROP_BOOL("stage-config", NikonZ72BootConfig, stage_config, true),
        DEFINE_PROP_BOOL("master-role", NikonZ72BootConfig, master_role, true),
        DEFINE_PROP_BOOL("own-file", NikonZ72BootConfig, own_file, true),
        DEFINE_PROP_BOOL("gate-completion", NikonZ72BootConfig,
                         gate_completion, true),
        DEFINE_PROP_BOOL("transfer-reset-completion", NikonZ72BootConfig,
                         transfer_reset_completion, true),
        DEFINE_PROP_BOOL("sequencer-completion", NikonZ72BootConfig,
                         sequencer_completion, true),
        DEFINE_PROP_BOOL("peer-gpio", NikonZ72BootConfig, peer_gpio, true),
        DEFINE_PROP_BOOL("transport-link", NikonZ72BootConfig, transport_link, true),
        DEFINE_PROP_LINK("root", NikonZ72BootConfig, root, TYPE_MEMORY_REGION,
                         MemoryRegion *),
        DEFINE_PROP_LINK("cpu", NikonZ72BootConfig, cpu, TYPE_ARM_CPU, ARMCPU *),
    };
    DeviceClass *dc = DEVICE_CLASS(oc);
    ResettableClass *rc = RESETTABLE_CLASS(oc);
    dc->vmsd = &boot_config_vmstate;
    dc->realize = boot_config_realize;
    device_class_set_props(dc, properties);
    rc->phases.hold = boot_config_reset;
}

static void boot_config_register_types(void)
{
    static const TypeInfo info = {
        .name = TYPE_NIKON_Z72_BOOT_CONFIG,
        .parent = TYPE_SYS_BUS_DEVICE,
        .instance_size = sizeof(NikonZ72BootConfig),
        .instance_init = boot_config_init,
        .instance_finalize = boot_config_finalize,
        .class_init = boot_config_class_init,
    };
    type_register_static(&info);
}
type_init(boot_config_register_types)

/* Engine boot storage: the image set the board reloads at every reset.
 * The body boots from its stored firmware, so a reset must copy the image
 * back into the code window and restart both cores at the image entry even
 * though the preloader only runs once. Writing the image property replaces
 * the laboratory stored image; the next machine reset boots that image.
 * This property does not implement the firmware's flash programming API. */
#define TYPE_NIKON_Z72_BOOT_STORE "nikon-z72-boot-store"
OBJECT_DECLARE_SIMPLE_TYPE(NikonZ72BootStore, NIKON_Z72_BOOT_STORE)

#define Z72_BOOT_STORE_FILES 5

typedef struct NikonZ72BootFile {
    char *path;
    hwaddr address;
    uint8_t *data;
    size_t size;
} NikonZ72BootFile;

struct NikonZ72BootStore {
    SysBusDevice parent_obj;
    char *image;
    char *auxiliary;
    NikonZ72BootFile files[Z72_BOOT_STORE_FILES];
    unsigned file_count;
    hwaddr entry;
    ARMCPU *cpus[2];
    unsigned cpu_count;
    bool harvest;
};

/* CCITT CRC-16, polynomial 0x1021, zero initial value: the same transform
 * the original container checks use, streamed so multi-megabyte members
 * never need a host-sized buffer. */
static uint16_t update_crc_step(uint16_t crc, const uint8_t *data, size_t length)
{
    for (size_t i = 0; i < length; i++) {
        crc ^= (uint16_t)data[i] << 8;
        for (int bit = 0; bit < 8; bit++) {
            crc = (crc & 0x8000) ? (uint16_t)(crc << 1) ^ 0x1021
                                 : (uint16_t)(crc << 1);
        }
    }
    return crc;
}

static MemTxResult update_window_read(AddressSpace *view, uint32_t offset,
                                      void *buffer, uint32_t length)
{
    return address_space_read(view, Z72_UPDATE_WINDOW_BASE + offset,
                              MEMTXATTRS_UNSPECIFIED, buffer, length);
}

/* CRC over a window range computed in bounded chunks. */
static bool update_window_crc(AddressSpace *view, uint32_t offset,
                              uint32_t length, uint16_t *result)
{
    uint8_t chunk[0x10000];
    uint16_t crc = 0;
    while (length) {
        uint32_t take = MIN(length, sizeof(chunk));
        if (update_window_read(view, offset, chunk, take) != MEMTX_OK) {
            return false;
        }
        crc = update_crc_step(crc, chunk, take);
        offset += take;
        length -= take;
    }
    *result = crc;
    return true;
}

static bool update_member_name_ok(const uint8_t *raw)
{
    unsigned length = 0;
    while (length < 16 && raw[length]) {
        uint8_t c = raw[length];
        bool letter = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                      (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-';
        if (!letter) {
            return false;
        }
        length++;
    }
    if (length == 0) {
        return false;
    }
    while (length < 16) {
        if (raw[length]) {
            return false;
        }
        length++;
    }
    return true;
}

/* Harvest a decoded update container from an explicit laboratory window. Mirrors
 * the host-side container checks: 32-byte space marker, big-endian
 * directory (count 1..64, contiguous members, zero reserved fields), one
 * master member, every member CRC residue zero and the container CRC over
 * the directory plus all members zero. On success the master member bounds
 * are reported and the window is left untouched. */
static bool update_window_harvest(AddressSpace *view, uint32_t *member_offset,
                                  uint32_t *member_length)
{
    uint8_t marker[0x30];
    if (update_window_read(view, 0x20, marker, sizeof(marker)) != MEMTX_OK) {
        return false;
    }
    for (unsigned i = 0; i < 0x20; i++) {
        if (marker[i] != 0x20) {
            return false;
        }
    }
    uint32_t count = ldl_be_p(marker + 0x20);
    uint32_t header = ldl_be_p(marker + 0x24);
    if (count == 0 || count > 64 || header != 0x30 + count * 0x20 ||
        ldl_be_p(marker + 0x28) || ldl_be_p(marker + 0x2C)) {
        return false;
    }
    uint8_t *entries = g_malloc(header - 0x30);
    if (update_window_read(view, 0x20 + 0x30, entries, header - 0x30) != MEMTX_OK) {
        g_free(entries);
        return false;
    }
    /* The directory is followed by the members inside the window; the body
     * ends with a 16-byte CRC-plus-zero trailer. */
    const uint32_t body_limit = Z72_UPDATE_WINDOW_BYTES - 0x20 - 0x10;
    uint32_t end = header;
    unsigned masters = 0;
    for (unsigned index = 0; index < count; index++) {
        const uint8_t *entry = entries + index * 0x20;
        if (!update_member_name_ok(entry) ||
            ldl_be_p(entry + 24) || ldl_be_p(entry + 28)) {
            g_free(entries);
            return false;
        }
        uint32_t start = ldl_be_p(entry + 16);
        uint32_t size = ldl_be_p(entry + 20);
        bool master = memcmp(entry, "eg1840_mas_", 11) == 0;
        if (size < 2 || size > body_limit || start != end ||
            start > body_limit - size) {
            g_free(entries);
            return false;
        }
        if (master) {
            masters++;
            *member_offset = start;
            *member_length = size;
        }
        end = start + size;
    }
    g_free(entries);
    if (masters != 1 || end > body_limit) {
        return false;
    }
    uint8_t trailer[14];
    if (update_window_read(view, 0x20 + end + 2, trailer, sizeof(trailer))
        != MEMTX_OK) {
        return false;
    }
    for (unsigned i = 0; i < sizeof(trailer); i++) {
        if (trailer[i]) {
            return false;
        }
    }
    /* Per-member residues and the container CRC over directory + members
     * plus the trailer CRC word. */
    uint32_t cursor = header;
    for (unsigned index = 0; index < count; index++) {
        uint8_t entry[0x20];
        if (update_window_read(view, 0x20 + 0x30 + index * 0x20, entry,
                              sizeof(entry)) != MEMTX_OK) {
            return false;
        }
        uint32_t size = ldl_be_p(entry + 20);
        uint16_t residue = 1;
        if (!update_window_crc(view, 0x20 + cursor, size, &residue) ||
            residue != 0) {
            return false;
        }
        cursor += size;
    }
    uint16_t container = 1;
    if (!update_window_crc(view, 0x20, cursor + 2, &container) ||
        container != 0) {
        return false;
    }
    return true;
}

/* Copy the harvested master member into the code window in chunks. */
static void update_window_install(AddressSpace *view, uint32_t offset,
                                  uint32_t length, hwaddr target)
{
    uint8_t chunk[0x10000];
    while (length) {
        uint32_t take = MIN(length, sizeof(chunk));
        if (update_window_read(view, offset, chunk, take) != MEMTX_OK) {
            return;
        }
        address_space_write(view, target, MEMTXATTRS_UNSPECIFIED, chunk, take);
        offset += take;
        length -= take;
        target += take;
    }
}

static void boot_store_load(NikonZ72BootFile *file, const char *path,
                            hwaddr address, Error **errp)
{
    gchar *data = NULL;
    gsize size = 0;
    if (!g_file_get_contents(path, &data, &size, NULL)) {
        error_setg(errp, "Boot store file is not readable: %s", path);
        return;
    }
    g_free(file->path);
    g_free(file->data);
    file->path = g_strdup(path);
    file->data = (uint8_t *)data;
    file->size = size;
    file->address = address;
}

/* Auxiliary entries are "path@hex-address" pairs separated by commas. */
static void boot_store_parse_auxiliary(NikonZ72BootStore *s, Error **errp)
{
    g_auto(GStrv) entries = g_strsplit(s->auxiliary ?: "", ",", 0);
    for (unsigned i = 0; entries[i] && entries[i][0]; i++) {
        if (s->file_count >= Z72_BOOT_STORE_FILES) {
            error_setg(errp, "Boot store accepts at most %d auxiliary files",
                       Z72_BOOT_STORE_FILES - 1);
            return;
        }
        gchar *marker = strrchr(entries[i], '@');
        if (marker == NULL) {
            error_setg(errp, "Boot store entry lacks @address: %s", entries[i]);
            return;
        }
        uint64_t address;
        if (qemu_strtou64(marker + 1, NULL, 16, &address) || address == 0) {
            error_setg(errp, "Boot store entry address is invalid: %s", entries[i]);
            return;
        }
        *marker = '\0';
        boot_store_load(&s->files[s->file_count++], entries[i], address, errp);
        if (*errp) {
            return;
        }
    }
}

static char *boot_store_image_get(Object *obj, Error **errp)
{
    return g_strdup(NIKON_Z72_BOOT_STORE(obj)->image);
}

static void boot_store_image_set(Object *obj, const char *value, Error **errp)
{
    NikonZ72BootStore *s = NIKON_Z72_BOOT_STORE(obj);
    /* File zero is the firmware image; replacing it reprograms the store. */
    boot_store_load(&s->files[0], value, s->entry, errp);
    if (*errp) {
        return;
    }
    g_free(s->image);
    s->image = g_strdup(value);
    if (s->file_count == 0) {
        s->file_count = 1;
    }
}

static char *boot_store_auxiliary_get(Object *obj, Error **errp)
{
    return g_strdup(NIKON_Z72_BOOT_STORE(obj)->auxiliary);
}

static void boot_store_auxiliary_set(Object *obj, const char *value, Error **errp)
{
    NikonZ72BootStore *s = NIKON_Z72_BOOT_STORE(obj);
    g_free(s->auxiliary);
    s->auxiliary = g_strdup(value);
}

static bool boot_store_harvest_get(Object *obj, Error **errp)
{
    return NIKON_Z72_BOOT_STORE(obj)->harvest;
}

static void boot_store_harvest_set(Object *obj, bool value, Error **errp)
{
    NIKON_Z72_BOOT_STORE(obj)->harvest = value;
}

/* Runs after the device tree reset: the code window and the cores are back
 * at their reset state, so the stored set is copied in and execution is
 * pointed at the image entry, matching the preloader's initial placement.
 * The optional decoded-window fixture can replace the image for this boot.
 * Its structural checks do not establish native update authentication or
 * programming, so normal resets do not enable this fixture. */
static void boot_store_reset(void *opaque)
{
    NikonZ72BootStore *s = opaque;
    if (s->cpu_count == 0 || s->entry == 0) {
        return;
    }
    AddressSpace *view = CPU(s->cpus[0])->as;
    bool harvested = false;
    if (s->harvest) {
        uint32_t offset = 0, length = 0;
        harvested = update_window_harvest(view, &offset, &length);
        if (harvested) {
            /* The reported bounds are body-relative; the body starts 0x20
             * into the staging stream. */
            update_window_install(view, 0x20 + offset, length, s->entry);
        }
    }
    for (unsigned i = 0; i < s->file_count; i++) {
        NikonZ72BootFile *file = &s->files[i];
        if (file->size == 0 || (harvested && i == 0)) {
            continue;
        }
        address_space_write(view, file->address, MEMTXATTRS_UNSPECIFIED,
                            file->data, file->size);
    }
    for (unsigned i = 0; i < s->cpu_count; i++) {
        CPUState *cs = CPU(s->cpus[i]);
        cpu_reset(cs);
        cpu_set_pc(cs, s->entry);
    }
}

static void boot_store_realize(DeviceState *dev, Error **errp)
{
    NikonZ72BootStore *s = NIKON_Z72_BOOT_STORE(dev);
    /* Slot zero always belongs to the image, loaded or empty. */
    s->file_count = 1;
    if (s->image) {
        boot_store_load(&s->files[0], s->image, s->entry, errp);
        if (*errp) {
            return;
        }
    }
    boot_store_parse_auxiliary(s, errp);
    if (*errp) {
        return;
    }
    qemu_register_reset(boot_store_reset, s);
}

static void boot_store_finalize(Object *obj)
{
    NikonZ72BootStore *s = NIKON_Z72_BOOT_STORE(obj);
    for (unsigned i = 0; i < Z72_BOOT_STORE_FILES; i++) {
        g_free(s->files[i].path);
        g_free(s->files[i].data);
    }
    g_free(s->image);
    g_free(s->auxiliary);
}

static void boot_store_class_init(ObjectClass *oc, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    dc->realize = boot_store_realize;
    object_class_property_add_str(oc, "image", boot_store_image_get,
                                  boot_store_image_set);
    object_class_property_set_description(oc, "image",
        "Stored engine firmware image copied to the entry at every reset");
    object_class_property_add_str(oc, "auxiliary", boot_store_auxiliary_get,
                                  boot_store_auxiliary_set);
    object_class_property_set_description(oc, "auxiliary",
        "Comma separated path@address files reloaded alongside the image");
    object_class_property_add_bool(oc, "harvest-update",
        boot_store_harvest_get, boot_store_harvest_set);
    object_class_property_set_description(oc, "harvest-update",
        "Explicit laboratory fixture: boot a CRC-valid decoded RAM container");
}

static void boot_store_init(Object *obj)
{
    /* Normal resets use stored images. Decoded-window experiments opt in. */
    NIKON_Z72_BOOT_STORE(obj)->harvest = false;
}

static void boot_store_register_types(void)
{
    static const TypeInfo info = {
        .name = TYPE_NIKON_Z72_BOOT_STORE,
        .parent = TYPE_SYS_BUS_DEVICE,
        .instance_size = sizeof(NikonZ72BootStore),
        .instance_init = boot_store_init,
        .instance_finalize = boot_store_finalize,
        .class_init = boot_store_class_init,
    };
    type_register_static(&info);
}
type_init(boot_store_register_types)

static DeviceState *nikon_z72_engine_init(MachineState *machine, MemoryRegion *view,
                                          const NikonZ72Window *windows,
                                          unsigned count,
                                          MemoryRegion *shared_message,
                                          const char *chardev_id, bool own_file,
                                          const char *boot_image,
                                          const char *boot_aux);

static void nikon_z72_context_init(MachineState *machine,
                                  const NikonZ72Window *windows, unsigned count)
{
    nikon_z72_engine_init(machine, get_system_memory(), windows, count, NULL,
                          NULL, true, NULL, NULL);
}

/* One engine context: two execution cores, its own private view of the bus
 * (the laboratory system memory for the single-role machines, a private
 * container for the dual-engine machine) and its own interrupt controller.
 * Execution cores within one role share RAM and a GIC. */
static DeviceState *nikon_z72_engine_init(MachineState *machine, MemoryRegion *view,
                                          const NikonZ72Window *windows,
                                          unsigned count, MemoryRegion *shared_message,
                                          const char *chardev_id, bool own_file,
                                          const char *boot_image,
                                          const char *boot_aux)
{
    MemoryRegion *ram = g_new0(MemoryRegion, count);
    /* Execution cores within one selected role share RAM and a GIC. The
     * master and slave roles remain separate machines, not SMP cores. */
    unsigned num_cpus = shared_message ? 2 : machine->smp.cpus;
    ARMCPU **cpus = g_new0(ARMCPU *, num_cpus);
    for (unsigned i = 0; i < num_cpus; i++) {
        cpus[i] = ARM_CPU(object_new(machine->cpu_type));
        object_property_set_int(OBJECT(cpus[i]), "mp-affinity", i, &error_fatal);
        object_property_set_int(OBJECT(cpus[i]), "core-count", num_cpus, &error_fatal);
        object_property_set_int(OBJECT(cpus[i]), "reset-cbar", Z72_PRIVATE_BASE, &error_fatal);
        object_property_set_int(OBJECT(cpus[i]), "cntfrq", Z72_COUNTER_FREQUENCY, &error_fatal);
        /* Each engine executes through its own view: the shared system
         * memory for a single-role machine, a private container when both
         * engines run in one machine. */
        object_property_set_link(OBJECT(cpus[i]), "memory", OBJECT(view),
                                 &error_fatal);
        object_property_set_bool(OBJECT(cpus[i]), "realized", true, &error_fatal);
    }
    /* Boot storage: every machine reset re-copies the stored image set into
     * the code window and restarts the cores at the image entry, so a reset
     * after a store update boots the replaced firmware. */
    DeviceState *boot_store = qdev_new(TYPE_NIKON_Z72_BOOT_STORE);
    NikonZ72BootStore *store = NIKON_Z72_BOOT_STORE(boot_store);
    store->entry = Z72_MASTER_BASE;
    for (unsigned i = 0; i < num_cpus; i++) {
        store->cpus[i] = cpus[i];
    }
    store->cpu_count = num_cpus;
    if (boot_image) {
        qdev_prop_set_string(boot_store, "image", boot_image);
    }
    if (boot_aux) {
        qdev_prop_set_string(boot_store, "auxiliary", boot_aux);
    }
    object_property_add_child(OBJECT(machine),
                              windows == nikon_z72_slave_windows
                                  ? "slave-boot-store" : "master-boot-store",
                              OBJECT(boot_store));
    sysbus_realize_and_unref(SYS_BUS_DEVICE(boot_store), &error_fatal);
    /* Stock RTOS setup reads CBAR and uses distributor +0x1000, CPU +0x2000
     * and 256 interrupt slots. Revision, base and timer wiring are laboratory
     * choices, using the standard QEMU device rather than status-only words. */
    DeviceState *gic = qdev_new(gic_class_name());
    /* Firmware timer setup writes the active-status word at +0x300.
     * The v1 interface leaves this status read-only; the v2 set-active
     * interpretation would leave the timer permanently active. */
    qdev_prop_set_uint32(gic, "revision", 1);
    qdev_prop_set_uint32(gic, "num-cpu", num_cpus);
    /* Banked interfaces use engine-local core numbers even when another
     * engine's cores precede this group in the machine CPU list. */
    qdev_prop_set_uint32(gic, "first-cpu-index", CPU(cpus[0])->cpu_index);
    qdev_prop_set_uint32(gic, "num-irq", 256);
    qdev_prop_set_bit(gic, "has-security-extensions", true);
    sysbus_realize_and_unref(SYS_BUS_DEVICE(gic), &error_fatal);
    memory_region_add_subregion(view, Z72_PRIVATE_BASE + 0x1000,
                                sysbus_mmio_get_region(SYS_BUS_DEVICE(gic), 0));
    memory_region_add_subregion(view, Z72_PRIVATE_BASE + 0x2000,
                                sysbus_mmio_get_region(SYS_BUS_DEVICE(gic), 1));
    const unsigned timer_irqs[] = {
        [GTIMER_PHYS] = 30, [GTIMER_VIRT] = 27,
        [GTIMER_HYP] = 26, [GTIMER_SEC] = 29,
    };
    for (unsigned i = 0; i < num_cpus; i++) {
        sysbus_connect_irq(SYS_BUS_DEVICE(gic), i,
                           qdev_get_gpio_in(DEVICE(cpus[i]), ARM_CPU_IRQ));
        sysbus_connect_irq(SYS_BUS_DEVICE(gic), i + num_cpus,
                           qdev_get_gpio_in(DEVICE(cpus[i]), ARM_CPU_FIQ));
        for (unsigned timer = 0; timer < G_N_ELEMENTS(timer_irqs); timer++) {
            qdev_connect_gpio_out(DEVICE(cpus[i]), timer,
                                  qdev_get_gpio_in(gic, 224 + i * 32 + timer_irqs[timer]));
        }
    }
    for (unsigned i = 0; i < count; i++) {
        const NikonZ72Window *w = &windows[i];
        if (shared_message && g_str_has_suffix(w->name, "message-ram-lab")) {
            /* The owner's native message window uses the shared backing;
             * the dual board adds the peer's translated bus aliases. */
            memory_region_add_subregion(view, w->base, shared_message);
            continue;
        }
        memory_region_init_ram(&ram[i], NULL, w->name, w->size, &error_fatal);
        memory_region_add_subregion(view, w->base, &ram[i]);
        hwaddr bus_base;
        switch (w->base) {
        case 0x50300000:
            bus_base = 0x30000000;
            break;
        case 0x5f900000:
            bus_base = 0x34600000;
            break;
        case 0xc6100000:
            bus_base = 0x15100000;
            break;
        default:
            continue;
        }
        MemoryRegion *alias = g_new0(MemoryRegion, 1);
        memory_region_init_alias(alias, NULL, "z72-buffer-bus-alias",
                                 &ram[i], 0, w->size);
        memory_region_add_subregion(view, bus_base, alias);
    }
    DeviceState *config = qdev_new(TYPE_NIKON_Z72_BOOT_CONFIG);
    bool slave = windows == nikon_z72_slave_windows;
    qdev_prop_set_uint32(config, "clear-base", slave ? 0xc1000000 : 0xb1800000);
    qdev_prop_set_uint32(config, "clear-size", slave ? 0x00a00000 : 0x01400000);
    qdev_prop_set_bit(config, "master-role", !slave);
    qdev_prop_set_bit(config, "own-file", own_file);
    object_property_set_link(OBJECT(config), "intc", OBJECT(gic), &error_fatal);
    object_property_set_link(OBJECT(config), "root", OBJECT(view), &error_fatal);
    object_property_set_link(OBJECT(config), "cpu", OBJECT(cpus[0]), &error_fatal);
    sysbus_realize_and_unref(SYS_BUS_DEVICE(config), &error_fatal);
    memory_region_add_subregion(view, 0x04200000,
                                sysbus_mmio_get_region(SYS_BUS_DEVICE(config), 0));
    memory_region_add_subregion(view, 0x20000000,
                                sysbus_mmio_get_region(SYS_BUS_DEVICE(config), 1));
    DeviceState *memory = qdev_new("nikon-z72-memory");
    NikonZ72BootConfig *boot_config = NIKON_Z72_BOOT_CONFIG(config);
    object_property_set_link(OBJECT(memory), "root", OBJECT(view), &error_fatal);
    qdev_prop_set_uint32(memory, "clear-base", boot_config->clear_base);
    qdev_prop_set_uint32(memory, "clear-size", boot_config->clear_size);
    qdev_prop_set_bit(memory, "fail", boot_config->memory_init_error);
    sysbus_realize_and_unref(SYS_BUS_DEVICE(memory), &error_fatal);
    memory_region_add_subregion_overlap(view, 0x20070000,
        sysbus_mmio_get_region(SYS_BUS_DEVICE(memory), 0), 1);
    for (unsigned channel = 0; channel < 2; channel++) {
        sysbus_connect_irq(SYS_BUS_DEVICE(memory), channel,
                           qdev_get_gpio_in(gic, 103 + channel - 32));
    }
    DeviceState *input_config = qdev_new("nikon-z72-input-config");
    sysbus_realize_and_unref(SYS_BUS_DEVICE(input_config), &error_fatal);
    memory_region_add_subregion(view, 0x20068400,
        sysbus_mmio_get_region(SYS_BUS_DEVICE(input_config), 0));
    DeviceState *counter = qdev_new("nikon-z72-counter");
    if (!slave) {
        DeviceState *display = qdev_new("nikon-z72-display");
        object_property_add_child(OBJECT(machine), "master-display", OBJECT(display));
        sysbus_realize_and_unref(SYS_BUS_DEVICE(display), &error_fatal);
        memory_region_add_subregion_overlap(view, 0x20140000,
            sysbus_mmio_get_region(SYS_BUS_DEVICE(display), 0), 1);
        for (unsigned line = 0; line < 2; line++) {
            sysbus_connect_irq(SYS_BUS_DEVICE(display), line,
                               qdev_get_gpio_in(gic, 112 - line - 32));
        }
        /* Frame-timed completion edges for the recovered output lines
         * 48/52 (channel 1 bits 16/20) when display-complete is set. */
        qdev_connect_gpio_out_named(config, "display-complete", 0,
                                    qdev_get_gpio_in_named(display,
                                                           "output-event", 48));
        qdev_connect_gpio_out_named(config, "display-complete", 1,
                                    qdev_get_gpio_in_named(display,
                                                           "output-event", 52));
        DeviceState *graphics = qdev_new("nikon-z72-graphics");
        object_property_add_child(OBJECT(machine), "master-graphics", OBJECT(graphics));
        object_property_set_link(OBJECT(graphics), "root", OBJECT(view), &error_fatal);
        sysbus_realize_and_unref(SYS_BUS_DEVICE(graphics), &error_fatal);
        memory_region_add_subregion_overlap(view, 0x20180000,
            sysbus_mmio_get_region(SYS_BUS_DEVICE(graphics), 0), 1);
        for (unsigned line = 0; line < 3; line++) {
            sysbus_connect_irq(SYS_BUS_DEVICE(graphics), line,
                               qdev_get_gpio_in(gic, 129 + line - 32));
        }
    }
    object_property_set_link(OBJECT(counter), "cpu", OBJECT(cpus[0]), &error_fatal);
    sysbus_realize_and_unref(SYS_BUS_DEVICE(counter), &error_fatal);
    memory_region_add_subregion(&NIKON_Z72_BOOT_CONFIG(config)->banks[0],
                                Z72_COUNTER_BASE - 0x04200000,
                                sysbus_mmio_get_region(SYS_BUS_DEVICE(counter), 0));
    DeviceState *uart = qdev_new("nikon-z72-uart");
    if (chardev_id) {
        /* In the dual-engine machine only the selected engine's console
         * owns the character backend; the other transmitter stays quiet. */
        qdev_prop_set_chr(uart, "chardev", qemu_chr_find(chardev_id));
    }
    sysbus_realize_and_unref(SYS_BUS_DEVICE(uart), &error_fatal);
    memory_region_add_subregion(view, 0x2c090000,
                                sysbus_mmio_get_region(SYS_BUS_DEVICE(uart), 0));
    DeviceState *spi = qdev_new("nikon-z72-spi");
    NIKON_Z72_BOOT_CONFIG(config)->serial = spi;
    qdev_prop_set_string(spi, "bus-name", own_file ? "master-spi" : "slave-spi");
    if (object_dynamic_cast(OBJECT(machine), TYPE_NIKON_Z72_DUAL) &&
        NIKON_Z72_DUAL(machine)->controller_link && own_file) {
        qdev_prop_set_bit(spi, "peer-low-byte-first", true);
    }
    sysbus_realize_and_unref(SYS_BUS_DEVICE(spi), &error_fatal);
    memory_region_add_subregion_overlap(view, 0x2c0a0000,
        sysbus_mmio_get_region(SYS_BUS_DEVICE(spi), 0), 1);
    for (unsigned channel = 0; channel < 11; channel++) {
        sysbus_connect_irq(SYS_BUS_DEVICE(spi), channel * 2,
                           qdev_get_gpio_in(gic, 193 + channel * 2 - 32));
        sysbus_connect_irq(SYS_BUS_DEVICE(spi), channel * 2 + 1,
                           qdev_get_gpio_in(gic, 192 + channel * 2 - 32));
    }
    DeviceState *delay = qdev_new("nikon-z72-delay");
    sysbus_realize_and_unref(SYS_BUS_DEVICE(delay), &error_fatal);
    memory_region_add_subregion_overlap(view, 0x2c010000,
        sysbus_mmio_get_region(SYS_BUS_DEVICE(delay), 0), 1);
    for (unsigned channel = 0; channel < 12; channel++) {
        sysbus_connect_irq(SYS_BUS_DEVICE(delay), channel,
                           qdev_get_gpio_in(gic, 172 + channel - 32));
    }
    DeviceState *i2c = qdev_new("nikon-z72-i2c");
    qdev_prop_set_string(i2c, "bus-name", slave ? "slave-i2c" : "master-i2c");
    sysbus_realize_and_unref(SYS_BUS_DEVICE(i2c), &error_fatal);
    memory_region_add_subregion_overlap(view, 0x2c018000,
        sysbus_mmio_get_region(SYS_BUS_DEVICE(i2c), 0), 1);
    for (unsigned channel = 0; channel < 4; channel++) {
        sysbus_connect_irq(SYS_BUS_DEVICE(i2c), channel,
                           qdev_get_gpio_in(gic, 214 + channel - 32));
    }
    /* Laboratory notification source: probe-driven GIC line control used to
     * identify which interrupt the stock handoff wait expects. The private
     * peripheral tail word is otherwise unassigned. */
    DeviceState *notify = qdev_new("nikon-z72-notify");
    object_property_set_link(OBJECT(notify), "intc", OBJECT(gic), &error_fatal);
    sysbus_realize_and_unref(SYS_BUS_DEVICE(notify), &error_fatal);
    memory_region_add_subregion(view, 0x04009000,
                                sysbus_mmio_get_region(SYS_BUS_DEVICE(notify), 0));
    /* Generic loader supplies images and initial PC explicitly. Unmapped
     * accesses outside the supported configuration words remain unmapped. */
    return config;
}

static void nikon_z72_init(MachineState *machine)
{
    nikon_z72_context_init(machine, nikon_z72_windows,
                          G_N_ELEMENTS(nikon_z72_windows));
}

static void nikon_z72_slave_init(MachineState *machine)
{
    nikon_z72_context_init(machine, nikon_z72_slave_windows,
                          G_N_ELEMENTS(nikon_z72_slave_windows));
}

/* Dual-engine machine: each CPU pair has its own bus view. Communication
 * RAM is shared through the native and translated addresses used by the
 * firmware. Readiness pins and transport notifications connect the two
 * engines; physical timing and payload lane transfers remain unmodeled. */
static void nikon_z72_dual_init(MachineState *machine)
{
    NikonZ72DualMachine *s = NIKON_Z72_DUAL(machine);
    if (machine->smp.cpus != 4) {
        error_setg(&error_fatal, "Dual-engine machine requires four engine cores");
    }
    if (s->controller_link && !s->controller_firmware) {
        error_setg(&error_fatal, "Controller link requires a controller firmware image");
    }
    if (s->controller_step_link && !s->controller_link) {
        error_setg(&error_fatal, "Controller step link requires the controller link");
    }
    if (s->controller_inputs.flash_data && !s->controller_firmware) {
        error_setg(&error_fatal, "Controller flash data requires a controller firmware image");
    }
    if (s->controller_inputs.supply_data && !s->controller_firmware) {
        error_setg(&error_fatal, "Controller supply data requires a controller firmware image");
    }
    if (s->controller_inputs.battery_peer && !s->controller_firmware) {
        error_setg(&error_fatal, "Controller battery peer requires a controller firmware image");
    }
    if (s->controller_firmware) {
        /* The embedded core adds an execution slot beyond the engine topology. */
        machine->smp.max_cpus = MAX(machine->smp.max_cpus, 5);
    }
    MemoryRegion *master_view = g_new0(MemoryRegion, 1);
    MemoryRegion *slave_view = g_new0(MemoryRegion, 1);
    memory_region_init(master_view, NULL, "z72-dual-master-view", UINT64_MAX);
    memory_region_init(slave_view, NULL, "z72-dual-slave-view", UINT64_MAX);
    MemoryRegion *master_message = g_new0(MemoryRegion, 1);
    MemoryRegion *slave_message = g_new0(MemoryRegion, 1);
    memory_region_init_ram(master_message, NULL, "z72-shared-master-message",
                           0x00100000, &error_fatal);
    memory_region_init_ram(slave_message, NULL, "z72-shared-slave-message",
                           0x00100000, &error_fatal);
    DeviceState *master_config =
        nikon_z72_engine_init(machine, master_view, nikon_z72_windows,
                              G_N_ELEMENTS(nikon_z72_windows), master_message,
                              "z72-console", true, s->master_boot_image,
                              s->master_boot_aux);
    DeviceState *slave_config =
        nikon_z72_engine_init(machine, slave_view, nikon_z72_slave_windows,
                          G_N_ELEMENTS(nikon_z72_slave_windows), slave_message,
                          NULL, false, s->slave_boot_image, s->slave_boot_aux);
    /* Communication initialization uses master bank 6 bit 3 and slave
     * bank 8 bit 10. The board connects the two readiness signals; this
     * wiring is inferred from the complementary firmware startup paths. */
    NIKON_Z72_BOOT_CONFIG(master_config)->peer_connected = true;
    NIKON_Z72_BOOT_CONFIG(slave_config)->peer_connected = true;
    NIKON_Z72_BOOT_CONFIG(master_config)->peer = NIKON_Z72_BOOT_CONFIG(slave_config);
    NIKON_Z72_BOOT_CONFIG(slave_config)->peer = NIKON_Z72_BOOT_CONFIG(master_config);
    qdev_connect_gpio_out(slave_config, 0, qdev_get_gpio_in(master_config, 0));
    qdev_connect_gpio_out(master_config, 0, qdev_get_gpio_in(slave_config, 0));
    /* Peer visibility: each engine's communication RAM at its native
     * address inside the other engine's view. A region belongs to one
     * container, so the peer view receives aliases of the same storage. */
    MemoryRegion *master_alias = g_new0(MemoryRegion, 1);
    memory_region_init_alias(master_alias, NULL, "z72-master-message-peer",
                             master_message, 0, 0x00100000);
    memory_region_add_subregion(slave_view, 0xB7C00000, master_alias);
    /* The peer address table maps the master's B0000000 family into the
     * slave's 40000000 bus window. Alias the container so RAM gaps remain
     * unmapped and writes reach the owner's existing backing storage. */
    MemoryRegion *master_bus_alias = g_new0(MemoryRegion, 1);
    memory_region_init_alias(master_bus_alias, NULL, "z72-master-memory-peer",
                             master_view, 0xB0000000, 0x10000000);
    memory_region_add_subregion_overlap(slave_view, 0x40000000,
                                        master_bus_alias, -1);
    /* File reads request the inverse copy: the master accesses slave
     * C0000000-family RAM through the same 40000000 bus-address family. */
    MemoryRegion *slave_bus_alias = g_new0(MemoryRegion, 1);
    memory_region_init_alias(slave_bus_alias, NULL, "z72-slave-memory-peer",
                             slave_view, 0xC0000000, 0x10000000);
    memory_region_add_subregion_overlap(master_view, 0x40000000,
                                        slave_bus_alias, -1);
    /* The master's own frame pool includes 0xC6000000. Its peer message
     * access uses the translated 0x46000000 window, preserving that pool. */
    /* Runtime pointer translation supplies bus-visible message addresses.
     * Those aliases resolve to the native headers in the same shared RAM;
     * the two roles use different translations for the master's header. */
    MemoryRegion *views[] = { master_view, slave_view };
    MemoryRegion *messages[] = { master_message, slave_message };
    const hwaddr bus_addresses[] = { 0x37C00000, 0x46000000 };
    for (unsigned engine = 0; engine < 2; engine++) {
        for (unsigned owner = 0; owner < 2; owner++) {
            if (engine == 1 && owner == 1) {
                /* This address belongs to the slave's master RAM alias. */
                continue;
            }
            MemoryRegion *alias = g_new0(MemoryRegion, 1);
            memory_region_init_alias(alias, NULL, "z72-message-bus-alias",
                                     messages[owner], 0, 0x00100000);
            memory_region_add_subregion(views[engine], bus_addresses[owner], alias);
        }
        MemoryRegion *alias = g_new0(MemoryRegion, 1);
        memory_region_init_alias(alias, NULL, "z72-master-message-link-alias",
                                 master_message, 0, 0x00100000);
        memory_region_add_subregion(views[engine], 0x47C00000, alias);
    }
    /* One shared peer-descriptor file at 0x04280000: the slave engine
     * addresses the master instance's window in its own view. */
    NikonZ72BootConfig *master_boot = NIKON_Z72_BOOT_CONFIG(master_config);
    MemoryRegion *file_alias = g_new0(MemoryRegion, 1);
    MemoryRegion *pair_alias = g_new0(MemoryRegion, 1);
    memory_region_init_alias(file_alias, NULL, "z72-shared-peer-file",
                             &master_boot->file_ram, 0, 0x100);
    memory_region_init_alias(pair_alias, NULL, "z72-shared-peer-pairs",
                             &master_boot->pair_ram, 0, 0x100);
    memory_region_add_subregion(slave_view, 0x04280000, file_alias);
    memory_region_add_subregion(slave_view, 0x04281200, pair_alias);
    if (s->controller_firmware) {
        Object *owner = object_new(TYPE_CONTAINER);
        object_property_add_child(OBJECT(machine), "controller", owner);
        object_unref(owner);
        MemoryRegion *controller_view = g_new0(MemoryRegion, 1);
        memory_region_init(controller_view, owner, "z72-controller-private-view", UINT64_MAX);
        nikon_z72_controller_create(owner, controller_view, &s->controller_inputs,
                                    ARM_CPU_TYPE_NAME("cortex-m4"), s->controller_firmware);
        if (s->controller_link) {
            master_boot->controller_connected = true;
            qdev_connect_gpio_out_named(master_config, "controller-ack", 0,
                qdev_get_gpio_in(s->controller_inputs.gpio[6], 6));
            if (s->controller_step_link) {
                /* Functional connection hypothesis: native output 0x65 to
                 * the controller's verified G8 step input. */
                qdev_connect_gpio_out_named(master_config, "controller-step", 0,
                    qdev_get_gpio_in(s->controller_inputs.gpio[6], 8));
            }
            static const unsigned ports[] = { 1, 4, 3 }, pins[] = { 14, 3, 12 };
            for (unsigned i = 0; i < 3; i++) {
                qdev_connect_gpio_out(s->controller_inputs.gpio[ports[i]], pins[i],
                    qdev_get_gpio_in_named(master_config, "controller-input", i));
            }
            for (unsigned port = 0; port < 2; port++) {
                DeviceState *peer = qdev_new("nikon-z72-controller-spi-peer");
                object_property_set_link(OBJECT(peer), "controller",
                                         OBJECT(s->controller_inputs.spi[port]), &error_fatal);
                qdev_realize_and_unref(peer, qdev_get_child_bus(master_boot->serial,
                    port ? "master-spi1" : "master-spi0"), &error_fatal);
            }
        }
    }
}

static void nikon_z72_class_init(MachineClass *mc)
{
    mc->desc = "Nikon Z7 II C1.70 master instruction laboratory";
    mc->init = nikon_z72_init;
    mc->default_cpu_type = ARM_CPU_TYPE_NAME("cortex-a7");
    mc->default_cpus = 1;
    mc->max_cpus = 2;
    mc->no_serial = true;
    mc->no_parallel = true;
}
DEFINE_MACHINE_ARM("nikon-z72-lab", nikon_z72_class_init)

static void nikon_z72_slave_class_init(MachineClass *mc)
{
    nikon_z72_class_init(mc);
    mc->desc = "Nikon Z7 II C1.70 isolated slave instruction laboratory";
    mc->init = nikon_z72_slave_init;
}
DEFINE_MACHINE_ARM("nikon-z72-slave-lab", nikon_z72_slave_class_init)

static void nikon_z72_dual_class_init(MachineClass *mc)
{
    nikon_z72_class_init(mc);
    mc->desc = "Nikon Z7 II C1.70 dual-engine laboratory";
    mc->init = nikon_z72_dual_init;
    mc->default_cpus = 4;
    mc->max_cpus = 5;
}
static void dual_machine_class_init(ObjectClass *klass, const void *data)
{
    nikon_z72_dual_class_init(MACHINE_CLASS(klass));
    object_class_property_add_str(klass, "controller-firmware", dual_controller_firmware_get,
                                 dual_controller_firmware_set);
    object_class_property_set_description(klass, "controller-firmware",
        "Private controller firmware in a separate address space");
    object_class_property_add_str(klass, "controller-flash-data", dual_controller_flash_data_get,
                                 dual_controller_flash_data_set);
    object_class_property_set_description(klass, "controller-flash-data",
        "Explicit resident data for the controller empty flash window");
    object_class_property_add_str(klass, "controller-supply-data", dual_controller_supply_data_get,
                                 dual_controller_supply_data_set);
    object_class_property_set_description(klass, "controller-supply-data",
        "Experimental supply response records for the controller");
    object_class_property_add_bool(klass, "controller-link", dual_controller_link_get,
                                  dual_controller_link_set);
    object_class_property_set_description(klass, "controller-link",
        "Experimental serial peers and controller readiness inputs");
    object_class_property_add_bool(klass, "controller-step-link", dual_controller_step_link_get,
                                  dual_controller_step_link_set);
    object_class_property_set_description(klass, "controller-step-link",
        "Experimental engine handshake output to controller G8 connection");
    object_class_property_add_bool(klass, "controller-battery-peer",
                                  dual_controller_battery_peer_get,
                                  dual_controller_battery_peer_set);
    object_class_property_set_description(klass, "controller-battery-peer",
        "Answer original battery serial exchanges with a synthetic peer");
    object_class_property_add_str(klass, "master-boot-image",
                                  dual_master_boot_image_get,
                                  dual_master_boot_image_set);
    object_class_property_set_description(klass, "master-boot-image",
        "Master engine firmware image reloaded at every machine reset");
    object_class_property_add_str(klass, "slave-boot-image",
                                  dual_slave_boot_image_get,
                                  dual_slave_boot_image_set);
    object_class_property_set_description(klass, "slave-boot-image",
        "Slave engine firmware image reloaded at every machine reset");
    object_class_property_add_str(klass, "master-boot-aux",
                                  dual_master_boot_aux_get,
                                  dual_master_boot_aux_set);
    object_class_property_set_description(klass, "master-boot-aux",
        "Comma separated path@address master boot files reloaded at reset");
    object_class_property_add_str(klass, "slave-boot-aux",
                                  dual_slave_boot_aux_get,
                                  dual_slave_boot_aux_set);
    object_class_property_set_description(klass, "slave-boot-aux",
        "Comma separated path@address slave boot files reloaded at reset");
}

static void dual_machine_instance_init(Object *obj)
{
    NIKON_Z72_DUAL(obj)->controller_inputs.power_switch = true;
}

static void dual_machine_finalize(Object *obj)
{
    g_free(NIKON_Z72_DUAL(obj)->controller_firmware);
    g_free(NIKON_Z72_DUAL(obj)->master_boot_image);
    g_free(NIKON_Z72_DUAL(obj)->slave_boot_image);
    g_free(NIKON_Z72_DUAL(obj)->master_boot_aux);
    g_free(NIKON_Z72_DUAL(obj)->slave_boot_aux);
    g_free(NIKON_Z72_DUAL(obj)->controller_inputs.flash_data);
    g_free(NIKON_Z72_DUAL(obj)->controller_inputs.supply_data);
}

static void dual_machine_register(void)
{
    static const TypeInfo info = {
        .name = TYPE_NIKON_Z72_DUAL, .parent = TYPE_MACHINE,
        .interfaces = arm_machine_interfaces,
        .instance_size = sizeof(NikonZ72DualMachine),
        .instance_init = dual_machine_instance_init,
        .instance_finalize = dual_machine_finalize,
        .class_init = dual_machine_class_init,
    };
    type_register_static(&info);
}
type_init(dual_machine_register)
