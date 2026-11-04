/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Finite normal-family virtual 50 mm F2.8 lens and motor history stream. */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qapi/visitor.h"
#include "qemu/bswap.h"
#include "qemu/log.h"
#include "qemu/timer.h"
#include "hw/irq.h"
#include "hw/qdev-properties.h"
#include "hw/ssi/ssi.h"
#include "nikon-z72-spi.h"
#include "trace.h"

#include "migration/vmstate.h"

#define LENS_MAX_PACKET 7426
#define LENS_PHASE_NS 1000000
#define LENS_CONFIG_NS 2000000
#define LENS_MODE_NS 2000000
#define LENS_STREAM_NS 1000000
#define LENS_WORD_NS 4000
#define LENS_APERTURE_OPEN 960
#define LENS_APERTURE_RANGE 1152
#define LENS_APERTURE_STEP_NS 20000000
#define LENS_APERTURE_MIN_NS 2000000
#define LENS_FOCUS_MIN -4096
#define LENS_FOCUS_MAX 4096
#define LENS_FOCUS_STEP_NS 100000
#define LENS_FOCUS_MIN_NS 2000000
#define TYPE_Z72_LENS "nikon-z72-lens"
OBJECT_DECLARE_SIMPLE_TYPE(Z72Lens, Z72_LENS)

typedef enum LensPhase {
    LENS_HEADER,
    LENS_PAYLOAD,
    LENS_ERROR,
} LensPhase;

struct Z72Lens {
    SSIPeripheral parent_obj;
    DeviceState *stream;
    qemu_irq notify;
    QEMUTimer *phase_timer, *operation_timer, *stream_timer, *mode_timer;
    QEMUTimer *aperture_timer, *focus_timer;
    uint8_t header[8], input[LENS_MAX_PACKET], output[LENS_MAX_PACKET];
    uint8_t configuration[12], history[42];
    unsigned offset, size;
    LensPhase phase;
    uint32_t sync_anchor;
    uint8_t probe;
    unsigned history_offset;
    uint8_t history_sequence;
    int64_t history_start, stream_deadline;
    uint64_t completed, rejected, configuration_generation;
    uint64_t stream_frames;
    uint64_t aperture_noops;
    uint64_t aperture_generation;
    uint64_t focus_noops;
    uint64_t focus_generation;
    uint16_t aperture, aperture_start, aperture_target;
    int32_t focus_position, focus_start, focus_target;
    int64_t aperture_begin, aperture_duration;
    int64_t focus_begin, focus_duration;
    uint64_t mode_generation;
    uint8_t mode, requested_mode;
    uint64_t header_counts[256], packet_counts[256];
    bool configured, pending, stream_enabled, notify_level, reported;
    bool mode_pending;
    bool aperture_pending;
    bool focus_pending;
};

static int32_t lens_focus_position(Z72Lens *s)
{
    int64_t elapsed;
    int32_t distance, moved;

    if (!s->focus_pending) {
        return s->focus_position;
    }
    elapsed = MIN(qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) - s->focus_begin,
                  s->focus_duration);
    distance = abs(s->focus_target - s->focus_start);
    moved = (int64_t)distance * elapsed / s->focus_duration;
    return s->focus_target >= s->focus_start ?
        s->focus_start + moved : s->focus_start - moved;
}

static void lens_focus_done(void *opaque)
{
    Z72Lens *s = opaque;

    s->focus_position = s->focus_target;
    s->focus_pending = false;
    s->focus_generation++;
}

static void lens_get_focus_position(Object *obj, Visitor *v, const char *name,
                                    void *opaque, Error **errp)
{
    Z72Lens *s = Z72_LENS(obj);
    int32_t value = lens_focus_position(s);

    visit_type_int32(v, name, &value, errp);
}

static void lens_get_focus_target(Object *obj, Visitor *v, const char *name,
                                  void *opaque, Error **errp)
{
    Z72Lens *s = Z72_LENS(obj);
    int32_t value = s->focus_target;

    visit_type_int32(v, name, &value, errp);
}

static bool lens_get_focus_pending(Object *obj, Error **errp)
{
    Z72Lens *s = Z72_LENS(obj);

    return s->focus_pending;
}

static uint16_t lens_aperture_position(Z72Lens *s)
{
    int64_t elapsed;
    unsigned distance, moved;

    if (!s->aperture_pending) {
        return s->aperture;
    }
    elapsed = MIN(qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) - s->aperture_begin,
                  s->aperture_duration);
    distance = abs((int)s->aperture_target - s->aperture_start);
    moved = distance * elapsed / s->aperture_duration;
    return s->aperture_target >= s->aperture_start ?
        s->aperture_start + moved : s->aperture_start - moved;
}

static void lens_aperture_done(void *opaque)
{
    Z72Lens *s = opaque;

    s->aperture = s->aperture_target;
    s->aperture_pending = false;
    s->aperture_generation++;
    trace_z72_lens_iris_complete(qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),
                                 s->aperture, s->aperture_generation);
}

static void lens_get_aperture_position(Object *obj, Visitor *v,
                                       const char *name, void *opaque,
                                       Error **errp)
{
    Z72Lens *s = Z72_LENS(obj);
    uint16_t value = lens_aperture_position(s);

    visit_type_uint16(v, name, &value, errp);
}

static void lens_get_aperture_target(Object *obj, Visitor *v,
                                     const char *name, void *opaque,
                                     Error **errp)
{
    Z72Lens *s = Z72_LENS(obj);
    uint16_t value = s->aperture_target;

    visit_type_uint16(v, name, &value, errp);
}

static bool lens_get_aperture_pending(Object *obj, Error **errp)
{
    Z72Lens *s = Z72_LENS(obj);

    return s->aperture_pending;
}

static void lens_notify(Z72Lens *s, bool level)
{
    s->notify_level = level;
    qemu_set_irq(s->notify, level);

}

static bool lens_checksum(const uint8_t *bytes, unsigned size)
{
    unsigned sum = 0;

    for (unsigned i = 0; i < size; i++) {
        sum += bytes[i];
    }
    return !(sum & 0xff);
}

static void lens_finish_packet(uint8_t *bytes, unsigned size)
{
    unsigned sum = 0;

    bytes[0] = 0x55;
    for (unsigned i = 0; i < size - 1; i++) {
        sum += bytes[i];
    }
    bytes[size - 1] = -sum;
}

static void lens_error(Z72Lens *s, const char *reason)
{
    s->phase = LENS_ERROR;
    s->rejected++;
    timer_del(s->phase_timer);
    /* A rejected packet has no successful phase-completion edge. */
    lens_notify(s, true);
    if (!s->reported) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "nikon-lens: %s command=%02x:%02x mode=%02x size=%u\n",
                      reason, s->header[3], s->header[4],
                      s->header[2], s->size);
        s->reported = true;
    }
}

static unsigned lens_packet_size(uint8_t command, uint8_t subcommand)
{
    if (command == 0x24) {
        return subcommand == 0 ? 7426 : subcommand == 0x10 ? 3468 : 0;
    }
    if (command == 0x20) {
        return subcommand == 0 ? 258 : subcommand == 1 ? 24 : 0;
    }
    if (command == 0x78) {
        return subcommand < 3 ? 4 : 0;
    }
    if (command == 0xa0) {
        return subcommand < 8 ? 24 : 0;
    }
    if (command == 0xa3) {
        return subcommand < 2 ? 4 : 0;
    }
    if (subcommand) {
        return 0;
    }
    switch (command) {
    case 0x10: return 28;
    case 0x11: return 74;
    case 0x12: return 66;
    case 0x13: return 14;
    case 0x15: return 6;
    case 0x16: return 4;
    case 0x1f: return 4;
    case 0x21: return 6;
    case 0x27: return 6;
    case 0x50:
    case 0x51: return 4;
    case 0x70:
    case 0x71: return 14;
    case 0xa1: return 10;
    default: return 0;
    }
}

static void lens_response(Z72Lens *s)
{
    uint8_t *out = s->output;

    /* Explicit virtual inputs; unnamed zero coordinates are documented. */
    memset(out, 0, s->size);
    switch (s->header[3]) {
    case 0x10:
        stw_le_p(out + 1, 0x7ffe); /* Explicit virtual identity. */
        stl_le_p(out + 3, 1);
        out[12] = 3;
        break;
    case 0x12:
        /* Both focal endpoints are 50 mm at F2.8: Av=3, raw=384+192*3. */
        stw_le_p(out + 1, 960);
        stw_le_p(out + 3, 960);
        stw_le_p(out + 7, 50);
        stw_le_p(out + 11, 50);
        out[25] = 1;
        break;
    case 0x15:
        out[1] = s->pending ? 1 : 0;
        out[2] = s->configured ? 0 : 1;
        break;
    case 0x16:
        out[1] = 15;
        break;
    case 0x1f:
        out[2] = 1; /* Ordinary family, supported negotiation endpoint. */
        break;
    case 0x20:
        if (!s->header[4]) {
            static const unsigned aperture[] = { 1, 9, 15, 162, 164 };

            for (unsigned i = 0; i < ARRAY_SIZE(aperture); i++) {
                stw_le_p(out + aperture[i], 960);
            }
            /* Source-joined current coordinates; other APEX fields stay fixed. */
            stw_le_p(out + 9, LENS_APERTURE_OPEN + lens_aperture_position(s));
            stw_le_p(out + 197, lens_aperture_position(s));
            stw_le_p(out + 199, LENS_APERTURE_RANGE);
            stw_le_p(out + 201, (int16_t)lens_focus_position(s));
            out[169] = s->configured ? 0x40 : 0x20;
            out[203] = (s->pending ? 8 : 0) |
                (s->aperture_pending ? 0x18 : 0) |
                (s->focus_pending ? 2 : 0);
            /* Fixed optics remain usable; configuration busy is separate. */
            out[216] = 3;
        } else {
            stw_le_p(out + 1, 960);
            stw_le_p(out + 3, 960);
            stw_le_p(out + 7, 50);
        }
        break;
    case 0x27:
        stl_le_p(out + 1, s->sync_anchor);
        break;
    case 0x51:
        out[1] = s->mode_pending ? 0x80 : 0;
        break;
    case 0x71:
        out[1] = s->focus_pending ? 2 : 0;
        stl_le_p(out + 2, (uint32_t)lens_focus_position(s));
        break;
    case 0x70:
    case 0x78:
        break;
    case 0x24:
        /*
         * Zero higher-order radial coefficients retain r'=r. The other
         * zero sentinel selects the original Q15-unity response path.
         */
        if (!s->header[4]) {
            out[7385] = 1; /* Explicit 27-float representation. */
        }
        break;
    default:
        break;
    }
    lens_finish_packet(out, s->size);
}

static void lens_operation_done(void *opaque)
{
    Z72Lens *s = opaque;

    s->pending = false;
    s->configured = true;
    s->configuration_generation++;
}

static void lens_mode_done(void *opaque)
{
    Z72Lens *s = opaque;

    s->mode = s->requested_mode;
    s->mode_pending = false;
    s->mode_generation++;
}

static void lens_stream_word(void *opaque)
{
    Z72Lens *s = opaque;
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);

    if (!s->stream_enabled) {
        return;
    }
    if (!s->history_offset) {
        int32_t pos = lens_focus_position(s);

        memset(s->history, 0, sizeof(s->history));
        s->history[1] = s->history_sequence;
        stl_le_p(s->history + 2, (uint32_t)pos);
        if (pos >= LENS_FOCUS_MAX) {
            s->history[7] = 1;
        } else if (pos <= LENS_FOCUS_MIN) {
            s->history[7] = 2;
        }
        lens_finish_packet(s->history, sizeof(s->history));
        s->history_start = s->stream_deadline;
    }
    if (!nikon_z72_spi_receive(s->stream, 2,
                               lduw_le_p(s->history + s->history_offset), 16)) {
        s->stream_deadline = now + LENS_STREAM_NS;
    } else {
        s->history_offset += 2;
        if (s->history_offset == sizeof(s->history)) {
            s->history_offset = 0;
            s->history_sequence++;
            s->stream_frames++;
            s->stream_deadline = MAX(now + LENS_WORD_NS,
                                     s->history_start + LENS_STREAM_NS);
        } else {
            s->stream_deadline += LENS_WORD_NS;
        }
    }
    timer_mod(s->stream_timer, s->stream_deadline);
}

static bool lens_process(Z72Lens *s)
{
    const uint8_t *in = s->input;

    if (in[0] != 0x55 || !lens_checksum(in, s->size)) {
        lens_error(s, "payload-checksum-not-supported");
        return false;
    }
    switch (s->header[3]) {
    case 0x1f:
        if ((in[1] != 1 && in[1] != 2) || in[2]) {
            lens_error(s, "probe-not-supported");
            return false;
        }
        s->probe = in[1];
        break;
    case 0x13:
        if ((in[1] & ~0x1f) || (in[4] & ~0x3f) || s->pending) {
            lens_error(s, "configuration-not-supported");
            return false;
        }
        memcpy(s->configuration, in + 1, sizeof(s->configuration));
        s->pending = true;
        timer_mod(s->operation_timer,
                  qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + LENS_CONFIG_NS);
        break;
    case 0x16:
        if (in[1] > 1 || (in[1] && !s->stream)) {
            lens_error(s, "stream-control-not-supported");
            return false;
        }
        if (s->stream_enabled == !!in[1]) {
            break;
        }
        s->stream_enabled = in[1];
        timer_del(s->stream_timer);
        if (s->stream_enabled) {
            s->stream_deadline = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                (s->history_offset ? LENS_WORD_NS : LENS_STREAM_NS);
            timer_mod(s->stream_timer, s->stream_deadline);
        }
        break;
    case 0x21:
        s->sync_anchor = ldl_le_p(in + 1);
        break;
    case 0x50:
        /* 103130aa emits selectors0/1/2, independently of configuration. */
        if (in[1] > 2 || in[2] || s->mode_pending) {
            lens_error(s, "mode-request-not-supported");
            return false;
        }
        s->requested_mode = in[1];
        s->mode_pending = true;
        timer_mod(s->mode_timer,
                  qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + LENS_MODE_NS);
        break;
    case 0xa0:
    case 0xa1:
    case 0xa3:
    {
        unsigned target = lduw_le_p(in + 1);
        unsigned distance;

        if (!s->configured || s->pending || s->aperture_pending) {
            lens_error(s, "aperture-state-not-supported");
            return false;
        }
        if (target > LENS_APERTURE_RANGE) {
            lens_error(s, "aperture-target-not-supported");
            return false;
        }
        if (s->header[3] == 0xa1) {
            unsigned parameter = lduw_le_p(in + 3);

            /* 10310f64's default is ffff; other rates/times are unresolved. */
            if ((parameter != UINT16_MAX &&
                 (parameter || target || s->aperture)) ||
                ldl_le_p(in + 5)) {
                lens_error(s, "aperture-parameters-not-supported");
                return false;
            }
        } else {
            for (unsigned i = 3; i < s->size - 1; i++) {
                if (in[i]) {
                    lens_error(s, "aperture-tail-not-supported");
                    return false;
                }
            }
        }
        distance = abs((int)target - s->aperture);
        if (!distance) {
            trace_z72_lens_iris_request(qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),
                s->header[3], s->header[4], s->aperture, target, 0, false);
            s->aperture_noops++;
            break;
        }
        s->aperture_start = s->aperture;
        s->aperture_target = target;
        s->aperture_begin = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
        /* Explicit virtual mechanics: 20 ms/stop, minimum 2 ms per move. */
        s->aperture_duration = MAX(LENS_APERTURE_MIN_NS,
            (LENS_APERTURE_STEP_NS * (int64_t)distance + 191) / 192);
        trace_z72_lens_iris_request(s->aperture_begin, s->header[3], s->header[4],
            s->aperture_start, target, s->aperture_duration, true);
        s->aperture_pending = true;
        timer_mod(s->aperture_timer,
                  s->aperture_begin + s->aperture_duration);
        break;
    }
    case 0x70:
    {
        int32_t current = lens_focus_position(s);
        int64_t target;
        unsigned distance;

        if (!s->configured || s->pending || s->focus_pending) {
            lens_error(s, "focus-state-not-supported");
            return false;
        }
        if (in[1] == 0) {
            target = (int32_t)ldl_le_p(in + 2);
        } else if (in[1] == 1) {
            target = (int64_t)current + (int32_t)ldl_le_p(in + 2);
        } else if (in[1] == 2) {
            target = (int32_t)ldl_le_p(in + 6);
        } else if (in[1] == 3) {
            target = (int64_t)current + (int32_t)ldl_le_p(in + 6);
        } else {
            lens_error(s, "focus-subcommand-not-supported");
            return false;
        }
        if (target < LENS_FOCUS_MIN || target > LENS_FOCUS_MAX) {
            lens_error(s, "focus-target-not-supported");
            return false;
        }
        distance = abs((int)target - current);
        if (!distance) {
            s->focus_noops++;
            break;
        }
        s->focus_start = current;
        s->focus_target = target;
        s->focus_begin = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
        s->focus_duration = MAX(LENS_FOCUS_MIN_NS,
                                (int64_t)distance * LENS_FOCUS_STEP_NS);
        s->focus_pending = true;
        timer_mod(s->focus_timer, s->focus_begin + s->focus_duration);
        break;
    }
    case 0x71:
        if (!s->configured || s->pending) {
            lens_error(s, "focus-state-not-supported");
            return false;
        }
        break;
    case 0x78:
        if (!s->configured || s->pending) {
            lens_error(s, "focus-state-not-supported");
            return false;
        }
        if (s->focus_pending) {
            s->focus_position = lens_focus_position(s);
            s->focus_target = s->focus_position;
            s->focus_pending = false;
            timer_del(s->focus_timer);
            s->focus_generation++;
        }
        break;
    default:
        break;
    }
    return true;
}

static void lens_phase_done(void *opaque)
{
    Z72Lens *s = opaque;

    if (s->phase != LENS_ERROR) {
        lens_notify(s, false);
    }
}

static uint32_t lens_transfer(SSIPeripheral *dev, uint32_t value)
{
    Z72Lens *s = Z72_LENS(dev);
    uint8_t result = 0;

    if (s->phase == LENS_ERROR) {
        return 0;
    }
    if (timer_pending(s->phase_timer) || value > UINT8_MAX) {
        lens_error(s, "word-or-phase-not-supported");
        return 0;
    }
    lens_notify(s, true);
    if (s->phase == LENS_HEADER) {
        s->header[s->offset++] = value;
        if (s->offset == sizeof(s->header)) {
            unsigned expected = lens_packet_size(s->header[3], s->header[4]);

            s->size = 2 * (unsigned)lduw_le_p(s->header + 5) + 2;
            if (s->header[0] != 0x55 || !lens_checksum(s->header, 8) ||
                !expected || s->size != expected ||
                (s->header[3] == 0x1f ? s->header[2] != 0xff :
                                       s->header[2] > 1)) {
                lens_error(s, "header-or-command-not-supported");
                return 0;
            }
            lens_response(s);
            s->header_counts[s->header[3]]++;
            s->phase = LENS_PAYLOAD;
            s->offset = 0;
            timer_mod(s->phase_timer,
                      qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + LENS_PHASE_NS);
        }
    } else {
        result = s->output[s->offset];
        s->input[s->offset++] = value;
        if (s->offset == s->size && lens_process(s)) {
            s->completed++;
            s->packet_counts[s->header[3]]++;
            s->phase = LENS_HEADER;
            s->offset = 0;
            timer_mod(s->phase_timer,
                      qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + LENS_PHASE_NS);
        }
    }
    return result;
}

static void lens_reset(DeviceState *dev)
{
    Z72Lens *s = Z72_LENS(dev);

    timer_del(s->phase_timer);
    timer_del(s->operation_timer);
    timer_del(s->stream_timer);
    timer_del(s->mode_timer);
    timer_del(s->aperture_timer);
    timer_del(s->focus_timer);
    s->phase = LENS_HEADER;
    s->offset = s->size = s->sync_anchor = 0;
    s->probe = 0;
    s->configured = s->pending = s->stream_enabled = s->reported = false;
    s->completed = s->rejected = s->configuration_generation = 0;
    s->stream_frames = s->history_offset = s->history_sequence = 0;
    s->aperture_noops = 0;
    s->aperture_generation = 0;
    s->aperture = s->aperture_start = s->aperture_target = 0;
    s->aperture_pending = false;
    s->aperture_begin = s->aperture_duration = 0;
    s->focus_noops = 0;
    s->focus_generation = 0;
    s->focus_position = s->focus_start = s->focus_target = 0;
    s->focus_pending = false;
    s->focus_begin = s->focus_duration = 0;
    s->mode = s->requested_mode = 0;
    s->mode_pending = false;
    s->mode_generation = 0;
    memset(s->configuration, 0, sizeof(s->configuration));
    memset(s->header_counts, 0, sizeof(s->header_counts));
    memset(s->packet_counts, 0, sizeof(s->packet_counts));
    memset(s->header, 0, sizeof(s->header));
    memset(s->input, 0, sizeof(s->input));
    memset(s->output, 0, sizeof(s->output));
    lens_notify(s, false);
}

static void lens_unrealize(DeviceState *dev)
{
    Z72Lens *s = Z72_LENS(dev);

    timer_del(s->phase_timer);
    timer_del(s->operation_timer);
    timer_del(s->stream_timer);
    timer_del(s->mode_timer);
    timer_del(s->aperture_timer);
    timer_del(s->focus_timer);
    s->aperture = lens_aperture_position(s);
    s->aperture_start = s->aperture_target = s->aperture;
    s->aperture_pending = false;
    s->focus_position = lens_focus_position(s);
    s->focus_start = s->focus_target = s->focus_position;
    s->focus_pending = false;
    s->stream_enabled = false;
    lens_notify(s, true);
}

static void lens_realize(SSIPeripheral *dev, Error **errp)
{
    Z72Lens *s = Z72_LENS(dev);
    if (!s->stream) {
        error_setg(errp, "Virtual lens requires its engine serial receiver");
    }
}

static char *lens_runtime(Object *obj, Error **errp)
{
    Z72Lens *s = Z72_LENS(obj);
    GString *text = g_string_new(NULL);

    g_string_append_printf(text,
        "phase=%u offset=%u/%u command=%02x:%02x mode=%02x notify=%u "
        "configured=%u pending=%u stream=%u history-offset=%u probe=%u\n",
        s->phase, s->offset, s->size, s->header[3], s->header[4],
        s->header[2], s->notify_level, s->configured, s->pending,
        s->stream_enabled, s->history_offset, s->probe);
    g_string_append_printf(text,
        "mode-state=%u requested-mode=%u mode-pending=%u mode-generation=%"
        PRIu64 "\n", s->mode, s->requested_mode, s->mode_pending,
        s->mode_generation);
    g_string_append_printf(text, "tx-prefix=%02x %02x %02x %02x\n",
        s->input[0], s->input[1], s->input[2], s->input[3]);
    g_string_append_printf(text,
        "aperture=%u target=%u aperture-pending=%u aperture-generation=%"
        PRIu64 "\n", lens_aperture_position(s), s->aperture_target,
        s->aperture_pending, s->aperture_generation);
    g_string_append_printf(text,
        "focus=%" PRId32 " target=%" PRId32 " focus-pending=%u "
        "focus-generation=%" PRIu64 " focus-noops=%" PRIu64 "\n",
        lens_focus_position(s), s->focus_target, s->focus_pending,
        s->focus_generation, s->focus_noops);
    for (unsigned i = 0; i < ARRAY_SIZE(s->header_counts); i++) {
        if (s->header_counts[i]) {
            g_string_append_printf(text,
                "%02x headers=%" PRIu64 " completed=%" PRIu64 "\n",
                i, s->header_counts[i], s->packet_counts[i]);
        }
    }
    return g_string_free(text, false);
}

static void lens_init(Object *obj)
{
    Z72Lens *s = Z72_LENS(obj);

    qdev_init_gpio_out_named(DEVICE(obj), &s->notify, "notify", 1);
    s->phase_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, lens_phase_done, s);
    s->operation_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                     lens_operation_done, s);
    s->stream_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, lens_stream_word, s);
    s->mode_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, lens_mode_done, s);
    s->aperture_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, lens_aperture_done, s);
    s->focus_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, lens_focus_done, s);
    object_property_add_uint64_ptr(obj, "completed", &s->completed,
                                    OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "rejected", &s->rejected,
                                    OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "configuration-generation",
                                   &s->configuration_generation,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "stream-frames", &s->stream_frames,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "aperture-noops", &s->aperture_noops,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "aperture-generation",
                                   &s->aperture_generation, OBJ_PROP_FLAG_READ);
    object_property_add(obj, "aperture-position", "uint16",
                        lens_get_aperture_position, NULL,
                        NULL, NULL);
    object_property_add(obj, "aperture-target", "uint16",
                        lens_get_aperture_target, NULL, NULL, NULL);
    object_property_add_bool(obj, "aperture-pending",
                             lens_get_aperture_pending, NULL);
    object_property_add_uint64_ptr(obj, "focus-noops", &s->focus_noops,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "focus-generation",
                                   &s->focus_generation, OBJ_PROP_FLAG_READ);
    object_property_add(obj, "focus-position", "int32",
                        lens_get_focus_position, NULL,
                        NULL, NULL);
    object_property_add(obj, "focus-target", "int32",
                        lens_get_focus_target, NULL, NULL, NULL);
    object_property_add_bool(obj, "focus-pending",
                             lens_get_focus_pending, NULL);
    object_property_add_uint64_ptr(obj, "mode-generation", &s->mode_generation,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_str(obj, "runtime", lens_runtime, NULL);
}

static void lens_finalize(Object *obj)
{
    Z72Lens *s = Z72_LENS(obj);

    timer_free(s->phase_timer);
    timer_free(s->operation_timer);
    timer_free(s->stream_timer);
    timer_free(s->mode_timer);
    timer_free(s->aperture_timer);
    timer_free(s->focus_timer);
}

static const Property lens_properties[] = {
    DEFINE_PROP_LINK("stream", Z72Lens, stream, "nikon-z72-spi",
                     DeviceState *),
};

static const VMStateDescription lens_vmstate = {
    .name = "nikon-lens", .unmigratable = true,
};

static void lens_class_init(ObjectClass *oc, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    SSIPeripheralClass *sc = SSI_PERIPHERAL_CLASS(oc);

    dc->vmsd = &lens_vmstate;
    dc->user_creatable = false;
    dc->unrealize = lens_unrealize;
    device_class_set_props(dc, lens_properties);
    device_class_set_legacy_reset(dc, lens_reset);
    sc->realize = lens_realize;
    sc->transfer = lens_transfer;
    sc->cs_polarity = SSI_CS_NONE;
}

static const TypeInfo lens_type = {
    .name = TYPE_Z72_LENS,
    .parent = TYPE_SSI_PERIPHERAL,
    .instance_size = sizeof(Z72Lens),
    .instance_init = lens_init,
    .instance_finalize = lens_finalize,
    .class_init = lens_class_init,
};

static void lens_register(void)
{
    type_register_static(&lens_type);
}
type_init(lens_register)
