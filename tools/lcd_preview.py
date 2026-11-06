# SPDX-License-Identifier: GPL-2.0-or-later
"""Read-only RGB preview of the modeled LCD planes, not physical scanout."""
from analyze.decode_z72 import require


def _rgb(y, u, v):
    # Inverse of the functional limited-range conversion in the renderer.
    c, d, e = max(0, y - 16), u - 128, v - 128
    return tuple(max(0, min(255, value >> 8)) for value in
                 (298 * c + 409 * e + 128,
                  298 * c - 100 * d - 208 * e + 128,
                  298 * c + 516 * d + 128))


def lcd_rgb(width, height, format_, luminance, chroma, overlay=None, alpha=None, *, alpha_bits=8):
    """Compose NV16/NV12 background and optional equal-size YYUV+A4/A8 UI.

    Each plane is a (bytes, byte stride) pair. The conversion and straight
    alpha composition follow the existing functional pixel backend; this
    does not apply the panel's programmable matrices or calibration tables.
    """
    require(0 < width <= 4096 and 0 < height <= 4096 and not width & 1 and
            format_ in (0, 4) and (format_ != 4 or not height & 1),
            'Unsupported display background format or geometry')
    require((overlay is None) == (alpha is None), 'Incomplete display overlay planes')
    require(alpha_bits in (4, 8), 'Unsupported display alpha depth')

    def check(plane, minimum, rows):
        data, stride = plane
        require(minimum <= stride <= 16384 and len(data) == stride * rows,
                'Invalid display plane stride or length')
        return data, stride

    y, ys = check(luminance, width, height)
    uv, uvs = check(chroma, width, height // 2 if format_ == 4 else height)
    if overlay is not None:
        foreground, fs = check(overlay, width * 2, height)
        opacity, os = check(alpha, width // 2 if alpha_bits == 4 else width, height)
    output = bytearray(width * height * 3)
    for row in range(height):
        uv_row = (row // 2 if format_ == 4 else row) * uvs
        for column in range(0, width, 2):
            u, v = uv[uv_row + column:uv_row + column + 2]
            for pixel in range(2):
                x = column + pixel
                color = _rgb(y[row * ys + x], u, v)
                if overlay is not None:
                    if alpha_bits == 4:
                        a = ((opacity[row * os + x // 2] >> ((x & 1) * 4)) & 15) * 17
                    else:
                        a = opacity[row * os + x]
                    if a:
                        at = row * fs + column * 2
                        front = _rgb(foreground[at + pixel], foreground[at + 2], foreground[at + 3])
                        color = tuple((f * a + b * (255 - a) + 127) // 255
                                      for f, b in zip(front, color))
                at = (row * width + x) * 3
                output[at:at + 3] = bytes(color)
    return bytes(output)


def read_display_planes(words, read_bytes, base):
    """Read the selected planes of a paused display bank for RGB composition."""
    geometry = words(base + 0x204, 1)[0]
    width, height = geometry & 0xffff, (geometry >> 16) & 0x3fff
    if not (0 < width <= 4096 and 0 < height <= 4096):
        raise ValueError('Display output geometry is not configured')
    format_ = words(base + 0x200, 1)[0] & 31
    if format_ not in (0, 4) or width & 1 or format_ == 4 and height & 1:
        raise ValueError('Unsupported display background format or geometry')

    def plane(address_register, stride_register, minimum_stride, rows=height):
        address = words(address_register, 1)[0]
        stride = words(stride_register, 1)[0]
        if not (minimum_stride <= stride <= 16384 and
                0xb0000000 <= address <= 0xf0000000 - stride * rows):
            raise ValueError('Display output plane is not configured')
        return bytes(read_bytes(address, stride * rows)), stride

    slot = (words(base + 0x260, 1)[0] >> 16) & 3
    luminance = plane(base + 0x210 + slot * 4, base + 0x240, width)
    chroma = plane(base + 0x220 + slot * 4, base + 0x250, width,
                   height // 2 if format_ == 4 else height)
    overlay = alpha = None
    alpha_bits = 8
    if words(base + 0x2110, 1)[0] & 1:
        overlay_format = words(base + 0x2200, 1)[0] & 31
        if (overlay_format not in (5, 6) or
                words(base + 0x2400, 1)[0] != geometry or width & 1):
            raise ValueError('Unsupported display overlay format or geometry')
        alpha_bits = 4 if overlay_format == 5 else 8
        overlay_slot = (words(base + 0x2214, 1)[0] >> 16) & 3
        overlay = plane(base + 0x2440 + overlay_slot * 4, base + 0x2500, width * 2)
        alpha = plane(base + 0x24c0, base + 0x2540,
                      width // 2 if alpha_bits == 4 else width)
    return dict(width=width, height=height, format_=format_, luminance=luminance,
                chroma=chroma, overlay=overlay, alpha=alpha, alpha_bits=alpha_bits)
