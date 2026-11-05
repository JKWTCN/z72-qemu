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
