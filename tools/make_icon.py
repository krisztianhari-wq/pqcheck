"""Generate the PQCheck app icon (PNG, pure stdlib) in Yettel navy/lime, retro-terminal style.
Usage: python3 tools/make_icon.py assets/icon_1024.png [size]"""
import struct
import sys
import zlib

NAVY = (0, 35, 64)
NAVY2 = (0, 26, 48)
LIME = (180, 255, 0)
ICE = (196, 223, 233)

# 5x7 pixel font for the glyphs we need
FONT = {
    "P": ["11110", "10001", "10001", "11110", "10000", "10000", "10000"],
    "Q": ["01110", "10001", "10001", "10001", "10101", "10010", "01101"],
}


def make(size=1024):
    px = bytearray(size * size * 4)

    def put(x, y, c, a=255):
        if 0 <= x < size and 0 <= y < size:
            i = (y * size + x) * 4
            px[i:i + 4] = bytes((c[0], c[1], c[2], a))

    m = int(size * 0.10)               # macOS icon margin
    r = int(size * 0.185)              # corner radius
    x0, y0, x1, y1 = m, m, size - m, size - m

    def inside(x, y):
        if x < x0 or x >= x1 or y < y0 or y >= y1:
            return False
        cx = x0 + r if x < x0 + r else (x1 - 1 - r if x >= x1 - r else x)
        cy = y0 + r if y < y0 + r else (y1 - 1 - r if y >= y1 - r else y)
        return (x - cx) ** 2 + (y - cy) ** 2 <= r * r

    # background with scanlines + vignette
    for y in range(size):
        for x in range(size):
            if inside(x, y):
                base = NAVY if (y // max(1, size // 256)) % 3 else NAVY2
                dx, dy = (x - size / 2) / size, (y - size / 2) / size
                v = 1.0 - 0.9 * (dx * dx + dy * dy)
                put(x, y, tuple(int(c * v) for c in base))

    # lime bezel (double frame)
    t = max(2, size // 128)
    inset = int(size * 0.06)
    for k in (0, 3 * t):
        bx0, by0, bx1, by1 = x0 + inset + k, y0 + inset + k, x1 - inset - k, y1 - inset - k
        for x in range(bx0, bx1):
            for yy in range(t):
                put(x, by0 + yy, LIME); put(x, by1 - 1 - yy, LIME)
        for y in range(by0, by1):
            for xx in range(t):
                put(bx0 + xx, y, LIME); put(bx1 - 1 - xx, y, LIME)

    # "PQ" glyphs + cursor block, with a soft glow
    cell = int(size * 0.052)
    gap = cell
    total_w = 2 * 5 * cell + gap + 3 * cell + gap   # P, Q, cursor
    gx = (size - total_w) // 2
    gy = int(size * 0.36)

    def block(bx, by, w, h, c):
        for y in range(by, by + h):
            for x in range(bx, bx + w):
                put(x, y, c)

    def glow(bx, by, w, h):
        g = cell // 2
        for y in range(by - g, by + h + g):
            for x in range(bx - g, bx + w + g):
                if inside(x, y) and not (bx <= x < bx + w and by <= y < by + h):
                    i = (y * size + x) * 4
                    if px[i + 3]:
                        px[i] = min(255, px[i] + 18); px[i + 1] = min(255, px[i + 1] + 30)

    for ch in "PQ":
        rows = FONT[ch]
        for ry, row in enumerate(rows):
            for rx, bit in enumerate(row):
                if bit == "1":
                    glow(gx + rx * cell, gy + ry * cell, cell, cell)
        for ry, row in enumerate(rows):
            for rx, bit in enumerate(row):
                if bit == "1":
                    block(gx + rx * cell, gy + ry * cell, cell, cell, LIME)
        gx += 5 * cell + gap
    block(gx, gy + 2 * cell, 3 * cell, 5 * cell, ICE)   # cursor

    # underline "bar" like the Yettel lime footer
    bar_y = int(size * 0.74)
    block(x0 + inset + 6 * t, bar_y, (x1 - x0) - 2 * inset - 12 * t, max(3, size // 90), LIME)

    raw = b"".join(b"\x00" + bytes(px[y * size * 4:(y + 1) * size * 4]) for y in range(size))

    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "icon.png"
    size = int(sys.argv[2]) if len(sys.argv) > 2 else 1024
    with open(out, "wb") as fh:
        fh.write(make(size))
    print("wrote", out, size)
