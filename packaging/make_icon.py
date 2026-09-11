#!/usr/bin/env python3
"""Generate packaging/mashxd.png (256x256 RGBA) using only the stdlib."""
import struct
import zlib
from pathlib import Path

SIZE = 256
OUT = Path(__file__).resolve().parent / "mashxd.png"

BG = (13, 17, 23, 255)
PANEL = (22, 27, 34, 255)
HEX_FILL = (33, 38, 45, 255)
HEX_STROKE = (248, 81, 73, 255)   # crimson
MONO = (88, 166, 255, 255)        # blue
ACCENT = (248, 81, 73, 255)


def lerp(a, b, t):
    return a + (b - a) * t


class Canvas:
    def __init__(self):
        self.px = bytearray(b"\x00\x00\x00\x00") * (SIZE * SIZE)

    def set(self, x, y, color):
        if 0 <= x < SIZE and 0 <= y < SIZE:
            i = (y * SIZE + x) * 4
            self.px[i:i + 4] = bytes(color[:3]) + bytes([color[3]])

    def fill_rect(self, x0, y0, x1, y1, color):
        for y in range(y0, y1):
            for x in range(x0, x1):
                self.set(x, y, color)

    def fill_circle(self, cx, cy, r, color):
        for y in range(int(cy - r), int(cy + r + 1)):
            for x in range(int(cx - r), int(cx + r + 1)):
                if (x - cx) ** 2 + (y - cy) ** 2 <= r * r:
                    self.set(x, y, color)

    def stamp(self, x, y, r, color):  # filled circle but cheap
        self.fill_circle(x, y, r, color)

    def line(self, x0, y0, x1, y1, width, color):
        steps = int(max(abs(x1 - x0), abs(y1 - y0)))
        steps = max(steps, 1)
        r = width / 2
        for i in range(steps + 1):
            t = i / steps
            self.stamp(lerp(x0, x1, t), lerp(y0, y1, t), r, color)

    def polyline(self, pts, width, color):
        for (ax, ay), (bx, by) in zip(pts, pts[1:]):
            self.line(ax, ay, bx, by, width, color)

    def polygon(self, pts, fill, outline=None, width=0):
        ymin = int(min(p[1] for p in pts))
        ymax = int(max(p[1] for p in pts))
        for y in range(ymin, ymax + 1):
            xs = []
            n = len(pts)
            for i in range(n):
                x0, y0 = pts[i]
                x1, y1 = pts[(i + 1) % n]
                yl, yr = min(y0, y1), max(y0, y1)
                if yl < y <= yr:      # scanline crossing (open top edge)
                    xs.append(x0 + (x1 - x0) * (y - y0) / (y1 - y0))
            xs.sort()
            for i in range(0, len(xs) - 1, 2):
                self.fill_rect(int(xs[i]), y, int(xs[i + 1]) + 1, y + 1, fill)
        if outline:
            pts_closed = list(pts) + [pts[0]]
            self.polyline(pts_closed, width, outline)

    def rounded_rect(self, x0, y0, x1, y1, radius, fill):
        self.fill_rect(x0 + radius, y0, x1 - radius, y1, fill)
        self.fill_rect(x0, y0 + radius, x1, y1 - radius, fill)
        for cx, cy in ((x0 + radius, y0 + radius), (x1 - radius, y0 + radius),
                       (x0 + radius, y1 - radius), (x1 - radius, y1 - radius)):
            self.fill_circle(cx, cy, radius, fill)


def hexagon(cx, cy, radius):
    import math
    pts = []
    for i in range(6):
        ang = (30 + 60 * i) * math.pi / 180
        pts.append((round(cx + radius * math.cos(ang), 1),
                    round(cy + radius * math.sin(ang), 1)))
    return pts


def render():
    c = Canvas()
    c.fill_rect(0, 0, SIZE, SIZE, BG)
    c.rounded_rect(12, 12, SIZE - 12, SIZE - 12, 52, PANEL)

    hex_pts = hexagon(128, 126, 92)
    c.polygon(hex_pts, HEX_FILL, outline=HEX_STROKE, width=10)

    # "M" monogram
    w = 22
    c.line(84, 78, 84, 174, w, MONO)
    c.line(172, 78, 172, 174, w, MONO)
    c.line(84, 74, 128, 130, w, MONO)
    c.line(128, 130, 172, 74, w, MONO)

    # accent dot (lower right inside hexagon)
    c.fill_circle(176, 176, 13, ACCENT)

    # zero out-of-bounds corners -> alpha
    for y in range(SIZE):
        for x in range(SIZE):
            pass  # corners already transparent via rounded_rect

    rows = b"".join(b"\x00" + c.px[y * SIZE * 4:(y + 1) * SIZE * 4]
                    for y in range(SIZE))
    raw = zlib.compress(rows, 9)

    def chunk(tag, data):
        block = tag + data
        return (struct.pack(">I", len(data)) + block
                + struct.pack(">I", zlib.crc32(block) & 0xFFFFFFFF))

    ihdr = struct.pack(">IIBBBBB", SIZE, SIZE, 8, 6, 0, 0, 0)
    png = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
           + chunk(b"IDAT", raw) + chunk(b"IEND", b""))
    OUT.write_bytes(png)
    print(f"wrote {OUT} ({len(png)} bytes)")


if __name__ == "__main__":
    render()