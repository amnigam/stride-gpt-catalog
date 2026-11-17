"""Tiny SVG diagram helper for the sample architecture diagrams.

A diagram is zones (trust boundaries), nodes (boxes) and edges (arrows with
labels). `to_svg` returns SVG text; render_png.js turns it into a PNG.
"""
from __future__ import annotations

from html import escape

PALETTE = {
    "user": ("#FFF4E5", "#C26A00"),
    "edge": ("#FDECEC", "#B42318"),
    "compute": ("#E8F1FD", "#1F5FBF"),
    "data": ("#E9F7EF", "#1E7B43"),
    "security": ("#F3EDFC", "#6B3FB5"),
    "ai": ("#FFF0F7", "#B0246E"),
    "ext": ("#F2F2F2", "#555555"),
    "msg": ("#E7F7F8", "#0E7C86"),
    "ops": ("#FBF8E6", "#8A6D00"),
}


class Diagram:
    def __init__(self, width: int, height: int, title: str, subtitle: str = ""):
        self.w, self.h, self.title, self.subtitle = width, height, title, subtitle
        self.zones: list[tuple] = []
        self.nodes: dict[str, tuple] = {}
        self.edges: list[tuple] = []
        self.notes: list[tuple] = []

    def zone(self, x, y, w, h, label, dashed=True, fill="none", color="#7A7A7A"):
        self.zones.append((x, y, w, h, label, dashed, fill, color))

    def node(self, key, x, y, w, h, label, sub="", kind="compute"):
        self.nodes[key] = (x, y, w, h, label, sub, kind)

    def edge(self, a, b, label="", via=None, dashed=False, both=False, lpos=0.5, loff=(0, -6),
             sa=None, sb=None):
        """sa/sb: optional side anchors ('l','r','t','b') overriding auto choice."""
        self.edges.append((a, b, label, via or [], dashed, both, lpos, loff, sa, sb))

    def note(self, x, y, text, size=13, color="#444", weight="400", anchor="start"):
        self.notes.append((x, y, text, size, color, weight, anchor))

    # ------------------------------------------------------------------ #
    def _anchor(self, key, toward, side=None):
        x, y, w, h = self.nodes[key][:4]
        cx, cy = x + w / 2, y + h / 2
        if isinstance(side, tuple):          # (side, absolute coordinate along that side)
            side, at = side
            if side in ("l", "r"):
                cy = at
            else:
                cx = at
        if side == "l":
            return x, cy
        if side == "r":
            return x + w, cy
        if side == "t":
            return cx, y
        if side == "b":
            return cx, y + h
        tx, ty = toward
        dx, dy = tx - cx, ty - cy
        if dx == 0 and dy == 0:
            return cx, cy
        sx = (w / 2) / abs(dx) if dx else float("inf")
        sy = (h / 2) / abs(dy) if dy else float("inf")
        s = min(sx, sy)
        return cx + dx * s, cy + dy * s

    def _center(self, key):
        x, y, w, h = self.nodes[key][:4]
        return x + w / 2, y + h / 2

    def to_svg(self) -> str:
        o = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{self.w}" height="{self.h}" '
             f'viewBox="0 0 {self.w} {self.h}" font-family="Inter, DejaVu Sans, sans-serif">',
             '<defs><marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" '
             'markerHeight="8" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" '
             'fill="#333"/></marker></defs>',
             f'<rect width="{self.w}" height="{self.h}" fill="#FFFFFF"/>',
             f'<text x="24" y="38" font-size="24" font-weight="700" fill="#111">'
             f'{escape(self.title)}</text>']
        if self.subtitle:
            o.append(f'<text x="24" y="62" font-size="14" fill="#555">{escape(self.subtitle)}</text>')
        for x, y, w, h, label, dashed, fill, color in self.zones:
            da = ' stroke-dasharray="8 5"' if dashed else ""
            o.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="10" fill="{fill}" '
                     f'stroke="{color}" stroke-width="1.6"{da}/>')
            o.append(f'<text x="{x + 10}" y="{y + 18}" font-size="13" font-weight="600" '
                     f'fill="{color}">{escape(label)}</text>')
        labels = []
        for a, b, label, via, dashed, both, lpos, loff, sa, sb in self.edges:
            first = via[0] if via else self._center(b)
            last = via[-1] if via else self._center(a)
            p0 = self._anchor(a, first, sa)
            p1 = self._anchor(b, last, sb)
            pts = [p0, *via, p1]
            d = " ".join(f"{'M' if i == 0 else 'L'}{px:.1f},{py:.1f}" for i, (px, py) in enumerate(pts))
            da = ' stroke-dasharray="6 4"' if dashed else ""
            ms = ' marker-start="url(#arr)"' if both else ""
            o.append(f'<path d="{d}" fill="none" stroke="#333" stroke-width="1.5"{da}{ms} '
                     f'marker-end="url(#arr)"/>')
            if label:
                labels.append((pts, label, lpos, loff))
        for key, (x, y, w, h, label, sub, kind) in self.nodes.items():
            fill, stroke = PALETTE[kind]
            o.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="8" fill="{fill}" '
                     f'stroke="{stroke}" stroke-width="2"/>')
            lines = [label] + [t for t in sub.split("\n") if t]
            n = len(lines)
            top = y + h / 2 - (n - 1) * 8.5 + 5
            for i, t in enumerate(lines):
                fs, fw, col = (14, "700", "#111") if i == 0 else (12, "400", "#333")
                o.append(f'<text x="{x + w / 2}" y="{top + i * 17}" font-size="{fs}" '
                         f'font-weight="{fw}" fill="{col}" text-anchor="middle">{escape(t)}</text>')
        for pts, label, lpos, loff in labels:
            segs = list(zip(pts, pts[1:]))
            (ax, ay), (bx, by) = max(segs, key=lambda s: abs(s[1][0] - s[0][0]) + abs(s[1][1] - s[0][1]))
            lx, ly = ax + (bx - ax) * lpos + loff[0], ay + (by - ay) * lpos + loff[1]
            lines = label.split("\n")
            wmax = max(len(t) for t in lines) * 6.6 + 10
            hh = 15 * len(lines) + 4
            o.append(f'<rect x="{lx - wmax / 2:.1f}" y="{ly - 13:.1f}" width="{wmax:.1f}" '
                     f'height="{hh}" rx="4" fill="#FFFFFF" fill-opacity="0.95" stroke="#DDD"/>')
            for i, t in enumerate(lines):
                o.append(f'<text x="{lx:.1f}" y="{ly + i * 15:.1f}" font-size="12" fill="#222" '
                         f'text-anchor="middle">{escape(t)}</text>')
        for x, y, text, size, color, weight, anchor in self.notes:
            o.append(f'<text x="{x}" y="{y}" font-size="{size}" fill="{color}" font-weight="{weight}" '
                     f'text-anchor="{anchor}">{escape(text)}</text>')
        o.append("</svg>")
        return "\n".join(o)
