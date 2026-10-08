"""The MVK block-art wordmark from the terminal header, drawn as inline SVG."""
from .scan import ACCENT, wordmark_lines

CELL_W, CELL_H = 10, 20
STROKE = 1.3
GAP = 2.2


def cell(char: str, x: float, y: float) -> list[str]:
    cx, cy, right, bottom = x + CELL_W / 2, y + CELL_H / 2, x + CELL_W, y + CELL_H

    def rect(left, top, width, height):
        return f'<rect stroke="none" x="{left:.1f}" y="{top:.1f}" width="{width:.1f}" height="{height:.1f}"/>'

    def line(*points):
        return '<polyline fill="none" points="' + " ".join(f"{a:.1f},{b:.1f}" for a, b in points) + '"/>'

    o = GAP
    shapes = {
        "█": [rect(x, y, CELL_W + 0.5, CELL_H + 0.5)],
        "═": [line((x, cy - o), (right, cy - o)), line((x, cy + o), (right, cy + o))],
        "║": [line((cx - o, y), (cx - o, bottom)), line((cx + o, y), (cx + o, bottom))],
        "╔": [line((right, cy - o), (cx - o, cy - o), (cx - o, bottom)),
              line((right, cy + o), (cx + o, cy + o), (cx + o, bottom))],
        "╗": [line((x, cy - o), (cx + o, cy - o), (cx + o, bottom)),
              line((x, cy + o), (cx - o, cy + o), (cx - o, bottom))],
        "╚": [line((cx - o, y), (cx - o, cy + o), (right, cy + o)),
              line((cx + o, y), (cx + o, cy - o), (right, cy - o))],
        "╝": [line((cx + o, y), (cx + o, cy + o), (x, cy + o)),
              line((cx - o, y), (cx - o, cy - o), (x, cy - o))],
        " ": [],
    }
    return shapes[char]


def lockup_svg(color: str = ACCENT, *, label: str = "Matt VAPT Kit") -> str:
    lines = wordmark_lines()
    width = max(len(line) for line in lines) * CELL_W
    height = len(lines) * CELL_H
    shapes = "".join(shape for row, text in enumerate(lines) for col, char in enumerate(text)
                     for shape in cell(char, col * CELL_W, row * CELL_H))
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="-4 -4 {width + 8} {height + 8}" role="img" '
            f'aria-label="{label}"><g fill="{color}" stroke="{color}" stroke-width="{STROKE}" '
            f'stroke-linecap="square">{shapes}</g></svg>')
