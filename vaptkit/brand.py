"""The shield + MVK block-art lockup from the terminal header, drawn as inline SVG."""
from pyfiglet import Figlet

from .scan import ACCENT, SHIELD

CELL_W, CELL_H = 10, 20
STROKE = 1.3
GAP = 2.2


def lockup_lines() -> list[str]:
    wordmark = [line.rstrip() for line in Figlet(font="ansi_shadow", width=60).renderText("MVK").splitlines()
                if line.strip()]
    pad = len(wordmark) - len(SHIELD)
    blank = " " * len(SHIELD[0])
    shield = [blank] * (pad // 2) + list(SHIELD) + [blank] * (pad - pad // 2)
    return [left + "  " + right for left, right in zip(shield, wordmark)]


def cell(char: str, x: float, y: float) -> list[str]:
    cx, cy, right, bottom = x + CELL_W / 2, y + CELL_H / 2, x + CELL_W, y + CELL_H

    def rect(left, top, width, height):
        return f'<rect stroke="none" x="{left:.1f}" y="{top:.1f}" width="{width:.1f}" height="{height:.1f}"/>'

    def line(*points):
        return '<polyline fill="none" points="' + " ".join(f"{a:.1f},{b:.1f}" for a, b in points) + '"/>'

    o = GAP
    shapes = {
        "█": [rect(x, y, CELL_W + 0.5, CELL_H + 0.5)],
        "▀": [rect(x, y, CELL_W + 0.5, CELL_H / 2 + 0.5)],
        "▄": [rect(x, cy, CELL_W + 0.5, CELL_H / 2 + 0.5)],
        "◆": [f'<path stroke="none" d="M{cx} {cy - 5}L{cx + 5} {cy}L{cx} {cy + 5}L{cx - 5} {cy}Z"/>'],
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
    lines = lockup_lines()
    width = max(len(line) for line in lines) * CELL_W
    height = len(lines) * CELL_H
    shapes = "".join(shape for row, text in enumerate(lines) for col, char in enumerate(text)
                     for shape in cell(char, col * CELL_W, row * CELL_H))
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="-4 -4 {width + 8} {height + 8}" role="img" '
            f'aria-label="{label}"><g fill="{color}" stroke="{color}" stroke-width="{STROKE}" '
            f'stroke-linecap="square">{shapes}</g></svg>')
