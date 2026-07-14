from __future__ import annotations

import subprocess
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs" / "assets" / "demo-terminal.gif"

COMMAND = [
    "cargo",
    "run",
    "-q",
    "-p",
    "cerberus-cli",
    "--",
    "scan-domain",
    "paypa1-login.com",
    "paypal-secure-login.com",
    "--config",
    "examples/demo_config.yaml",
    "--grouped",
    "--summary",
]

COMMAND_LINES = [
    "$ cargo run -q -p cerberus-cli -- scan-domain paypa1-login.com paypal-secure-login.com",
    "  --config examples/demo_config.yaml --grouped --summary",
]
COMMAND_TEXT = "\n".join(COMMAND_LINES)

WIDTH = 1120
HEIGHT = 760
TERMINAL_X = 70
TERMINAL_Y = 58
TERMINAL_W = 980
TERMINAL_H = 640
HEADER_H = 46
COMMAND_X = 104
COMMAND_Y = 122
COMMAND_W = 912
COMMAND_H = 70
OUTPUT_X = 112
OUTPUT_Y = 230
LINE_H = 26

BG_TOP = (16, 24, 32)
BG_BOTTOM = (22, 36, 47)
TERMINAL_BG = (7, 16, 21)
TERMINAL_BORDER = (45, 70, 84)
HEADER_BG = (16, 33, 43)
COMMAND_BG = (11, 26, 34)
COMMAND_BORDER = (29, 52, 66)
PROMPT = (125, 211, 252)
TEXT = (229, 240, 246)
MUTED = (203, 213, 225)
DOMAIN = (248, 113, 113)
SCORE = (250, 204, 21)
SIGNAL = (167, 243, 208)
TITLE = (185, 215, 230)


def main() -> None:
    try:
        from PIL import __version__ as pillow_version  # noqa: F401
    except ImportError as exc:
        raise SystemExit("Install Pillow first: python -m pip install --user pillow") from exc

    output = run_demo_command()
    output_lines = output.strip().splitlines()

    frames: list[Image.Image] = []
    durations: list[int] = []

    frames.append(draw_frame("", []))
    durations.append(450)

    for index in range(1, len(COMMAND_TEXT) + 1):
        frames.append(draw_frame(COMMAND_TEXT[:index], []))
        durations.append(32)

    frames.append(draw_frame(COMMAND_TEXT, []))
    durations.append(260)

    for index in range(1, len(output_lines) + 1):
        frames.append(draw_frame(COMMAND_TEXT, output_lines[:index]))
        durations.append(210)

    durations[-1] = 2600

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    frames[0].save(
        OUTPUT,
        save_all=True,
        append_images=frames[1:],
        duration=durations,
        loop=0,
        optimize=True,
    )

    print(f"Wrote {OUTPUT.relative_to(ROOT)} from real command output.")


def run_demo_command() -> str:
    completed = subprocess.run(
        COMMAND,
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=True,
    )
    return completed.stdout


def draw_frame(typed_command: str, lines: list[str]) -> Image.Image:
    image = vertical_gradient(WIDTH, HEIGHT, BG_TOP, BG_BOTTOM)
    draw = ImageDraw.Draw(image)
    fonts = load_fonts()

    rounded_rectangle(draw, (TERMINAL_X, TERMINAL_Y, TERMINAL_X + TERMINAL_W, TERMINAL_Y + TERMINAL_H), 8, TERMINAL_BG, TERMINAL_BORDER)
    rounded_rectangle(draw, (TERMINAL_X, TERMINAL_Y, TERMINAL_X + TERMINAL_W, TERMINAL_Y + HEADER_H), 8, HEADER_BG, None)
    draw.ellipse((98 - 7, 81 - 7, 98 + 7, 81 + 7), fill=(255, 95, 86))
    draw.ellipse((122 - 7, 81 - 7, 122 + 7, 81 + 7), fill=(255, 189, 46))
    draw.ellipse((146 - 7, 81 - 7, 146 + 7, 81 + 7), fill=(39, 201, 63))
    draw.text((WIDTH // 2, 87), "cerberus-ct real CLI demo", fill=TITLE, font=fonts["title"], anchor="mm")

    rounded_rectangle(
        draw,
        (COMMAND_X, COMMAND_Y, COMMAND_X + COMMAND_W, COMMAND_Y + COMMAND_H),
        6,
        COMMAND_BG,
        COMMAND_BORDER,
    )

    draw_command(draw, typed_command, fonts["command"])

    y = OUTPUT_Y
    for line in lines:
        color, font_name = style_for_line(line)
        draw.text((OUTPUT_X + indent_for_line(line), y), line, fill=color, font=fonts[font_name])
        y += LINE_H

    return image


def draw_command(
    draw: ImageDraw.ImageDraw,
    typed_command: str,
    font: ImageFont.FreeTypeFont,
) -> None:
    lines = typed_command.split("\n")
    if len(lines) == 1:
        first_line = lines[0]
        second_line = ""
        cursor_line = 0
    else:
        first_line = lines[0]
        second_line = lines[1]
        cursor_line = 1

    first_pos = (COMMAND_X + 18, COMMAND_Y + 18)
    second_pos = (COMMAND_X + 38, COMMAND_Y + 44)

    draw.text(first_pos, first_line, fill=PROMPT, font=font)
    draw.text(second_pos, second_line, fill=PROMPT, font=font)

    cursor_source = second_line if cursor_line else first_line
    cursor_base_x, cursor_base_y = second_pos if cursor_line else first_pos
    cursor_x = cursor_base_x + text_width(draw, cursor_source, font) + 2
    cursor_y = cursor_base_y + 2
    draw.rectangle((cursor_x, cursor_y, cursor_x + 8, cursor_y + 17), fill=PROMPT)


def text_width(
    draw: ImageDraw.ImageDraw,
    text: str,
    font: ImageFont.FreeTypeFont,
) -> int:
    if not text:
        return 0
    left, _, right, _ = draw.textbbox((0, 0), text, font=font)
    return right - left


def style_for_line(line: str) -> tuple[tuple[int, int, int], str]:
    if line and not line.startswith(" "):
        return DOMAIN, "output_bold"
    if "detectors=" in line:
        return SIGNAL, "output"
    return MUTED, "output"


def indent_for_line(line: str) -> int:
    if line.startswith("  - "):
        return 34
    return 0


def load_fonts() -> dict[str, ImageFont.FreeTypeFont]:
    font_dir = Path("C:/Windows/Fonts")
    regular = font_dir / "consola.ttf"
    bold = font_dir / "consolab.ttf"

    return {
        "title": ImageFont.truetype(str(regular), 16),
        "command": ImageFont.truetype(str(regular), 16),
        "output": ImageFont.truetype(str(regular), 17),
        "output_bold": ImageFont.truetype(str(bold), 18),
    }


def vertical_gradient(
    width: int,
    height: int,
    top: tuple[int, int, int],
    bottom: tuple[int, int, int],
) -> Image.Image:
    image = Image.new("RGB", (width, height), top)
    pixels = image.load()

    for y in range(height):
        ratio = y / max(1, height - 1)
        color = tuple(round(top[i] * (1 - ratio) + bottom[i] * ratio) for i in range(3))
        for x in range(width):
            pixels[x, y] = color

    return image


def rounded_rectangle(
    draw: ImageDraw.ImageDraw,
    xy: tuple[int, int, int, int],
    radius: int,
    fill: tuple[int, int, int],
    outline: tuple[int, int, int] | None,
) -> None:
    draw.rounded_rectangle(xy, radius=radius, fill=fill, outline=outline)


if __name__ == "__main__":
    main()
