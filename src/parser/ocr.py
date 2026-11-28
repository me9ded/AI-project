"""Screenshot OCR for Task 1 (docs/task1-brief.md, rule 6; proposal section 2.2.3).

image_to_text(image) -> (text, mean_confidence)
    image: a file path, raw bytes (e.g. a FastAPI upload) or a PIL image.

Steps: greyscale -> upscale x2 if narrower than 1,000 px -> invert dark mode -> EasyOCR
(CRAFT detector + CRNN recogniser) -> drop boxes with confidence < 0.4 -> rebuild lines ->
fix O/0 and l/1 only inside version- and ID-shaped tokens.

EasyOCR (and PyTorch) are imported only when a screenshot is read, so `import src.parser`
stays fast. The first run downloads the models (about 100 MB) into ~/.EasyOCR; call
`get_reader()` once at app start-up (Task 4) so the first request is not slow.
"""

import io
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

MIN_BOX_CONFIDENCE = 0.4     # boxes below this are dropped
LOW_CONFIDENCE = 0.5         # below this mean, extract() adds a warning for the UI
# Small fonts are the main cause of OCR errors. The proposal said 1,500 px; measured on the demo
# screenshot (1,396 px) upscaling doubled the time (13 s vs 7 s on CPU) with no accuracy gain, while
# a 698 px copy failed completely without it. So only images narrower than 1,000 px are upscaled.
UPSCALE_BELOW_WIDTH = 1000
DARK_MODE_BRIGHTNESS = 100   # mean grey level (0-255) below which the image is inverted


class OcrUnavailable(RuntimeError):
    """EasyOCR is not installed or its models cannot be loaded."""


# ---------------------------------------------------------------------------
# 1. Pre-processing (Pillow)
# ---------------------------------------------------------------------------

def load_image(image: Any):
    """Open a path, bytes or PIL image as a PIL image. Raises ValueError if it is not an image."""
    from PIL import Image, UnidentifiedImageError

    if isinstance(image, Image.Image):
        return image
    try:
        if isinstance(image, (bytes, bytearray)):
            opened = Image.open(io.BytesIO(image))
        elif isinstance(image, (str, Path)):
            opened = Image.open(image)
        else:
            raise ValueError(f"Unsupported image input: {type(image).__name__}")
        opened.load()
        return opened
    except (UnidentifiedImageError, OSError) as error:
        raise ValueError("The upload is not a readable PNG or JPG image.") from error


def preprocess(image):
    """Greyscale, upscale small images x2, invert dark-mode screenshots."""
    from PIL import Image, ImageOps, ImageStat

    grey = image.convert("L")
    if grey.width < UPSCALE_BELOW_WIDTH:
        grey = grey.resize((grey.width * 2, grey.height * 2), Image.Resampling.LANCZOS)
    if ImageStat.Stat(grey).mean[0] < DARK_MODE_BRIGHTNESS:
        grey = ImageOps.invert(grey)
    return grey


# ---------------------------------------------------------------------------
# 2. EasyOCR (lazy, created once)
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def get_reader():
    """The EasyOCR reader is slow to create, so it is built once and reused."""
    try:
        import easyocr
        import torch
    except ImportError as error:
        raise OcrUnavailable("EasyOCR is not installed. Run: pip install -r requirements.txt") from error
    try:
        return easyocr.Reader(["en"], gpu=torch.cuda.is_available(), verbose=False)
    except Exception as error:  # e.g. the first-run model download failed (no internet)
        raise OcrUnavailable(f"EasyOCR could not load its models: {error}") from error


# ---------------------------------------------------------------------------
# 3. Rebuilding lines from text boxes
# ---------------------------------------------------------------------------

def rebuild_lines(boxes: list[tuple[list, str, float]]) -> str:
    """Group EasyOCR boxes into lines by vertical centre, then sort each line left to right."""
    items = []
    for corners, text, _ in boxes:
        ys = [point[1] for point in corners]
        xs = [point[0] for point in corners]
        items.append(((min(ys) + max(ys)) / 2, max(ys) - min(ys), min(xs), text))
    items.sort(key=lambda item: item[0])

    lines: list[list[tuple]] = []
    for item in items:
        centre, height = item[0], item[1]
        if lines:
            last = lines[-1]
            last_centre = sum(i[0] for i in last) / len(last)
            if abs(centre - last_centre) < max(height, last[0][1]) / 2:
                last.append(item)
                continue
        lines.append([item])
    return "\n".join(" ".join(i[3] for i in sorted(line, key=lambda i: i[2])) for line in lines)


# ---------------------------------------------------------------------------
# 4. Character correction (only inside version- and ID-shaped tokens)
# ---------------------------------------------------------------------------

_DIGIT_LOOKALIKES = str.maketrans({"O": "0", "o": "0", "l": "1", "I": "1", "|": "1"})
_LOOKALIKE = "[0-9OolI|]"
# A version may follow '-' (as in "log4j-core-2.l4.1.jar"), but must not be glued to a word.
_VERSION_TOKEN = re.compile(rf"(?<![\w.])(?=[^\s]*\d){_LOOKALIKE}+(?:\.{_LOOKALIKE}+)+(?![\w-])")
_ID_TOKEN = re.compile(rf"\b(CVE|PYSEC)-({_LOOKALIKE}{{4}})-({_LOOKALIKE}+)\b", re.IGNORECASE)


def fix_lookalikes(text: str) -> str:
    """'2.l4.1' -> '2.14.1', 'CVE-2O21-44228' -> 'CVE-2021-44228'. Ordinary words are untouched,
    and GHSA IDs are left alone because their letters are real."""
    text = _ID_TOKEN.sub(
        lambda m: f"{m.group(1)}-{m.group(2).translate(_DIGIT_LOOKALIKES)}-{m.group(3).translate(_DIGIT_LOOKALIKES)}",
        text,
    )
    return _VERSION_TOKEN.sub(lambda m: m.group(0).translate(_DIGIT_LOOKALIKES), text)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def image_to_text(image: Any) -> tuple[str, float]:
    """Return (text, mean confidence 0-1). Raises ValueError for a non-image, OcrUnavailable without EasyOCR."""
    import numpy as np

    prepared = preprocess(load_image(image))
    boxes = get_reader().readtext(np.array(prepared), detail=1)
    kept = [box for box in boxes if box[2] >= MIN_BOX_CONFIDENCE]
    if not kept:
        return "", 0.0
    mean_confidence = sum(float(box[2]) for box in kept) / len(kept)
    return fix_lookalikes(rebuild_lines(kept)), round(mean_confidence, 3)
