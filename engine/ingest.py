"""Convert uploaded analysis artefacts into plain text for the generator.

Supported: .txt/.log/.md/.csv/.yar, .json (any.run IOC export or any JSON),
.pdf (text layer; OCR if pytesseract + Tesseract are installed).
Uploaded files are only *read as text* - nothing is executed.
"""

import io
import json


def _flatten_json(obj, prefix=""):
    lines = []
    if isinstance(obj, dict):
        # any.run IOC export: {"Category": [{"type":..,"ioc":..,"name":..}]}
        if "ioc" in obj and isinstance(obj["ioc"], str):
            lines.append(f"{obj.get('category', prefix)} {obj.get('type', '')}: {obj['ioc']}")
            return lines
        for k, v in obj.items():
            lines += _flatten_json(v, k)
    elif isinstance(obj, list):
        for v in obj:
            lines += _flatten_json(v, prefix)
    elif obj is not None:
        lines.append(f"{prefix}: {obj}" if prefix else str(obj))
    return lines


def _pdf_text(data):
    import fitz  # pymupdf

    doc = fitz.open(stream=data, filetype="pdf")
    text = "\n".join(p.get_text() for p in doc)
    if text.strip():
        return text, None
    try:
        import pytesseract
        from PIL import Image
    except ImportError:
        return "", ("PDF has no text layer (scanned/image PDF). Install Tesseract + pytesseract for OCR, "
                    "or paste the text into the form.")
    out = []
    try:
        for p in doc:
            pix = p.get_pixmap(dpi=200)
            out.append(pytesseract.image_to_string(Image.open(io.BytesIO(pix.tobytes("png")))))
    except Exception as exc:  # tesseract binary missing etc.
        return "", f"OCR failed: {exc}"
    return "\n".join(out), "Text recovered by OCR - review extracted values."


def file_to_text(filename, data):
    """Returns (text, warning_or_None)."""
    name = (filename or "").lower()
    if name.endswith(".pdf"):
        return _pdf_text(data)
    raw = data.decode("utf-8", errors="replace")
    if name.endswith(".json"):
        try:
            return "\n".join(_flatten_json(json.loads(raw))), None
        except json.JSONDecodeError:
            return raw, "JSON could not be parsed - treated as plain text."
    return raw, None
