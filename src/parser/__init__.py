"""Task 1 - Input Parsing & Extraction (spec: docs/task1-brief.md).

Planned entry point (Prompt 5): extract(text=None, image=None) -> dict
Available now:
    src.parser.patterns.find_ids / find_packages / name_appears_in
    src.parser.schema.Extraction, Package

Keep heavy libraries (EasyOCR, Ollama) imported inside functions, so that
`import src.parser` stays fast for the other tasks and their tests.
"""
