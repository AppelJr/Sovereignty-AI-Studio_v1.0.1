#!/usr/bin/env python3
"""Surgical fix for DevAssist420_Test.html setConnected comment terminators.
Run from repo root:
  python3 scripts/xai-grok/fix_setConnected_comments.py DevAssist420_Test.html
"""
from __future__ import annotations
import re
import sys
from pathlib import Path

def fix(text: str) -> tuple[str, int]:
    a, b = (
        r'/\* Local mode: neutral blue bar, never red "Bridge offline" /',
        '/* Local mode: neutral blue bar, never red "Bridge offline" */',
    )
    c, d = (
        r'(?<![*])/ Update all status elements in the DOM \*/',
        '/* Update all status elements in the DOM */',
    )
    text2, n1 = re.subn(a, b, text, count=1)
    text3, n2 = re.subn(c, d, text2, count=1)
    return text3, n1 + n2

def main() -> int:
    if len(sys.argv) < 2:
        print('usage: fix_setConnected_comments.py <html-path>', file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    raw = path.read_text(encoding='utf-8', errors='replace')
    fixed, n = fix(raw)
    if n == 0:
        print('no broken comment patterns found (already fixed?)')
        return 0
    path.write_text(fixed, encoding='utf-8')
    print(f'applied {n} surgical comment fix(es) -> {path}')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
