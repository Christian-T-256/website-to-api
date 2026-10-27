#!/usr/bin/env python3
"""Gate a model response from a file or stdin before saving a client."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from client_gate import save_client


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--slug", required=True)
    parser.add_argument("--input", type=Path, help="model response file; omit to read stdin")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    try:
        response = args.input.read_text(encoding="utf-8") if args.input else sys.stdin.read()
        path = save_client(args.slug, response, args.output, args.force)
    except (OSError, ValueError) as exc:
        raise SystemExit(f"not saved: {exc}") from exc
    print(f"saved checked client to {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

