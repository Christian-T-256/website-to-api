#!/usr/bin/env python3
"""Check publishable output against captured secrets without printing values."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from common import ARTIFACT_ROOT, CAPTURE_ROOT, CLIENT_ROOT, find_secret_names, load_vault, validate_slug


def files_under(paths: list[Path]) -> list[Path]:
    files: list[Path] = []
    for path in paths:
        if path.is_file():
            files.append(path)
        elif path.is_dir():
            files.extend(candidate for candidate in path.rglob("*") if candidate.is_file())
    return sorted(set(files))


def verify(vault_path: Path, targets: list[Path]) -> tuple[int, int, list[tuple[Path, list[str]]]]:
    secrets = load_vault(vault_path)
    files = files_under(targets)
    leaks: list[tuple[Path, list[str]]] = []
    for path in files:
        if path.resolve() == vault_path.resolve():
            raise ValueError("the secret vault cannot be a scan target")
        text = path.read_text(encoding="utf-8", errors="ignore")
        names = find_secret_names(text, secrets)
        if names:
            leaks.append((path, names))
    return len(secrets), len(files), leaks


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--slug", required=True)
    parser.add_argument("--vault-root", type=Path, default=CAPTURE_ROOT)
    parser.add_argument("--target", action="append", type=Path, help="file or directory; can be repeated")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        slug = validate_slug(args.slug)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    vault_path = args.vault_root / slug / "captured-secrets.json"
    if not vault_path.is_file():
        raise SystemExit(f"secret vault not found: {vault_path}; run the digest first")
    targets = args.target or [ARTIFACT_ROOT / slug, CLIENT_ROOT / slug]
    names_count, files_count, leaks = verify(vault_path, targets)
    if files_count == 0:
        print("FAILED no publishable files found to check")
        return 1
    for path, names in leaks:
        print(f"LEAK {path}: {', '.join(names)}")
    status = "FAILED" if leaks else "CLEAN"
    print(f"{status} {names_count} secret names checked across {files_count} files")
    return 1 if leaks else 0


if __name__ == "__main__":
    sys.exit(main())
