#!/usr/bin/env python3
"""Build the model prompt from a redacted digest, without reading the HAR or vault."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from common import ARTIFACT_ROOT, CLIENT_ROOT, REPO_ROOT, validate_slug

TEMPLATE = REPO_ROOT / "prompts" / "write-api-client.md"


def build_prompt(slug: str, digest_path: Path | None = None, output_path: Path | None = None) -> str:
    validate_slug(slug)
    digest_path = digest_path or ARTIFACT_ROOT / slug / "api-calls-digest.md"
    output_path = output_path or CLIENT_ROOT / slug / "api_client.py"
    digest = digest_path.read_text(encoding="utf-8")
    template = TEMPLATE.read_text(encoding="utf-8")
    instructions = (
        template.replace("{{SLUG}}", slug)
        .replace("{{DIGEST_PATH}}", str(digest_path))
        .replace("{{OUTPUT_PATH}}", str(output_path))
    )
    return f"{instructions}\n\n## Redacted digest\n\n{digest}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--slug", required=True)
    parser.add_argument("--digest", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        print(build_prompt(args.slug, args.digest, args.output))
    except (ValueError, OSError) as exc:
        raise SystemExit(str(exc)) from exc
    return 0


if __name__ == "__main__":
    sys.exit(main())

