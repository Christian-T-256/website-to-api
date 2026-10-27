#!/usr/bin/env python3
"""Send only the redacted prompt to any model CLI and gate its Python output."""
from __future__ import annotations

import argparse
import shlex
import subprocess
import sys
from pathlib import Path

from build_prompt import build_prompt
from client_gate import save_client


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--slug", required=True)
    parser.add_argument(
        "--model-command",
        required=True,
        help="command that reads a prompt on stdin and returns Python on stdout; it runs without a shell",
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--max-output-bytes", type=int, default=200_000)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    if args.timeout < 1 or args.timeout > 1800:
        raise SystemExit("--timeout must be between 1 and 1800 seconds")

    try:
        prompt = build_prompt(args.slug, output_path=args.output)
        command = shlex.split(args.model_command)
        if not command:
            raise ValueError("--model-command cannot be empty")
        result = subprocess.run(
            command,
            input=prompt,
            text=True,
            capture_output=True,
            timeout=args.timeout,
            check=False,
        )
        if result.returncode:
            detail = result.stderr.strip()[:500]
            raise ValueError(f"model command exited {result.returncode}: {detail}")
        if len(result.stdout.encode("utf-8")) > args.max_output_bytes:
            raise ValueError("model output exceeded --max-output-bytes")
        path = save_client(args.slug, result.stdout, args.output, args.force)
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        raise SystemExit(f"not saved: {exc}") from exc
    print(f"saved checked client to {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

