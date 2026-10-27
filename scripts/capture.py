#!/usr/bin/env python3
"""Capture browser network traffic to a local, gitignored HAR file."""
from __future__ import annotations

import argparse
import json
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from common import CAPTURE_ROOT, validate_slug

USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)


def valid_http_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise argparse.ArgumentTypeError("URL must be an absolute http or https URL")
    return value


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True, type=valid_http_url)
    parser.add_argument("--goal", required=True, help="the records or action the client should expose")
    parser.add_argument("--slug", required=True)
    parser.add_argument("--mode", choices=("auto", "watch"), default="watch")
    parser.add_argument("--seconds", type=int, default=12)
    parser.add_argument("--profile", help="a named isolated Playwright profile, never a personal browser profile")
    parser.add_argument("--acknowledge-account-risk", action="store_true")
    parser.add_argument("--force", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        slug = validate_slug(args.slug)
        profile = validate_slug(args.profile) if args.profile else None
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    if profile and not args.acknowledge_account_risk:
        raise SystemExit("a persistent profile requires --acknowledge-account-risk; use only an authorized test account")
    if args.seconds < 1 or args.seconds > 300:
        raise SystemExit("--seconds must be between 1 and 300")

    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise SystemExit("Playwright is not installed. Run: pip install -r requirements.txt") from exc

    capture_dir = CAPTURE_ROOT / slug
    har_path = capture_dir / "recording.har"
    if har_path.exists() and not args.force:
        print(f"capture already exists at {har_path.relative_to(Path.cwd())}; use --force to replace it")
        return 0
    capture_dir.mkdir(parents=True, exist_ok=True)

    context_options = {
        "record_har_path": str(har_path),
        "record_har_content": "embed",
        "user_agent": USER_AGENT,
        "locale": "en-US",
        "viewport": {"width": 1440, "height": 900},
    }
    stopped = {"value": False}
    signal.signal(signal.SIGINT, lambda *_: stopped.__setitem__("value", True))
    started = datetime.now(timezone.utc).isoformat()

    playwright = sync_playwright().start()
    browser = None
    if profile:
        profile_dir = CAPTURE_ROOT / "profiles" / profile
        context = playwright.chromium.launch_persistent_context(
            str(profile_dir), headless=args.mode == "auto", **context_options
        )
    else:
        browser = playwright.chromium.launch(headless=args.mode == "auto")
        context = browser.new_context(**context_options)

    page = context.pages[0] if context.pages else context.new_page()
    print(f"capturing {slug} in {args.mode} mode")
    try:
        page.goto(args.url, wait_until="domcontentloaded", timeout=45_000)
    except Exception as exc:
        print(f"warning: page load did not finish: {exc}")

    if args.mode == "auto":
        deadline = time.monotonic() + args.seconds
        while time.monotonic() < deadline and not stopped["value"]:
            try:
                page.mouse.wheel(0, 1400)
                page.wait_for_timeout(1000)
            except Exception:
                break
    else:
        print("use the first browser tab, then close the window or press Ctrl+C")
        try:
            while context.pages and not stopped["value"]:
                context.pages[0].wait_for_timeout(250)
        except Exception:
            pass

    try:
        context.close()
    finally:
        if browser:
            browser.close()
        playwright.stop()

    if not har_path.exists():
        print("capture failed: no HAR was written")
        return 1
    requests_count = len(json.loads(har_path.read_text(encoding="utf-8")).get("log", {}).get("entries", []))
    metadata = {
        "slug": slug,
        "url": args.url,
        "goal": args.goal,
        "mode": args.mode,
        "profile": profile,
        "started_at": started,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "requests": requests_count,
    }
    (capture_dir / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    print(f"captured {requests_count} requests to {har_path.relative_to(Path.cwd())}")
    print(f"next: python scripts/digest.py --slug {slug}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

