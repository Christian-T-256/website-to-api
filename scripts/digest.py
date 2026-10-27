#!/usr/bin/env python3
"""Reduce a HAR to useful API calls while removing captured secrets."""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import OrderedDict
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from common import (
    ARTIFACT_ROOT,
    CAPTURE_ROOT,
    SENSITIVE_HEADER,
    SENSITIVE_NAME,
    safe_name,
    secret_variants,
    validate_slug,
)

SKIP_TYPES = {"image", "font", "stylesheet", "script", "media", "manifest", "texttrack", "other-static"}
SKIP_EXTENSIONS = re.compile(
    r"\.(?:png|jpe?g|gif|webp|svg|ico|woff2?|ttf|otf|css|js|mjs|map|mp4|webm|mp3)(?:$|\?)",
    re.IGNORECASE,
)
NOISE = re.compile(
    r"(?:google-analytics|googletagmanager|doubleclick|facebook\.net|hotjar|segment\.(?:io|com)|"
    r"mixpanel|amplitude|sentry|datadoghq|newrelic|clarity\.ms|intercom|fullstory|"
    r"/healthz?\b|/ping\b|/beacon\b|/collect\b|/metrics\b|/telemetry\b)",
    re.IGNORECASE,
)
KEEP_HEADER = re.compile(
    r"^(?:accept|content-type|origin|referer|x-requested-with|x-[a-z0-9-]*version|"
    r"x-[a-z0-9-]*app[a-z0-9-]*|x-[a-z0-9-]*-id|apollographql-client-name)$",
    re.IGNORECASE,
)
ID_SEGMENT = re.compile(r"^(?:\d{3,}|[0-9a-f]{8}-[0-9a-f-]{27,}|[0-9a-f]{20,}|[A-Za-z0-9_-]{22,})$")
BODY_LIMIT = 1600


def clip(value: str | None, limit: int = BODY_LIMIT) -> str:
    if not value:
        return ""
    value = value.strip()
    return value if len(value) <= limit else f"{value[:limit]}... [{len(value) - limit} more chars]"


def path_template(path: str) -> str:
    return "/".join("{id}" if ID_SEGMENT.fullmatch(segment) else segment for segment in path.split("/"))


def is_sensitive_name(name: str) -> bool:
    normalized = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
    return bool(SENSITIVE_NAME.search(normalized))


@dataclass
class SecretStore:
    values: dict[str, str] = field(default_factory=dict)

    def add(self, suggested_name: str, value: Any) -> str | None:
        if value is None or isinstance(value, (dict, list)):
            return None
        text = str(value)
        if not text:
            return None
        name = suggested_name
        counter = 2
        while name in self.values and self.values[name] != text:
            name = f"{suggested_name}_{counter}"
            counter += 1
        self.values[name] = text
        return name

    def add_header(self, side: str, name: str, value: str) -> None:
        vault_name = self.add(safe_name(f"{side}_HEADER", name), value)
        if name.lower() in {"authorization", "proxy-authorization"}:
            parts = value.split(None, 1)
            if len(parts) == 2:
                self.add(f"{vault_name}_CREDENTIAL", parts[1])
        if name.lower() in {"cookie", "set-cookie"}:
            self.add_cookie_text(side, value)

    def add_cookie_text(self, side: str, value: str) -> None:
        jar = SimpleCookie()
        try:
            jar.load(value)
        except Exception:
            return
        for name, morsel in jar.items():
            self.add(safe_name(f"{side}_COOKIE", name), morsel.value)

    def add_url(self, url: str) -> None:
        for name, value in parse_qsl(urlsplit(url).query, keep_blank_values=True):
            if is_sensitive_name(name):
                self.add(safe_name("QUERY", name), value)

    def add_object(self, side: str, value: Any) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if is_sensitive_name(str(key)) and not isinstance(child, (dict, list)):
                    self.add(safe_name(f"{side}_BODY", str(key)), child)
                else:
                    self.add_object(side, child)
        elif isinstance(value, list):
            for child in value:
                self.add_object(side, child)

    def add_body(self, side: str, text: str | None) -> None:
        if not text:
            return
        try:
            self.add_object(side, json.loads(text))
            return
        except (json.JSONDecodeError, TypeError):
            pass
        for name, value in parse_qsl(text, keep_blank_values=True):
            if is_sensitive_name(name):
                self.add(safe_name(f"{side}_BODY", name), value)

    def scrub(self, text: str) -> str:
        replacements: list[tuple[str, str]] = []
        for name, value in self.values.items():
            replacements.extend((variant, f"<REDACTED:{name}>") for variant in secret_variants(value))
        for value, marker in sorted(replacements, key=lambda item: len(item[0]), reverse=True):
            text = text.replace(value, marker)
        return text


def inventory_secrets(entries: list[dict], metadata: dict) -> SecretStore:
    secrets = SecretStore()
    secrets.add_url(str(metadata.get("url") or ""))
    for entry in entries:
        request = entry.get("request", {})
        response = entry.get("response", {})
        secrets.add_url(str(request.get("url") or ""))
        for side_name, part in (("REQUEST", request), ("RESPONSE", response)):
            for header in part.get("headers", []):
                name = str(header.get("name") or "")
                value = str(header.get("value") or "")
                if SENSITIVE_HEADER.fullmatch(name):
                    secrets.add_header(side_name, name, value)
            for cookie in part.get("cookies", []):
                secrets.add(safe_name(f"{side_name}_COOKIE", str(cookie.get("name") or "cookie")), cookie.get("value"))
        secrets.add_body("REQUEST", (request.get("postData") or {}).get("text"))
        content = response.get("content") or {}
        if content.get("encoding") != "base64":
            secrets.add_body("RESPONSE", content.get("text"))
    return secrets


def is_data_call(entry: dict) -> bool:
    request = entry.get("request", {})
    response = entry.get("response", {})
    url = str(request.get("url") or "")
    resource_type = str(entry.get("_resourceType") or "").lower()
    mime = str((response.get("content") or {}).get("mimeType") or "").lower()
    if not url.startswith(("http://", "https://")) or NOISE.search(url):
        return False
    if resource_type in SKIP_TYPES or SKIP_EXTENSIONS.search(urlsplit(url).path):
        return False
    return resource_type in {"xhr", "fetch"} or any(kind in mime for kind in ("json", "graphql", "event-stream"))


def make_sample(entry: dict, secrets: SecretStore) -> dict:
    request = entry["request"]
    response = entry.get("response", {})
    parsed = urlsplit(request["url"])
    headers: dict[str, str] = {}
    redacted_headers: list[str] = []
    for header in request.get("headers", []):
        name = str(header.get("name") or "")
        value = str(header.get("value") or "")
        if name.startswith(":"):
            continue
        if SENSITIVE_HEADER.fullmatch(name):
            redacted_headers.append(name.lower())
        elif KEEP_HEADER.fullmatch(name):
            headers[name.lower()] = value[:300]
    query = {
        name: (f"<REDACTED:{safe_name('QUERY', name)}>" if is_sensitive_name(name) else value[:300])
        for name, value in parse_qsl(parsed.query, keep_blank_values=True)
    }
    content = response.get("content") or {}
    response_text = "[base64 body omitted]" if content.get("encoding") == "base64" else clip(content.get("text"))
    sample = {
        "url_path": parsed.path,
        "query": query,
        "request_headers": headers,
        "redacted_headers": sorted(set(redacted_headers)),
        "request_body": clip((request.get("postData") or {}).get("text")),
        "status": response.get("status"),
        "response_type": content.get("mimeType"),
        "response_bytes": content.get("size"),
        "response_sample": response_text,
    }
    return json.loads(secrets.scrub(json.dumps(sample)))


def digest_har(
    har_path: Path,
    slug: str,
    output_dir: Path,
    vault_path: Path,
    metadata: dict | None = None,
    max_samples: int = 2,
) -> dict:
    validate_slug(slug)
    har = json.loads(har_path.read_text(encoding="utf-8"))
    entries = har.get("log", {}).get("entries", [])
    if not isinstance(entries, list):
        raise ValueError("HAR log.entries must be a list")
    metadata = metadata or {}
    secrets = inventory_secrets(entries, metadata)

    groups: OrderedDict[str, dict] = OrderedDict()
    for entry in entries:
        if not is_data_call(entry):
            continue
        request = entry["request"]
        response = entry.get("response", {})
        parsed = urlsplit(request["url"])
        endpoint = f"{request.get('method', 'GET')} {parsed.scheme}://{parsed.netloc}{path_template(parsed.path)}"
        group = groups.setdefault(endpoint, {"endpoint": endpoint, "count": 0, "statuses": set(), "samples": []})
        group["count"] += 1
        if response.get("status") is not None:
            group["statuses"].add(response["status"])
        if len(group["samples"]) < max_samples:
            group["samples"].append(make_sample(entry, secrets))

    calls = []
    for group in groups.values():
        group["statuses"] = sorted(group["statuses"])
        calls.append(group)
    calls.sort(
        key=lambda group: (
            -max((sample.get("response_bytes") or 0 for sample in group["samples"]), default=0),
            group["endpoint"],
        )
    )
    digest = {
        "slug": slug,
        "site": metadata.get("url"),
        "goal": metadata.get("goal"),
        "total_requests": len(entries),
        "data_endpoints": len(calls),
        "calls": calls,
    }
    safe_json = secrets.scrub(json.dumps(digest, indent=2))

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "api-calls-digest.json").write_text(safe_json + "\n", encoding="utf-8")
    safe_digest = json.loads(safe_json)
    lines = [
        f"# API calls digest: {slug}",
        "",
        f"- Site: {safe_digest.get('site')}",
        f"- Goal: {safe_digest.get('goal')}",
        f"- Requests recorded: {len(entries)}; data endpoints kept: {len(calls)}",
        "- Cookie, authentication, token, key, password, session, and secret values are redacted.",
        "",
    ]
    for index, group in enumerate(safe_digest["calls"], 1):
        lines.extend([f"## {index}. `{group['endpoint']}`", "", f"Seen {group['count']} times. Statuses: {group['statuses']}", ""])
        for sample in group["samples"]:
            lines.extend(["```json", json.dumps(sample, indent=2), "```", ""])
    (output_dir / "api-calls-digest.md").write_text("\n".join(lines), encoding="utf-8")

    vault_path.parent.mkdir(parents=True, exist_ok=True)
    vault_path.write_text(json.dumps(dict(sorted(secrets.values.items())), indent=2) + "\n", encoding="utf-8")
    vault_path.chmod(0o600)
    return safe_digest


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--slug", required=True)
    parser.add_argument("--har", type=Path, help="HAR path; defaults to the local capture for the slug")
    parser.add_argument("--metadata", type=Path, help="optional capture metadata JSON")
    parser.add_argument("--site", help="site URL when digesting a standalone fixture")
    parser.add_argument("--goal", help="client goal when digesting a standalone fixture")
    parser.add_argument("--output-root", type=Path, default=ARTIFACT_ROOT)
    parser.add_argument("--vault-root", type=Path, default=CAPTURE_ROOT)
    parser.add_argument("--max-samples", type=int, default=2)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        slug = validate_slug(args.slug)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    if args.max_samples < 1 or args.max_samples > 10:
        raise SystemExit("--max-samples must be between 1 and 10")
    capture_dir = CAPTURE_ROOT / slug
    har_path = args.har or capture_dir / "recording.har"
    if not har_path.is_file():
        raise SystemExit(f"HAR not found: {har_path}")
    metadata_path = args.metadata or capture_dir / "metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8")) if metadata_path.is_file() else {}
    if args.site:
        metadata["url"] = args.site
    if args.goal:
        metadata["goal"] = args.goal
    output_dir = args.output_root / slug
    vault_path = args.vault_root / slug / "captured-secrets.json"
    digest = digest_har(har_path, slug, output_dir, vault_path, metadata, args.max_samples)
    print(f"kept {digest['data_endpoints']} data endpoints from {digest['total_requests']} requests")
    print(f"digest: {output_dir / 'api-calls-digest.md'}")
    print(f"vault: {vault_path} ({len(json.loads(vault_path.read_text()))} names, values never printed)")
    return 0 if digest["data_endpoints"] else 1


if __name__ == "__main__":
    sys.exit(main())

