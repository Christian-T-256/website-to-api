"""Shared paths, validation, and secret handling."""
from __future__ import annotations

import base64
import json
import re
from pathlib import Path
from urllib.parse import quote, quote_plus

REPO_ROOT = Path(__file__).resolve().parents[1]
CAPTURE_ROOT = REPO_ROOT / ".tmp" / "website-to-api"
ARTIFACT_ROOT = REPO_ROOT / "artifacts"
CLIENT_ROOT = REPO_ROOT / "clients"

SLUG_PATTERN = re.compile(r"[a-z0-9][a-z0-9-]{1,60}")
SENSITIVE_NAME = re.compile(
    r"(?:^|[-_])(auth(?:orization)?|cookie|csrf|xsrf|jwt|key|password|secret|session|sid|signature|token)(?:$|[-_])",
    re.IGNORECASE,
)
SENSITIVE_HEADER = re.compile(
    r"^(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|"
    r"x-csrf.*|x-xsrf.*|csrf.*|x-auth.*|x-access-token|x-amz-security-token|"
    r".*[-_]key|.*[-_]token|.*[-_]secret|.*[-_]session)$",
    re.IGNORECASE,
)


def validate_slug(value: str) -> str:
    if not SLUG_PATTERN.fullmatch(value):
        raise ValueError("slug must use 2 to 61 lowercase letters, numbers, or hyphens")
    return value


def safe_name(prefix: str, name: str) -> str:
    expanded = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
    clean = re.sub(r"[^A-Z0-9]+", "_", expanded.upper()).strip("_") or "VALUE"
    return f"{prefix}_{clean}"


def secret_variants(value: str) -> set[str]:
    """Forms in which a captured value commonly reappears in a HAR or client."""
    variants = {value, quote(value, safe=""), quote_plus(value), json.dumps(value)[1:-1]}
    if len(value) >= 8:
        raw = value.encode("utf-8")
        variants.add(base64.b64encode(raw).decode("ascii"))
        variants.add(base64.urlsafe_b64encode(raw).decode("ascii").rstrip("="))
    return {item for item in variants if len(item) >= 4}


def load_vault(path: Path) -> dict[str, str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in data.items()):
        raise ValueError(f"invalid secret vault: {path}")
    return data


def find_secret_names(text: str, secrets: dict[str, str]) -> list[str]:
    found: list[str] = []
    for name, value in secrets.items():
        if any(variant in text for variant in secret_variants(value)):
            found.append(name)
    return sorted(found)
