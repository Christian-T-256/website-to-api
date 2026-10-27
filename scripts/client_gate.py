"""Pre-save checks shared by automated and interactive model workflows."""
from __future__ import annotations

import ast
import re
from pathlib import Path

from common import CAPTURE_ROOT, CLIENT_ROOT, find_secret_names, load_vault, validate_slug


def extract_python(response: str) -> str:
    fenced = re.search(r"```(?:python)?\s*(.*?)```", response, flags=re.DOTALL | re.IGNORECASE)
    return (fenced.group(1) if fenced else response).strip() + "\n"


def validate_client(source: str, vault_path: Path) -> None:
    try:
        ast.parse(source)
    except SyntaxError as exc:
        raise ValueError(f"model output is not valid Python: {exc}") from exc
    leaked_names = find_secret_names(source, load_vault(vault_path))
    if leaked_names:
        raise ValueError("model output contains captured values for: " + ", ".join(leaked_names))


def save_client(slug: str, response: str, output_path: Path | None = None, force: bool = False) -> Path:
    validate_slug(slug)
    vault_path = CAPTURE_ROOT / slug / "captured-secrets.json"
    if not vault_path.is_file():
        raise ValueError(f"secret vault not found: {vault_path}; run the digest first")
    source = extract_python(response)
    validate_client(source, vault_path)
    output_path = output_path or CLIENT_ROOT / slug / "api_client.py"
    if output_path.exists() and not force:
        raise ValueError(f"output exists: {output_path}; pass --force to replace it")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(source, encoding="utf-8")
    return output_path

