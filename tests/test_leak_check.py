from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import quote

from verify_no_secret_leak import verify


def test_leak_check_detects_encoded_value_without_printing_it(tmp_path: Path) -> None:
    secret = "fictional value with spaces 123"
    vault = tmp_path / "captured-secrets.json"
    vault.write_text(json.dumps({"QUERY_TOKEN": secret}), encoding="utf-8")
    target = tmp_path / "publish"
    target.mkdir()
    (target / "client.py").write_text(f'VALUE = "{quote(secret, safe="")}"\n', encoding="utf-8")

    names_count, files_count, leaks = verify(vault, [target])

    assert names_count == 1
    assert files_count == 1
    assert leaks == [(target / "client.py", ["QUERY_TOKEN"])]


def test_leak_check_passes_redacted_output(tmp_path: Path) -> None:
    vault = tmp_path / "captured-secrets.json"
    vault.write_text(json.dumps({"HEADER_AUTHORIZATION": "Bearer fictional-credential-123"}), encoding="utf-8")
    target = tmp_path / "digest.md"
    target.write_text("authorization: <REDACTED:HEADER_AUTHORIZATION>\n", encoding="utf-8")
    assert verify(vault, [target]) == (1, 1, [])

