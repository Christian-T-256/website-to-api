from __future__ import annotations

import json
from pathlib import Path

import pytest

import client_gate
from build_prompt import build_prompt
from client_gate import extract_python, validate_client


def test_prompt_contains_digest_but_no_private_files(tmp_path: Path) -> None:
    digest = tmp_path / "digest.md"
    digest.write_text("# Safe digest\n\n<REDACTED:QUERY_TOKEN>\n", encoding="utf-8")
    prompt = build_prompt("safe-site", digest_path=digest, output_path=tmp_path / "client.py")
    assert "# Safe digest" in prompt
    assert "Never open the raw HAR" in prompt
    assert "captured-secrets.json" in prompt


def test_model_output_is_checked_before_save(tmp_path: Path) -> None:
    vault = tmp_path / "captured-secrets.json"
    vault.write_text(json.dumps({"QUERY_TOKEN": "fictional-model-leak-123"}), encoding="utf-8")
    validate_client("print('safe')\n", vault)
    with pytest.raises(ValueError, match="QUERY_TOKEN"):
        validate_client("TOKEN = 'fictional-model-leak-123'\n", vault)
    with pytest.raises(ValueError, match="valid Python"):
        validate_client("def broken(:\n", vault)


def test_rejected_model_output_never_reaches_public_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    capture_root = tmp_path / "private"
    client_root = tmp_path / "clients"
    vault = capture_root / "safe-site" / "captured-secrets.json"
    vault.parent.mkdir(parents=True)
    vault.write_text(json.dumps({"QUERY_TOKEN": "fictional-model-leak-456"}), encoding="utf-8")
    monkeypatch.setattr(client_gate, "CAPTURE_ROOT", capture_root)
    monkeypatch.setattr(client_gate, "CLIENT_ROOT", client_root)

    with pytest.raises(ValueError, match="QUERY_TOKEN"):
        client_gate.save_client("safe-site", "TOKEN = 'fictional-model-leak-456'\n")

    assert not (client_root / "safe-site" / "api_client.py").exists()


def test_markdown_fence_is_removed() -> None:
    assert extract_python("```python\nprint('ok')\n```\n") == "print('ok')\n"
