from __future__ import annotations

import json
from pathlib import Path

from digest import digest_har

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "fictional.har"


def test_digest_filters_noise_and_redacts_all_secret_locations(tmp_path: Path) -> None:
    output_dir = tmp_path / "output"
    vault_path = tmp_path / "private" / "captured-secrets.json"
    digest = digest_har(
        FIXTURE,
        "northwind-catalog",
        output_dir,
        vault_path,
        {"url": "https://northwind-dental.example/plans", "goal": "list fictional dental plans"},
    )

    assert digest["total_requests"] == 3
    assert digest["data_endpoints"] == 1
    call = digest["calls"][0]
    assert call["endpoint"] == "POST https://api.northwind-dental.example/v1/clinics/{id}/plans"
    sample = call["samples"][0]
    assert sample["query"]["api_key"].startswith("<REDACTED:")
    assert sample["redacted_headers"] == ["authorization", "cookie", "x-api-key"]

    vault = json.loads(vault_path.read_text(encoding="utf-8"))
    assert "REQUEST_HEADER_AUTHORIZATION" in vault
    assert "REQUEST_HEADER_AUTHORIZATION_CREDENTIAL" in vault
    assert "REQUEST_COOKIE_SESSION_ID" in vault
    assert "RESPONSE_COOKIE_SESSION_ID" in vault
    assert "REQUEST_BODY_REFRESH_TOKEN" in vault
    assert "RESPONSE_BODY_ACCESS_TOKEN" in vault

    published = "\n".join(path.read_text(encoding="utf-8") for path in output_dir.iterdir())
    for value in vault.values():
        assert value not in published
    assert "<REDACTED:" in published
    assert "analytics.example" not in published


def test_vault_permissions_are_owner_only(tmp_path: Path) -> None:
    vault_path = tmp_path / "private" / "captured-secrets.json"
    digest_har(FIXTURE, "fixture-test", tmp_path / "output", vault_path, {})
    assert vault_path.stat().st_mode & 0o777 == 0o600

