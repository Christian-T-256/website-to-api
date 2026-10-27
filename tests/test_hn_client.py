from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLIENT_PATH = ROOT / "examples" / "hn-algolia-search" / "api_client.py"
SPEC = importlib.util.spec_from_file_location("hn_api_client", CLIENT_PATH)
assert SPEC and SPEC.loader
hn_api_client = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hn_api_client)


class FakeResponse:
    def __init__(self, payload: dict) -> None:
        self.payload = payload
        self.raised = False

    def raise_for_status(self) -> None:
        self.raised = True

    def json(self) -> dict:
        return self.payload


class FakeSession:
    def __init__(self, payloads: list[dict]) -> None:
        self.headers: dict[str, str] = {}
        self.payloads = payloads
        self.calls: list[dict] = []

    def post(self, url: str, **kwargs) -> FakeResponse:
        self.calls.append({"url": url, **kwargs})
        return FakeResponse(self.payloads[len(self.calls) - 1])


def test_hn_client_maps_records_and_paginates() -> None:
    payloads = [
        {
            "hits": [{
                "title": "Northwind publishes a Python tool",
                "url": "https://example.com/northwind-python",
                "points": 42,
                "num_comments": 7,
                "author": "jamie_rivera",
                "created_at": "2026-10-01T12:00:00Z",
                "objectID": "1001",
            }],
            "nbPages": 2,
        },
        {
            "hits": [{
                "title": "Testing API clients offline",
                "url": "https://example.com/api-tests",
                "points": 31,
                "num_comments": 4,
                "author": "casey_lee",
                "created_at": "2026-10-02T12:00:00Z",
                "objectID": "1002",
            }],
            "nbPages": 2,
        },
    ]
    session = FakeSession(payloads)
    sleeps: list[int] = []
    client = hn_api_client.HNSearch(api_key="fictional-public-search-key", session=session, sleep=sleeps.append)

    records = client.stories("python", limit=2)

    assert [record["title"] for record in records] == [
        "Northwind publishes a Python tool",
        "Testing API clients offline",
    ]
    assert records[0]["hn_link"].endswith("1001")
    assert len(session.calls) == 2
    assert sleeps == [1]
    assert session.calls[0]["timeout"] == 20
    assert session.calls[0]["params"]["x-algolia-api-key"] == "fictional-public-search-key"
    assert session.headers["Origin"] == "https://hn.algolia.com"


def test_hn_client_validates_arguments() -> None:
    session = FakeSession([])
    client = hn_api_client.HNSearch(api_key="fictional-public-search-key", session=session)
    try:
        client.stories("python", limit=0)
    except ValueError as exc:
        assert "positive" in str(exc)
    else:
        raise AssertionError("expected ValueError")

