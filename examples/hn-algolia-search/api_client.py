#!/usr/bin/env python3
"""Small client for the public Hacker News Algolia search interface."""
from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path
from typing import Any

import requests

APP_ID = "UJ5WYC0L7X"
SEARCH_URL = f"https://{APP_ID.lower()}-dsn.algolia.net/1/indexes/Item_dev/query"
USER_AGENT = "website-to-api-example/1.0 (+https://github.com/Christian-T-256)"
DEFAULT_VAULT = Path(__file__).resolve().parents[2] / ".tmp" / "website-to-api" / "hn-algolia-search" / "captured-secrets.json"


def load_search_key(vault_path: Path = DEFAULT_VAULT) -> str:
    if os.environ.get("HN_ALGOLIA_API_KEY"):
        return os.environ["HN_ALGOLIA_API_KEY"]
    if vault_path.is_file():
        values = json.loads(vault_path.read_text(encoding="utf-8"))
        for name in ("QUERY_X_ALGOLIA_API_KEY", "QUERY_X_ALGOLIA_API_KEY_2"):
            if values.get(name):
                return values[name]
    raise RuntimeError("search key missing; capture hn.algolia.com or set HN_ALGOLIA_API_KEY")


class HNSearch:
    def __init__(
        self,
        api_key: str | None = None,
        session: requests.Session | None = None,
        sleep: Any = time.sleep,
    ) -> None:
        self.api_key = api_key or load_search_key()
        self.session = session or requests.Session()
        self.sleep = sleep
        self.session.headers.update({
            "User-Agent": USER_AGENT,
            "Origin": "https://hn.algolia.com",
            "Referer": "https://hn.algolia.com/",
        })

    def search_page(self, query: str, page: int = 0, per_page: int = 30, kind: str = "story") -> dict:
        if not query.strip():
            raise ValueError("query cannot be empty")
        if not 1 <= per_page <= 100:
            raise ValueError("per_page must be between 1 and 100")
        body = {
            "query": query,
            "page": page,
            "hitsPerPage": per_page,
            "tagFilters": [[kind], []],
            "advancedSyntax": True,
            "restrictSearchableAttributes": ["title", "comment_text", "url", "story_text", "author"],
        }
        response = self.session.post(
            SEARCH_URL,
            params={"x-algolia-api-key": self.api_key, "x-algolia-application-id": APP_ID},
            data=json.dumps(body),
            timeout=20,
        )
        response.raise_for_status()
        return response.json()

    def stories(self, query: str, limit: int = 30) -> list[dict]:
        if limit < 1:
            raise ValueError("limit must be positive")
        records: list[dict] = []
        page = 0
        while len(records) < limit:
            payload = self.search_page(query, page=page, per_page=min(100, limit - len(records)))
            hits = payload.get("hits", [])
            records.extend({
                "title": hit.get("title"),
                "url": hit.get("url"),
                "points": hit.get("points"),
                "comments": hit.get("num_comments"),
                "author": hit.get("author"),
                "created_at": hit.get("created_at"),
                "hn_link": f"https://news.ycombinator.com/item?id={hit.get('story_id') or hit.get('objectID')}",
            } for hit in hits)
            if not hits or page + 1 >= int(payload.get("nbPages", 1)):
                break
            page += 1
            self.sleep(1)
        return records[:limit]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("query")
    parser.add_argument("--limit", type=int, default=10)
    args = parser.parse_args()
    print(json.dumps(HNSearch().stories(args.query, args.limit), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

