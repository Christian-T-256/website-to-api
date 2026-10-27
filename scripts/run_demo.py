#!/usr/bin/env python3
"""Run the offline digest and leak check against a fictional HAR."""
from __future__ import annotations

import json
import sys

from common import CAPTURE_ROOT, REPO_ROOT
from digest import digest_har
from verify_no_secret_leak import verify

SLUG = "northwind-catalog"


def main() -> int:
    har_path = REPO_ROOT / "tests" / "fixtures" / "fictional.har"
    output_dir = REPO_ROOT / ".demo-output" / SLUG
    vault_path = CAPTURE_ROOT / SLUG / "captured-secrets.json"
    metadata = {
        "url": "https://northwind-dental.example/plans",
        "goal": "list fictional dental plans",
    }
    digest = digest_har(har_path, SLUG, output_dir, vault_path, metadata)
    names_count, files_count, leaks = verify(vault_path, [output_dir])
    if leaks:
        for path, names in leaks:
            print(f"LEAK {path}: {', '.join(names)}")
        return 1
    sample = digest["calls"][0]["samples"][0]
    print(f"kept {digest['data_endpoints']} data endpoint from {digest['total_requests']} requests")
    print(json.dumps({
        "endpoint": digest["calls"][0]["endpoint"],
        "redacted_headers": sample["redacted_headers"],
        "query": sample["query"],
    }, indent=2))
    print(f"CLEAN {names_count} secret names checked across {files_count} files")
    return 0


if __name__ == "__main__":
    sys.exit(main())

