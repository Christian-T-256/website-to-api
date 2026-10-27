You are writing a small Python API client from a redacted digest of browser network calls.

Inputs:

- Digest: `{{DIGEST_PATH}}`
- Output: `{{OUTPUT_PATH}}`
- Secret names appear as `<REDACTED:NAME>`.
- At runtime, captured values are available in `.tmp/website-to-api/{{SLUG}}/captured-secrets.json`.

Rules:

1. Read only the digest. Never open the raw HAR, metadata, browser profile, environment files, or secret vault.
2. Use only endpoints needed for the goal. Ignore tracking, configuration, and health calls.
3. Write one class with low-level endpoint methods and one high-level method returning useful records as dictionaries.
4. Load required secret values at runtime by their redacted names. Never put a captured value in source code, comments, fixtures, or output.
5. Use `requests.Session`, a clear User-Agent, a 20 second timeout, and `raise_for_status()`.
6. Preserve required Origin, Referer, content type, and application identifiers shown in the digest.
7. Paginate when the digest supports it. Sleep at least one second between page requests.
8. Validate arguments and return helpful errors. Do not silently return an empty list after an HTTP failure.
9. Add an argparse entry point that prints JSON.
10. Return only complete Python source on stdout. Do not use Markdown fences.

The caller will syntax-check and secret-check your response before saving it.

