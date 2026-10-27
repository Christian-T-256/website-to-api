# Hacker News Algolia example

This client came from a redacted digest of the public network request made by
the Hacker News Algolia search page. It keeps the public application ID in
source and loads the current public search key at runtime from a local capture
or `HN_ALGOLIA_API_KEY`.

```bash
python scripts/capture.py \
  --url "https://hn.algolia.com/?q=python" \
  --goal "search Hacker News stories by keyword" \
  --slug hn-algolia-search \
  --mode auto
python scripts/digest.py --slug hn-algolia-search
python examples/hn-algolia-search/api_client.py "python" --limit 5
```

The tests use fictional HTTP responses and do not call the live service.

