#!/usr/bin/env python3

import os
import re
import sys
import time
import datetime
import requests
from bs4 import BeautifulSoup

USERNAME = os.environ["GH_USERNAME"]
TOKEN = os.environ.get("GITHUB_TOKEN")

ADVISORY_TYPES = ["reviewed", "unreviewed", "malware"]
MAX_PAGES = 50
README = "README.md"

web = requests.Session()
web.headers.update({"User-Agent": f"{USERNAME}-advisory-sync"})

api = requests.Session()
api.headers.update({
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": f"{USERNAME}-advisory-sync",
})
if TOKEN:
    api.headers["Authorization"] = f"Bearer {TOKEN}"


def discover_ghsa_ids():
    """Return GHSA ids credited to USERNAME across all advisory types."""
    ids = []
    for adv_type in ADVISORY_TYPES:
        for page in range(1, MAX_PAGES + 1):
            resp = web.get(
                "https://github.com/advisories",
                params={"query": f"credit:{USERNAME} type:{adv_type}", "page": page},
                timeout=(10, 30),
            )
            if resp.status_code != 200:
                raise RuntimeError(
                    f"advisories page returned HTTP {resp.status_code} "
                    f"(type={adv_type}, page={page})"
                )

            soup = BeautifulSoup(resp.text, "html.parser")
            page_ids = [
                a["href"].rstrip("/").rsplit("/", 1)[-1]
                for a in soup.select('a[href^="/advisories/GHSA-"]')
            ]
            page_ids = list(dict.fromkeys(page_ids))
            new = [g for g in page_ids if g not in ids]
            print(f"[{adv_type}] page {page}: {len(page_ids)} rows, {len(new)} new", flush=True)

            if not new:
                break
            ids.extend(new)
            time.sleep(1)
    return ids


def fetch_advisory(ghsa_id):
    resp = api.get(f"https://api.github.com/advisories/{ghsa_id}", timeout=(10, 30))
    if resp.status_code != 200:
        raise RuntimeError(f"API returned HTTP {resp.status_code} for {ghsa_id}")
    return resp.json()


def is_credited(data):
    """Confirm the credit actually stuck, rather than trusting the search index."""
    for credit in data.get("credits") or []:
        login = (credit.get("user") or {}).get("login") or ""
        if login.lower() == USERNAME.lower():
            return True
    return False


def cell(value):
    """Escape a value so it can't break out of a markdown table cell."""
    text = "" if value is None else str(value)
    text = text.replace("\\", "\\\\").replace("|", "\\|")
    return " ".join(text.split()).strip()


def build_table(advisories):
    today = datetime.date.today()
    if not advisories:
        return (
            "## Security Advisories\n\n"
            "> Auto-updated daily. No credited advisories found yet.\n\n"
            f"*Last updated: {today}*\n"
        )

    rows = []
    for a in sorted(advisories, key=lambda x: x["published"] or "", reverse=True):
        summary = cell(a["summary"])
        if len(summary) > 80:
            summary = summary[:77].rstrip() + "..."
        rows.append(
            f"| [{cell(a['ghsa_id'])}]({a['url']}) "
            f"| {cell(a['cve_id']) or '—'} "
            f"| {summary} "
            f"| {cell(a['severity'])} "
            f"| {cell(a['published']) or '—'} |"
        )

    return (
        "## Security Advisories\n\n"
        "> Auto-updated daily. Advisories from the "
        "[GitHub Advisory Database](https://github.com/advisories) where I am credited.\n\n"
        "| Advisory | CVE | Summary | Severity | Published |\n"
        "|----------|-----|---------|----------|-----------|\n"
        + "\n".join(rows)
        + f"\n\n*Last updated: {today}*\n"
    )


def write_readme(table):
    with open(README, "r", encoding="utf-8") as f:
        readme = f.read()

    updated, count = re.subn(
        r"<!-- ADVISORIES:START -->.*?<!-- ADVISORIES:END -->",
        lambda _: f"<!-- ADVISORIES:START -->\n{table}\n<!-- ADVISORIES:END -->",
        readme,
        flags=re.DOTALL,
    )
    if count == 0:
        raise RuntimeError("ADVISORIES:START / ADVISORIES:END markers not found in README.md")

    if updated == readme:
        print("README.md already up to date, no write needed.", flush=True)
        return

    with open(README, "w", encoding="utf-8") as f:
        f.write(updated)
    print("README.md updated successfully.", flush=True)


def main():
    ghsa_ids = discover_ghsa_ids()
    print(f"Discovered {len(ghsa_ids)} candidate advisories.", flush=True)

    advisories = []
    for ghsa_id in ghsa_ids:
        data = fetch_advisory(ghsa_id)
        if not is_credited(data):
            print(f"  · {ghsa_id} — credit not confirmed, skipping", flush=True)
            continue

        advisories.append({
            "ghsa_id": data["ghsa_id"],
            "cve_id": data.get("cve_id"),
            "summary": data.get("summary") or "(no summary)",
            "severity": (data.get("severity") or "unknown").title(),
            "url": data.get("html_url") or f"https://github.com/advisories/{ghsa_id}",
            "published": (data.get("published_at") or "")[:10],
            "type": data.get("type"),
        })
        print(f"  ✓ {data['ghsa_id']} — {data.get('cve_id') or 'no CVE'} "
              f"({data.get('type')})", flush=True)
        time.sleep(0.3)

    print(f"Done. {len(advisories)} confirmed advisories for {USERNAME}.", flush=True)
    write_readme(build_table(advisories))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr, flush=True)
        sys.exit(1)
