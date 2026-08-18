#!/usr/bin/env python3

import os
import re
import sys
import time
import datetime
import requests
from bs4 import BeautifulSoup

USERNAME = os.environ["GH_USERNAME"]
TOKEN = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
REPOS = [r.strip() for r in os.environ.get("GH_REPOS", "").split(",") if r.strip()]

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


def api_get(url, **kwargs):
    resp = api.get(url, timeout=(10, 30), **kwargs)
    if resp.status_code != 200:
        raise RuntimeError(f"API {resp.status_code} for {url}")
    return resp


def credited(data):
    target = USERNAME.lower()

    for credit in data.get("credits") or []:
        login = credit.get("login") or (credit.get("user") or {}).get("login") or ""
        if login.lower() == target:
            return True

    for credit in data.get("credits_detailed") or []:
        login = (credit.get("user") or {}).get("login") or credit.get("login") or ""
        if login.lower() == target and credit.get("state", "accepted") == "accepted":
            return True

    return False


def normalize(data, source):
    return {
        "ghsa_id": data["ghsa_id"],
        "cve_id": data.get("cve_id"),
        "summary": data.get("summary") or "(no summary)",
        "severity": (data.get("severity") or "unknown").title(),
        "url": data.get("html_url") or f"https://github.com/advisories/{data['ghsa_id']}",
        "published": (data.get("published_at") or "")[:10],
        "source": source,
    }


def global_advisories():
    ghsa_ids = []
    for adv_type in ADVISORY_TYPES:
        for page in range(1, MAX_PAGES + 1):
            resp = web.get(
                "https://github.com/advisories",
                params={"query": f"credit:{USERNAME} type:{adv_type}", "page": page},
                timeout=(10, 30),
            )
            if resp.status_code != 200:
                raise RuntimeError(
                    f"advisories page HTTP {resp.status_code} (type={adv_type}, page={page})"
                )
            soup = BeautifulSoup(resp.text, "html.parser")
            page_ids = list(dict.fromkeys(
                a["href"].rstrip("/").rsplit("/", 1)[-1]
                for a in soup.select('a[href^="/advisories/GHSA-"]')
            ))
            new = [g for g in page_ids if g not in ghsa_ids]
            print(f"[global/{adv_type}] page {page}: {len(page_ids)} rows, {len(new)} new", flush=True)
            if not new:
                break
            ghsa_ids.extend(new)
            time.sleep(1)

    out = []
    for ghsa_id in ghsa_ids:
        data = api_get(f"https://api.github.com/advisories/{ghsa_id}").json()
        if credited(data):
            out.append(normalize(data, "global"))
            print(f"  ✓ {ghsa_id} — {data.get('cve_id') or 'no CVE'}", flush=True)
        time.sleep(0.3)
    return out


def repo_advisories(repo):
    out = []
    page = 1
    while page <= MAX_PAGES:
        resp = api_get(
            f"https://api.github.com/repos/{repo}/security-advisories",
            params={"state": "published", "per_page": 100, "page": page},
        )
        batch = resp.json()
        if not batch:
            break
        for data in batch:
            if credited(data):
                item = normalize(data, repo)
                if not data.get("html_url"):
                    item["url"] = f"https://github.com/{repo}/security/advisories/{data['ghsa_id']}"
                out.append(item)
                print(f"  ✓ {data['ghsa_id']} — {data.get('cve_id') or 'no CVE'} ({repo})", flush=True)
        page += 1
        time.sleep(0.5)
    return out


def cell(value):
    text = "" if value is None else str(value)
    text = text.replace("\\", "\\\\").replace("|", "\\|")
    return " ".join(text.split()).strip()


def build_table(advisories):
    today = datetime.date.today()
    if not advisories:
        return ("## Security Advisories\n\n"
                "> Auto-updated daily. No credited advisories found yet.\n\n"
                f"*Last updated: {today}*\n")

    rows = []
    for a in sorted(advisories, key=lambda x: x["published"] or "", reverse=True):
        summary = cell(a["summary"])
        if len(summary) > 80:
            summary = summary[:77].rstrip() + "..."
        rows.append(
            f"| [{cell(a['ghsa_id'])}]({a['url']}) | {cell(a['cve_id']) or '—'} "
            f"| {summary} | {cell(a['severity'])} | {cell(a['published']) or '—'} |"
        )

    return ("## Security Advisories\n\n"
            "> Auto-updated daily. Advisories where I am credited, from the "
            "[GitHub Advisory Database](https://github.com/advisories) and from "
            "repository advisories.\n\n"
            "| Advisory | CVE | Summary | Severity | Published |\n"
            "|----------|-----|---------|----------|-----------|\n"
            + "\n".join(rows)
            + f"\n\n*Last updated: {today}*\n")


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
        print("README.md already up to date.", flush=True)
        return
    with open(README, "w", encoding="utf-8") as f:
        f.write(updated)
    print("README.md updated successfully.", flush=True)


def main():
    print(f"config: user={USERNAME} token={'yes' if TOKEN else 'no'} "
          f"repos={REPOS or '(none — repo-only advisories will be skipped)'}", flush=True)

    by_id = {}
    for item in global_advisories():
        by_id[item["ghsa_id"]] = item

    for repo in REPOS:
        print(f"[repo] {repo}", flush=True)
        for item in repo_advisories(repo):
            by_id.setdefault(item["ghsa_id"], item)

    advisories = list(by_id.values())
    print(f"Done. {len(advisories)} confirmed advisories for {USERNAME}.", flush=True)
    write_readme(build_table(advisories))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr, flush=True)
        sys.exit(1)
