import os, re, datetime, requests
from bs4 import BeautifulSoup

USERNAME = os.environ["GH_USERNAME"]

session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0",
})

found = []
page = 1

while True:
    url = f"https://github.com/advisories?query=credit%3A{USERNAME}&page={page}"
    try:
        resp = session.get(url, timeout=30)
        print(f"Page {page} — status {resp.status_code}", flush=True)
    except requests.exceptions.Timeout:
        print(f"Page {page} — timed out!", flush=True)
        break
    except requests.exceptions.RequestException as e:
        print(f"Page {page} — error: {e}", flush=True)
        break
    print(f"Page {page} — status {resp.status_code}", flush=True)

    soup = BeautifulSoup(resp.text, "html.parser")
    advisories = soup.select("div.Box-row.Box-row--focus-gray")
    print(f"Found {len(advisories)} rows on page {page}", flush=True)

    if not advisories:
        print("No more results, stopping.", flush=True)
        break

    for adv in advisories:
        link = adv.select_one("a.Link--primary")
        if not link:
            continue

        href = link["href"]
        ghsa_id = href.split("/")[-1]
        advisory_url = f"https://github.com{href}"
        summary = link.get_text(strip=True)

        severity_el = adv.select_one("span.Label")
        severity = severity_el.get_text(strip=True) if severity_el else "Unknown"

        cve_el = adv.find(string=re.compile(r"CVE-\d{4}-\d+"))
        cve_id = cve_el.strip() if cve_el else "N/A"

        date_el = adv.select_one("relative-time")
        published = date_el["datetime"][:10] if date_el else "N/A"

        found.append({
            "ghsa_id": ghsa_id,
            "cve_id": cve_id,
            "summary": summary,
            "severity": severity,
            "url": advisory_url,
            "published": published,
        })
        print(f"  ✓ {ghsa_id} — {cve_id}", flush=True)

    page += 1

print(f"Done. Found {len(found)} advisories for {USERNAME}.", flush=True)

# --- Build markdown table ---
if found:
    rows = "\n".join(
        f"| [{a['ghsa_id']}]({a['url']}) | {a['cve_id']} | {a['summary'][:60]} | {a['severity']} | {a['published']} |"
        for a in sorted(found, key=lambda x: x["published"], reverse=True)
    )
    table = f"""## Security Advisories

> Auto-updated daily. Advisories from the [GitHub Advisory Database](https://github.com/advisories) where I am credited.

| Advisory | CVE | Summary | Severity | Published |
|----------|-----|---------|----------|-----------|
{rows}

*Last updated: {datetime.date.today()}*
"""
else:
    table = f"""## Security Advisories

> Auto-updated daily. No credited advisories found yet.

*Last updated: {datetime.date.today()}*
"""

# --- Update README between markers ---
with open("README.md", "r") as f:
    readme = f.read()

updated = re.sub(
    r"<!-- ADVISORIES:START -->.*<!-- ADVISORIES:END -->",
    f"<!-- ADVISORIES:START -->\n{table}\n<!-- ADVISORIES:END -->",
    readme,
    flags=re.DOTALL
)

with open("README.md", "w") as f:
    f.write(updated)

print("README.md updated successfully.", flush=True)
