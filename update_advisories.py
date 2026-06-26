import os, re, datetime, requests
from bs4 import BeautifulSoup

USERNAME = os.environ["GH_USERNAME"]

session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0",
    "Accept": "text/html",
    "X-Requested-With": "XMLHttpRequest",
})

found = []
page = 1
MAX_PAGES = 20  # hard cap — safety net

while page <= MAX_PAGES:
    url = f"https://github.com/advisories?query=credit%3A{USERNAME}&page={page}"
    resp = session.get(url)
    print(f"Page {page} — status {resp.status_code}")

    soup = BeautifulSoup(resp.text, "html.parser")

    # Check total count from heading e.g. "2 advisories"
    heading = soup.find(string=re.compile(r"\d+ advisor"))
    if heading:
        print(f"Total: {heading.strip()}")

    advisories = soup.select("div.Box-row")
    print(f"Found {len(advisories)} rows on this page")

    if not advisories or "No results matched your search" in resp.text:
        print("No more results.")
        break

    for adv in advisories:
        link = adv.select_one("a[href*='/advisories/GHSA']")
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

    page += 1

print(f"Found {len(found)} advisories for {USERNAME}.")

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

print("README.md updated successfully.")
